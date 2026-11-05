package egress

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/webscope"
)

// oobSite is a stand-in interaction server: it records what reached it.
type oobSite struct {
	mu   sync.Mutex
	hits []string
	auth []string
	host []string
}

func (s *oobSite) start(t *testing.T) (*httptest.Server, int, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		s.mu.Lock()
		s.hits = append(s.hits, r.Method+" "+r.URL.RequestURI())
		s.auth = append(s.auth, r.Header.Get("Authorization")+"|"+r.Header.Get("Cookie"))
		s.host = append(s.host, r.Host)
		s.mu.Unlock()
		_, _ = io.WriteString(w, `{"message":"ok"}`)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, port, pool
}

func (s *oobSite) seen() (hits, auth, host []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...), append([]string(nil), s.auth...), append([]string(nil), s.host...)
}

// oobForwarder is a forwarder whose interaction server is the test site
// under the name example.com (httptest's certificate names it); the name
// resolves to loopback, which only PrivateOK admits.
func oobForwarder(t *testing.T, scope Scope, port int, pool *x509.CertPool, privateOK bool) *Forwarder {
	t.Helper()
	scope.OOB = &OOBServer{Host: "example.com", Port: port, Authorization: "grant-token", PrivateOK: privateOK, RootCAs: pool}
	f := New(scope, Limits{})
	f.LookupVendor = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return f
}

// viaProxy sends one absolute-form request through the forwarder at proxyAddr.
func viaProxy(t *testing.T, proxyAddr, method, rawURL, body string, hdr http.Header) (int, string) {
	t.Helper()
	pu, _ := url.Parse("http://" + proxyAddr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		// The forwarder closed the connection before the whole request was
		// written (an oversized body is refused from its length).
		return -1, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestOOBInteractionAPI(t *testing.T) {
	site := &oobSite{}
	_, port, pool := site.start(t)
	// A web-scoped task with no target: the interaction server still
	// answers, nothing else does.
	f := oobForwarder(t, Scope{Web: &webscope.Scope{DenyPaths: []string{"/admin"}}, WebTargets: []string{"app.test"}}, port, pool, true)
	p := serve(t, f)

	hdr := http.Header{"Authorization": {"tool-supplied"}, "Cookie": {"c=1"}, "Content-Type": {"application/json"}}
	for _, rq := range []struct{ method, path, body string }{
		{http.MethodPost, "/register", `{"public-key":"k"}`},
		{http.MethodGet, "/poll?id=abc&secret=s", ""},
		{http.MethodPost, "/deregister", `{}`},
	} {
		if code, body := viaProxy(t, p, rq.method, "http://example.com"+rq.path, rq.body, hdr); code != http.StatusOK || !strings.Contains(body, "ok") {
			t.Fatalf("%s %s: %d %q", rq.method, rq.path, code, body)
		}
	}
	hits, auth, host := site.seen()
	if strings.Join(hits, ",") != "POST /register,GET /poll?id=abc&secret=s,POST /deregister" {
		t.Fatalf("server saw %v", hits)
	}
	for i, a := range auth {
		// The forwarder's token replaces the tool's; no cookie is passed on.
		if a != "grant-token|" {
			t.Errorf("request %d carried %q", i, a)
		}
		if host[i] != "example.com" {
			t.Errorf("request %d Host %q", i, host[i])
		}
	}
	recs := waitRecords(t, f, 3)
	for _, r := range recs {
		if r.Protocol != ProtocolOOB || r.Verdict != Allowed || strings.Contains(r.Reason, "secret") {
			t.Errorf("record %+v", r)
		}
	}
	// Interaction requests are not target connections.
	if tl := f.Tally(); tl.Allowed != 0 || tl.Refused != 0 {
		t.Errorf("tally %+v", tl)
	}
}

func TestOOBRefusals(t *testing.T) {
	site := &oobSite{}
	_, port, pool := site.start(t)
	f := oobForwarder(t, Scope{}, port, pool, true)
	p := serve(t, f)

	cases := []struct{ name, method, url, body string }{
		{"other path", http.MethodGet, "http://example.com/anything", ""},
		{"wrong method", http.MethodGet, "http://example.com/register", ""},
		{"query on a post", http.MethodPost, "http://example.com/register?x=1", "{}"},
		{"oversized body", http.MethodPost, "http://example.com/register", strings.Repeat("a", MaxOOBBody+1)},
		{"a subdomain is a payload host, not the API", http.MethodPost, "http://abc.example.com/register", "{}"},
		{"another port", http.MethodPost, "http://example.com:8080/register", "{}"},
		{"a public interaction server that is not configured", http.MethodPost, "http://oast.pro/register", "{}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := viaProxy(t, p, tc.method, tc.url, tc.body, nil)
			if code != http.StatusForbidden && (code != -1 || len(tc.body) <= MaxOOBBody) {
				t.Fatalf("status %d (%s), want 403", code, body)
			}
		})
	}
	if hits, _, _ := site.seen(); len(hits) != 0 {
		t.Fatalf("the server saw %v", hits)
	}
	// CONNECT to the interaction host is an ordinary destination: refused.
	if got := connect(t, p, net.JoinHostPort("example.com", "443")); !strings.Contains(got, "403") {
		t.Fatalf("CONNECT: %q", got)
	}
}

// A server that resolves to a private address is refused unless the
// operator allowed it; the certificate is always verified.
func TestOOBUpstreamChecks(t *testing.T) {
	site := &oobSite{}
	_, port, pool := site.start(t)

	p := serve(t, oobForwarder(t, Scope{}, port, pool, false))
	if code, body := viaProxy(t, p, http.MethodPost, "http://example.com/register", "{}", nil); code != http.StatusForbidden || !strings.Contains(body, "no address") {
		t.Fatalf("private address without PrivateOK: %d %q", code, body)
	}

	p = serve(t, oobForwarder(t, Scope{}, port, nil, true))
	if code, body := viaProxy(t, p, http.MethodPost, "http://example.com/register", "{}", nil); code != http.StatusBadGateway || !strings.Contains(body, "certificate") {
		t.Fatalf("untrusted certificate: %d %q", code, body)
	}

	f := oobForwarder(t, Scope{}, port, pool, true)
	f.LookupVendor = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	p = serve(t, f)
	if code, _ := viaProxy(t, p, http.MethodPost, "http://example.com/register", "{}", nil); code != http.StatusForbidden {
		t.Fatalf("metadata address: %d", code)
	}
	if hits, _, _ := site.seen(); len(hits) != 0 {
		t.Fatalf("the server saw %v", hits)
	}
}

// Without an interaction server, an interaction API request is an ordinary
// destination: refused.
func TestOOBNotConfigured(t *testing.T) {
	p := serve(t, New(Scope{}, Limits{}))
	if code, _ := viaProxy(t, p, http.MethodPost, "http://oast.fun/register", "{}", nil); code != http.StatusForbidden {
		t.Fatalf("status %d", code)
	}
}
