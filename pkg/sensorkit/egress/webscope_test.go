package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// webSite records every raw path it is asked for; /go redirects to a
// denied path, /hop to an allowed one.
type webSite struct {
	mu   sync.Mutex
	hits []string
}

func (s *webSite) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, r.Method+" "+r.URL.EscapedPath())
		s.mu.Unlock()
		switch r.URL.Path {
		case "/go":
			http.Redirect(w, r, "/admin/redirected", http.StatusFound)
		case "/hop":
			http.Redirect(w, r, "/public/landed", http.StatusFound)
		default:
			fmt.Fprint(w, "page "+r.URL.Path)
		}
	})
}

func (s *webSite) served() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

// assertNoDenied fails when the server saw a path the scope denies.
func (s *webSite) assertNoDenied(t *testing.T) {
	t.Helper()
	for _, h := range s.served() {
		_, p, _ := strings.Cut(h, " ")
		if l := strings.ToLower(p); strings.HasPrefix(l, "/admin") || strings.HasPrefix(l, "/logout") || strings.Contains(l, "%") || strings.Contains(l, "..") {
			t.Errorf("the server saw %q", h)
		}
	}
}

var testWebScope = &webscope.Scope{DenyPaths: []string{"/admin", "/logout"}}

// webForwarder admits app.test and other.test (both pinned to 127.0.0.1)
// with the web scope; the job's target is app.test.
func webForwarder(t *testing.T, ws *webscope.Scope, limits ...scopelimit.Limit) (*Forwarder, string) {
	t.Helper()
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}, "other.test": {addr("127.0.0.1")}},
		Limits: limits, Web: ws, WebTargets: []string{"app.test", "other.test"}}, Limits{})
	return f, serve(t, f)
}

// deniedForms are requests for a denied path in the forms a server reads
// as that path: case, percent-encoding, dot segments, backslashes, an
// encoded separator.
var deniedForms = []string{
	"/admin", "/admin/x", "/ADMIN/x", "/Admin", "/%61dmin/x", "/%41DMIN", "/public/../admin/x",
	"/public/%2e%2e/admin", "/./admin", "/public/..%2fadmin", "/public\\..\\admin", "/logout", "/LOGOUT?x=1",
	"/public/..;/admin", "/;/admin", "/admin;jsessionid=1",
}

// SECURITY: plain HTTP through the forwarder (absolute form): a denied
// path in any form is refused, an allowed path is served, a method the
// scope does not allow is refused, and a redirect to a denied path is
// refused when the client follows it.
func TestWebScopeAbsoluteForm(t *testing.T) {
	s := &webSite{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	f, pa := webForwarder(t, testWebScope)
	c := proxiedClient(t, pa, nil)
	base := "http://app.test:" + strconv.Itoa(portOf(t, srv.URL))
	if got, body := get(t, c, base+"/public/a"); got != 200 || body != "page /public/a" {
		t.Fatalf("allowed path: %d %q", got, body)
	}
	for _, p := range deniedForms {
		if got, body := get(t, c, base+p); got != 403 {
			t.Errorf("%s: %d (%s), want 403", p, got, body)
		}
	}
	// A redirect to a denied path: the follow-up request is refused.
	if got, _ := get(t, c, base+"/go"); got != 403 {
		t.Errorf("redirect to a denied path: %d, want 403", got)
	}
	// A redirect to an allowed path still works.
	if got, body := get(t, c, base+"/hop"); got != 200 || body != "page /public/landed" {
		t.Errorf("redirect to an allowed path: %d %q", got, body)
	}
	// POST is outside a scope that names no methods.
	resp, err := c.Post(base+"/public/form", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("POST: %d, want 403", resp.StatusCode)
	}
	s.assertNoDenied(t)
	for _, h := range s.served() {
		if strings.HasPrefix(h, "POST") {
			t.Errorf("the server saw %q", h)
		}
	}
	if len(f.Refusals()) == 0 {
		t.Error("no refusal recorded")
	}
}

// SECURITY: HTTPS through a CONNECT tunnel: TLS is terminated with the
// forwarder's authority, every request on the kept-alive connection is
// checked, and a redirect to a denied path is refused.
func TestWebScopeHTTPS(t *testing.T) {
	s := &webSite{}
	srv := httptest.NewTLSServer(s.handler())
	defer srv.Close()
	f, pa := webForwarder(t, testWebScope)
	if err := f.CreateAuthority(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.AuthorityPEM())
	c := proxiedClient(t, pa, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	base := "https://app.test:" + strconv.Itoa(portOf(t, srv.URL))
	for i := 0; i < 2; i++ { // the second on the kept-alive connection
		if got, body := get(t, c, base+"/public/a"); got != 200 {
			t.Fatalf("allowed path: %d %q", got, body)
		}
	}
	for _, p := range deniedForms {
		if got, body := get(t, c, base+p); got != 403 {
			t.Errorf("%s: %d (%s), want 403", p, got, body)
		}
	}
	if got, _ := get(t, c, base+"/go"); got != 403 {
		t.Errorf("redirect to a denied path: %d, want 403", got)
	}
	if got, _ := get(t, c, base+"/hop"); got != 200 {
		t.Errorf("redirect to an allowed path: %d", got)
	}
	s.assertNoDenied(t)
	// A tool that does not verify certificates (nuclei does not by
	// default) works the same way.
	c2 := proxiedClient(t, pa, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test: a scanner's client
	if got, _ := get(t, c2, base+"/public/b"); got != 200 {
		t.Errorf("unverified client, allowed path: %d", got)
	}
	if got, _ := get(t, c2, base+"/admin"); got != 403 {
		t.Errorf("unverified client, denied path: %d", got)
	}
	s.assertNoDenied(t)
}

// SECURITY: raw requests in a tunnel (what a template with a raw request
// sends): a denied path is refused with a complete 403 and the connection
// stays open, so the allowed request pipelined behind it is served (a tool
// must not read a refusal as a broken host); a request that is not
// HTTP/1.x, a protocol upgrade, a Host for another name and HTTP/2 are
// refused.
func TestWebScopeTunnel(t *testing.T) {
	s := &webSite{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	_, pa := webForwarder(t, testWebScope)
	tunnel := func(t *testing.T, host, requests string) []string {
		t.Helper()
		c, err := net.Dial("tcp", pa)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n%s", host, port, host, requests)
		br := bufio.NewReader(c)
		if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
			t.Fatalf("CONNECT %s: %v", host, err)
		}
		var status []string
		for {
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
			if err != nil {
				return status
			}
			_ = resp.Body.Close()
			status = append(status, strconv.Itoa(resp.StatusCode))
			_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}
	}
	h := "app.test:" + strconv.Itoa(port)
	got := tunnel(t, "app.test", "GET /public/a HTTP/1.1\r\nHost: "+h+"\r\n\r\nGET /Admin HTTP/1.1\r\nHost: "+h+"\r\n\r\nGET /public/b HTTP/1.1\r\nHost: "+h+"\r\n\r\n")
	if strings.Join(got, ",") != "200,403,200" {
		t.Errorf("keep-alive tunnel: %v", got)
	}
	for name, req := range map[string]string{
		"not http":   "SSH-2.0-OpenSSH_9.6\r\n",
		"raw bytes":  "\x00\x01\x02\x03",
		"upgrade":    "GET /public/a HTTP/1.1\r\nHost: " + h + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		"h2 preface": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
		"other host": "GET /public/a HTTP/1.1\r\nHost: evil.test:" + strconv.Itoa(port) + "\r\n\r\n",
		"absolute":   "GET http://app.test/admin HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"delete":     "DELETE /public/a HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
	} {
		if got := tunnel(t, "app.test", req); len(got) > 0 && got[0] != "403" {
			t.Errorf("%s: %v", name, got)
		}
	}
	s.assertNoDenied(t)
	for _, hit := range s.served() {
		if !strings.HasPrefix(hit, "GET ") {
			t.Errorf("the server saw %q", hit)
		}
	}
}

// SOCKS5 is guarded the same way.
func TestWebScopeSOCKS5(t *testing.T) {
	s := &webSite{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	_, pa := webForwarder(t, testWebScope)
	d, err := proxy.SOCKS5("tcp", pa, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		return d.(proxy.ContextDialer).DialContext(ctx, n, a)
	}}}
	t.Cleanup(c.CloseIdleConnections)
	base := "http://app.test:" + strconv.Itoa(portOf(t, srv.URL))
	if got, _ := get(t, c, base+"/public/a"); got != 200 {
		t.Errorf("/public/a: %d", got)
	}
	for _, p := range []string{"/admin", "/ADMIN/x", "/%61dmin", "/public/../admin"} {
		if got, _ := get(t, c, base+p); got != 403 {
			t.Errorf("%s: %d", p, got)
		}
	}
	s.assertNoDenied(t)
}

// The scope's hosts and path prefixes apply too, and a path limit and a
// web scope on one task both hold.
func TestWebScopeHostsPrefixesAndLimits(t *testing.T) {
	s := &webSite{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	ws := &webscope.Scope{Hosts: []string{"app.test"}, PathPrefixes: []string{"/public"}, DenyPaths: []string{"/public/private"}}
	_, pa := webForwarder(t, ws, scopelimit.Limit{Host: "app.test", Ports: strconv.Itoa(port), PathPrefix: "/public/a"})
	c := proxiedClient(t, pa, nil)
	p := strconv.Itoa(port)
	for u, want := range map[string]int{
		"http://app.test:" + p + "/public/a":         200,
		"http://app.test:" + p + "/public/b":         403, // the path limit
		"http://app.test:" + p + "/other":            403, // the prefix
		"http://app.test:" + p + "/public/a/../../x": 403,
		"http://other.test:" + p + "/public/a":       403, // the scope's hosts
	} {
		if got, body := get(t, c, u); got != want {
			t.Errorf("%s: %d (%s), want %d", u, got, body, want)
		}
	}
}

// Without a web scope (and without path limits) nothing is read: the
// tunnel carries any protocol, as before.
func TestNoWebScopeTunnelIsRaw(t *testing.T) {
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}}}, Limits{})
	if f.guardFor("app.test", 22) != nil {
		t.Fatal("a guard without a web scope or a path limit")
	}
	f2 := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}}, Web: testWebScope}, Limits{})
	if f2.guardFor("app.test", 22) == nil {
		t.Fatal("no guard with a web scope")
	}
}
