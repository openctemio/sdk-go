package httpsec

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseProxySetting(t *testing.T) {
	cases := []struct {
		in      string
		mode    ProxyMode
		str     string
		wantErr string
	}{
		{in: "", mode: ProxyEnvironment, str: "environment"},
		{in: "direct", mode: ProxyDirect, str: "direct"},
		{in: " NONE ", mode: ProxyDirect, str: "direct"},
		{in: "proxy.corp:3128", mode: ProxyURL, str: "http://proxy.corp:3128"},
		{in: "http://u:secret@proxy.corp:3128", mode: ProxyURL, str: "http://u:xxxxx@proxy.corp:3128"},
		{in: "https://proxy.corp", mode: ProxyURL, str: "https://proxy.corp"},
		{in: "socks5h://10.40.0.5:1080", mode: ProxyURL, str: "socks5h://10.40.0.5:1080"},
		{in: "socks5://10.40.0.5:1080/", mode: ProxyURL, str: "socks5://10.40.0.5:1080"},
		{in: "ftp://proxy.corp:21", wantErr: "scheme must be"},
		{in: "http://proxy.corp:3128/path", wantErr: "no path"},
		{in: "http://169.254.169.254:80", wantErr: "cannot be a proxy"},
		{in: "http://224.0.0.1:80", wantErr: "cannot be a proxy"},
		{in: "http://", wantErr: "missing host"},
	}
	for _, c := range cases {
		s, err := ParseProxySetting(c.in, "")
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%q: err = %v, want %q", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if s.Mode != c.mode || s.String() != c.str {
			t.Errorf("%q: got mode %d %q, want %d %q", c.in, s.Mode, s.String(), c.mode, c.str)
		}
	}
}

func TestParseProxySetting_ErrorHidesPassword(t *testing.T) {
	_, err := ParseProxySetting("ftp://u:secret@proxy.corp:21", "")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error must not carry the password: %v", err)
	}
}

func TestProxySetting_NoProxyAndDirect(t *testing.T) {
	s, err := ParseProxySetting("http://proxy.corp:3128", "10.0.0.0/8,.corp.example")
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"http://203.0.113.7/x":       "http://proxy.corp:3128",
		"https://db.corp.example/x":  "",
		"https://10.1.2.3/x":         "",
		"http://127.0.0.1:8080/x":    "", // loopback is never proxied
		"https://api.github.com/foo": "http://proxy.corp:3128",
	} {
		u, _ := url.Parse(target)
		got, err := s.URLFor(u)
		if err != nil {
			t.Fatal(err)
		}
		gs := ""
		if got != nil {
			gs = got.String()
		}
		if gs != want {
			t.Errorf("%s: proxy %q, want %q", target, gs, want)
		}
	}
	direct, _ := ParseProxySetting("direct", "")
	u, _ := url.Parse("https://api.github.com/")
	if got, _ := direct.URLFor(u); got != nil {
		t.Errorf("direct returned proxy %v", got)
	}
}

// fakeProxy is an HTTP forward proxy that answers every request itself and
// records the absolute-form URLs it was asked for.
type fakeProxy struct {
	mu   sync.Mutex
	seen []string
	srv  *httptest.Server
	// redirect, when set, is the Location of a 302 answer to the first
	// request.
	redirect string
}

func newFakeProxy(t *testing.T) *fakeProxy {
	t.Helper()
	p := &fakeProxy{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.URL.String())
		first := len(p.seen) == 1
		p.mu.Unlock()
		if first && p.redirect != "" {
			http.Redirect(w, r, p.redirect, http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "via-proxy")
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func useContentProxy(t *testing.T, raw string) {
	t.Helper()
	s, err := ParseProxySetting(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	SetContentProxy(s)
	t.Cleanup(func() { SetContentProxy(ProxySetting{}) })
}

// The proxy listens on loopback, which SafeHTTPClient refuses as a target:
// reaching it proves the proxy is dialed with the operator (API) policy.
func TestSafeHTTPClient_PublicTargetGoesThroughProxy(t *testing.T) {
	p := newFakeProxy(t)
	useContentProxy(t, p.srv.URL)

	resp, err := SafeHTTPClient(5 * time.Second).Get("http://203.0.113.7/feed.json")
	if err != nil {
		t.Fatalf("request through the proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "via-proxy" {
		t.Fatalf("body %q: the request did not go through the proxy", body)
	}
	if got := p.requests(); len(got) != 1 || got[0] != "http://203.0.113.7/feed.json" {
		t.Fatalf("proxy saw %v", got)
	}
}

func TestSafeHTTPClient_ProxyDoesNotOpenBlockedTargets(t *testing.T) {
	p := newFakeProxy(t)
	useContentProxy(t, p.srv.URL)
	c := SafeHTTPClient(5 * time.Second)

	for _, target := range []string{
		"http://10.0.0.5/admin",                   // RFC 1918
		"http://192.168.1.1/",                     // RFC 1918
		"http://169.254.169.254/latest/meta-data", // IMDS
		"http://127.0.0.1:9999/",                  // loopback
		"http://[::1]:9999/",                      // loopback v6
		"http://localhost:9999/",                  // dangerous name
		"http://metadata.google.internal/",        // dangerous name
		"http://does-not-exist.invalid/",          // cannot be checked
	} {
		_, err := c.Get(target)
		if err == nil {
			t.Errorf("%s: allowed through the proxy", target)
			continue
		}
		// Loopback is never proxied (Go's NO_PROXY rule), so those go
		// direct and the dialer's own check refuses them.
		direct := strings.Contains(target, "127.0.0.1") || strings.Contains(target, "[::1]") || strings.Contains(target, "localhost")
		if !direct && !errors.Is(err, ErrProxiedTargetBlocked) {
			t.Errorf("%s: err = %v, want ErrProxiedTargetBlocked", target, err)
		}
		if direct && !strings.Contains(err.Error(), "ssrf guard: blocked IP") {
			t.Errorf("%s: err = %v, want the dialer's refusal", target, err)
		}
	}
	if got := p.requests(); len(got) != 0 {
		t.Fatalf("the proxy was asked for refused targets: %v", got)
	}
}

func TestSafeHTTPClient_RedirectToPrivateRefusedThroughProxy(t *testing.T) {
	p := newFakeProxy(t)
	p.redirect = "http://10.1.2.3/internal"
	useContentProxy(t, p.srv.URL)

	_, err := SafeHTTPClient(5 * time.Second).Get("http://203.0.113.7/start")
	if !errors.Is(err, ErrProxiedTargetBlocked) {
		t.Fatalf("redirect into a private address: err = %v, want ErrProxiedTargetBlocked", err)
	}
	if got := p.requests(); len(got) != 1 {
		t.Fatalf("the proxy saw the redirect target: %v", got)
	}
}

func TestSafeHTTPClient_TrustedUpstreamHostSkipsLocalDNS(t *testing.T) {
	p := newFakeProxy(t)
	useContentProxy(t, p.srv.URL)
	const host = "content-upstream.invalid"
	t.Cleanup(func() {
		proxyMu.Lock()
		delete(trustedUpHost, host)
		proxyMu.Unlock()
	})

	c := SafeHTTPClient(5 * time.Second)
	if _, err := c.Get("http://" + host + "/rules"); !errors.Is(err, ErrProxiedTargetBlocked) {
		t.Fatalf("unregistered unresolvable host: err = %v", err)
	}
	TrustUpstreamHosts(strings.ToUpper(host))
	resp, err := c.Get("http://" + host + "/rules")
	if err != nil {
		t.Fatalf("registered upstream host: %v", err)
	}
	_ = resp.Body.Close()
	if got := p.requests(); len(got) != 1 {
		t.Fatalf("proxy saw %v", got)
	}
}

func TestSafeHTTPClient_DirectSettingIgnoresEnvironment(t *testing.T) {
	useContentProxy(t, "direct")
	tr := SafeHTTPClient(time.Second).Transport.(*http.Transport)
	u, _ := url.Parse("http://203.0.113.7/")
	if got, err := tr.Proxy(&http.Request{URL: u}); err != nil || got != nil {
		t.Fatalf("direct content path: proxy %v, err %v", got, err)
	}
}

func TestNewAPIClient_UsesAPIProxySetting(t *testing.T) {
	s, err := ParseProxySetting("http://control-proxy.corp:3128", "")
	if err != nil {
		t.Fatal(err)
	}
	SetAPIProxy(s)
	t.Cleanup(func() { SetAPIProxy(ProxySetting{}) })
	tr := NewAPIClient(time.Second).Transport.(*http.Transport)
	u, _ := url.Parse("https://platform.corp.example/api/v2/sensor/heartbeat")
	got, err := tr.Proxy(&http.Request{URL: u})
	if err != nil || got == nil || got.Host != "control-proxy.corp:3128" {
		t.Fatalf("API path proxy = %v, %v", got, err)
	}
}

func TestEnvironmentProxySummary_Redacts(t *testing.T) {
	for _, n := range ProxyEnvVars {
		t.Setenv(n, "")
	}
	t.Setenv("HTTPS_PROXY", "http://user:hunter2@proxy.corp:3128")
	t.Setenv("NO_PROXY", ".corp,10.0.0.0/8")
	got := EnvironmentProxySummary()
	if strings.Contains(got, "hunter2") {
		t.Fatalf("summary leaks the password: %s", got)
	}
	if !strings.Contains(got, "HTTPS_PROXY=http://user:xxxxx@proxy.corp:3128") || !strings.Contains(got, "NO_PROXY=.corp,10.0.0.0/8") {
		t.Fatalf("summary = %q", got)
	}
}

func TestSafeHTTPClient_ContentRootCAs(t *testing.T) {
	if SafeHTTPClient(time.Second).Transport.(*http.Transport).TLSClientConfig != nil {
		t.Fatal("default content client must use Go's TLS defaults")
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	SetContentRootCAs(pool)
	t.Cleanup(func() { SetContentRootCAs(nil) })
	cfg := SafeHTTPClient(time.Second).Transport.(*http.Transport).TLSClientConfig
	if cfg == nil || cfg.RootCAs != pool {
		t.Fatal("SafeHTTPClient does not trust the content root CAs")
	}
	if ContentRootCAs() != pool {
		t.Fatal("ContentRootCAs")
	}
}
