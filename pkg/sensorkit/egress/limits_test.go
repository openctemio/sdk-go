package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/openctemio/sdk-go/pkg/scopelimit"
)

// site is a local web server that records every path it served.
type site struct {
	mu   sync.Mutex
	hits []string
}

func (s *site) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, r.URL.EscapedPath())
		s.mu.Unlock()
		switch r.URL.Path {
		case "/api/", "/api":
			fmt.Fprint(w, `<a href="/api/a">a</a> <a href="/admin">admin</a> <a href="/api/../secret">up</a> <a href="/apiadmin">x</a>`)
		case "/api/a":
			fmt.Fprint(w, `<a href="/api/b?q=1">b</a> <a href="/api/%2e%2e/admin">enc</a> <a href="/API/c">case</a>`)
		case "/api/b":
			fmt.Fprint(w, `<a href="/api/a">a</a> <a href="/api/..;/admin">semi</a>`)
		default:
			fmt.Fprint(w, "secret at "+r.URL.Path)
		}
	})
}

func (s *site) served() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

func portOf(t *testing.T, u string) int {
	t.Helper()
	pu, _ := url.Parse(u)
	p, _ := strconv.Atoi(pu.Port())
	return p
}

// limitedForwarder admits app.test (pinned to 127.0.0.1) with limits.
func limitedForwarder(t *testing.T, limits ...scopelimit.Limit) (*Forwarder, string) {
	t.Helper()
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}, "free.test": {addr("127.0.0.1")}},
		Limits: limits}, Limits{})
	return f, serve(t, f)
}

func proxiedClient(t *testing.T, proxyAddr string, tlsConf *tls.Config) *http.Client {
	pu, _ := url.Parse("http://" + proxyAddr)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: tlsConf}}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func get(t *testing.T, c *http.Client, rawURL string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The client sends the path as written (it does not clean "..", and
	// keeps the escapes of RawPath).
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-Openctem-Egress") != "refused" {
		t.Fatalf("a 403 that is not the guard's: %s", b)
	}
	return resp.StatusCode, string(b)
}

// SECURITY: a limited name or address is reached only on its allowed
// ports; an unlimited name is not limited.
func TestLimitedPorts(t *testing.T) {
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("192.0.2.10")}, "free.test": {addr("192.0.2.20")}},
		Prefixes: []netip.Prefix{pfx("198.51.100.7/32")},
		Limits:   []scopelimit.Limit{{Host: "app.test", Ports: "443,8000-8100"}, {Host: "198.51.100.7", Ports: "22"}}}, Limits{})
	ctx := context.Background()
	cases := []struct {
		host string
		port int
		ok   bool
	}{
		{"app.test", 443, true}, {"APP.test.", 8050, true}, {"app.test", 80, false}, {"app.test", 8101, false},
		{"free.test", 22, true},
		{"198.51.100.7", 22, true}, {"198.51.100.7", 23, false}, {"::ffff:198.51.100.7", 23, false},
	}
	for _, c := range cases {
		_, err := f.Resolve(ctx, c.host, c.port)
		if (err == nil) != c.ok {
			t.Errorf("Resolve(%s, %d) = %v, want ok=%v", c.host, c.port, err, c.ok)
		}
	}
}

// An absolute-form http:// request to a path-limited port is checked
// before anything is sent; the refusals are recorded.
func TestPathGuardAbsoluteForm(t *testing.T) {
	s := &site{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	f, pa := limitedForwarder(t, scopelimit.Limit{Host: "app.test", Ports: strconv.Itoa(port), PathPrefix: "/api"})
	c := proxiedClient(t, pa, nil)
	base := "http://app.test:" + strconv.Itoa(port)
	for path, want := range map[string]int{
		"/api": 200, "/api/a": 200, "/api/b?q=1": 200,
		"/admin": 403, "/apiadmin": 403, "/API/c": 403, "/api/../secret": 403, "/api/%2e%2e/admin": 403,
		"/api/..%2fadmin": 403, "/api/..;/admin": 403, "/": 403,
	} {
		if got, body := get(t, c, base+path); got != want {
			t.Errorf("%s: %d (%s), want %d", path, got, body, want)
		}
	}
	// Host header naming another host is refused even on the right port.
	conn, err := net.Dial("tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET http://app.test:%d/api HTTP/1.1\r\nHost: free.test\r\n\r\n", port)
	line, _ := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if !strings.Contains(line, " 200 ") {
		// The absolute URL wins over the Host header (RFC 9112 §3.2.2).
		t.Errorf("absolute-form with a Host header: %q", line)
	}
	for _, p := range s.served() {
		if !strings.HasPrefix(p, "/api") || strings.Contains(p, "..") || strings.Contains(p, "%") {
			t.Errorf("the server saw %q", p)
		}
	}
	if n := len(f.Refusals()); n < 8 {
		t.Errorf("%d refusals recorded", n)
	}
}

// Requests inside a CONNECT tunnel are checked one by one on a kept-alive
// connection, with the Host header, and the tunnel closes on a refusal.
func TestPathGuardTunnel(t *testing.T) {
	s := &site{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	f, pa := limitedForwarder(t, scopelimit.Limit{Host: "app.test", Ports: strconv.Itoa(port), PathPrefix: "/api/"})
	tunnel := func(t *testing.T, requests string) []string {
		t.Helper()
		c, err := net.Dial("tcp", pa)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "CONNECT app.test:%d HTTP/1.1\r\nHost: app.test\r\n\r\n%s", port, requests)
		br := bufio.NewReader(c)
		for { // the CONNECT answer: a status line and a blank line
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
		}
		var status []string
		for {
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
			if err != nil {
				return status
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			status = append(status, strconv.Itoa(resp.StatusCode))
		}
	}
	h := "app.test:" + strconv.Itoa(port)
	got := tunnel(t, "GET /api/a HTTP/1.1\r\nHost: "+h+"\r\n\r\nGET /api/b HTTP/1.1\r\nHost: "+h+"\r\n\r\nGET /admin HTTP/1.1\r\nHost: "+h+"\r\n\r\nGET /api/a HTTP/1.1\r\nHost: "+h+"\r\n\r\n")
	if strings.Join(got, ",") != "200,200,403" {
		t.Errorf("keep-alive tunnel: %v", got)
	}
	for name, req := range map[string]string{
		"other host":     "GET /api/a HTTP/1.1\r\nHost: free.test:" + strconv.Itoa(port) + "\r\n\r\n",
		"other port":     "GET /api/a HTTP/1.1\r\nHost: app.test:1\r\n\r\n",
		"absolute other": "GET http://free.test/api/a HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"upgrade":        "GET /api/a HTTP/1.1\r\nHost: " + h + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		"asterisk":       "OPTIONS * HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"h2 preface":     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
		"backslash":      "GET /api\\..\\admin HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"encoded slash":  "GET /api%2f..%2fadmin HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
	} {
		if got := tunnel(t, req); len(got) > 0 && got[0] != "403" {
			t.Errorf("%s: %v", name, got)
		}
	}
	for _, p := range s.served() {
		if !strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/apia") {
			t.Errorf("the server saw %q", p)
		}
	}
	if len(f.Refusals()) == 0 {
		t.Error("no refusal recorded")
	}
}

// TLS to a path-limited port is terminated with the forwarder's authority
// (a tool that verifies can trust AuthorityPEM), the requests are checked,
// and a server name that is not the destination fails the handshake.
func TestPathGuardTLS(t *testing.T) {
	s := &site{}
	srv := httptest.NewTLSServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	f, pa := limitedForwarder(t, scopelimit.Limit{Host: "app.test", Ports: strconv.Itoa(port), PathPrefix: "/api"})
	if err := f.CreateAuthority(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.AuthorityPEM()) {
		t.Fatal("authority PEM")
	}
	c := proxiedClient(t, pa, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	base := "https://app.test:" + strconv.Itoa(port)
	for path, want := range map[string]int{"/api/a": 200, "/api/b": 200, "/admin": 403, "/api/%2e%2e/admin": 403} {
		if got, body := get(t, c, base+path); got != want {
			t.Errorf("%s: %d (%s), want %d", path, got, body, want)
		}
	}
	// SNI for another host through a tunnel to app.test.
	conn, err := net.Dial("tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "CONNECT app.test:%d HTTP/1.1\r\nHost: app.test\r\n\r\n", port)
	br := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "free.test", InsecureSkipVerify: true}) //nolint:gosec // test
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Error("handshake with another server name succeeded")
	}
	_ = conn.Close()
	for _, p := range s.served() {
		if !strings.HasPrefix(p, "/api") || strings.Contains(p, "%") {
			t.Errorf("the server saw %q", p)
		}
	}
}

// SOCKS5 to a path-limited port is guarded the same way.
func TestPathGuardSOCKS5(t *testing.T) {
	s := &site{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	_, pa := limitedForwarder(t, scopelimit.Limit{Host: "app.test", Ports: strconv.Itoa(port), PathPrefix: "/api"})
	d, err := proxy.SOCKS5("tcp", pa, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		return d.(proxy.ContextDialer).DialContext(ctx, n, a)
	}}}
	t.Cleanup(c.CloseIdleConnections)
	base := "http://app.test:" + strconv.Itoa(port)
	if got, _ := get(t, c, base+"/api/a"); got != 200 {
		t.Errorf("/api/a: %d", got)
	}
	if got, _ := get(t, c, base+"/admin"); got != 403 {
		t.Errorf("/admin: %d", got)
	}
	// Another port of the limited host is refused at SOCKS level.
	if _, err := d.Dial("tcp", "app.test:1"); err == nil {
		t.Error("another port reached")
	}
}

var hrefRE = regexp.MustCompile(`href="([^"]+)"`)

// End to end: a crawler that follows every link it finds, through the
// forwarder, stays inside the path prefix; the server never serves a path
// outside it, and every attempt outside is refused and recorded.
func TestCrawlStaysInsidePrefix(t *testing.T) {
	s := &site{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	f, pa := limitedForwarder(t, scopelimit.Limit{Host: "app.test", Ports: strconv.Itoa(port), PathPrefix: "/api"})
	c := proxiedClient(t, pa, nil)
	base := "http://app.test:" + strconv.Itoa(port)
	queue, seen := []string{"/api/"}, map[string]bool{"/api/": true}
	refused := 0
	for len(queue) > 0 && len(seen) < 50 {
		p := queue[0]
		queue = queue[1:]
		code, body := get(t, c, base+p)
		if code == http.StatusForbidden {
			refused++
			continue
		}
		for _, m := range hrefRE.FindAllStringSubmatch(body, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				queue = append(queue, m[1])
			}
		}
	}
	if refused < 5 {
		t.Errorf("%d links refused, want the 5 outside the prefix (%v)", refused, seen)
	}
	for _, p := range s.served() {
		if p != "/api/" && p != "/api/a" && p != "/api/b" {
			t.Errorf("the server served %q", p)
		}
	}
	reasons := 0
	for _, r := range f.Refusals() {
		if r.Protocol == ProtocolHTTPPath && r.Host == "app.test:"+strconv.Itoa(port) && strings.Contains(r.Reason, "scope limits") {
			reasons++
		}
	}
	if reasons != refused {
		t.Errorf("%d refusals recorded, %d seen by the crawler: %+v", reasons, refused, f.Refusals())
	}
}
