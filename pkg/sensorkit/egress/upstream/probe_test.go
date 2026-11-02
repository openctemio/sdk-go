package upstream

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

// echoFixture is a TLS echo (answers the address a request came from, only
// for its token) and a plain second listener, both on loopback.
type echoFixture struct {
	url     string
	altPort int
	roots   *x509.CertPool
	mu      sync.Mutex
	paths   []string
	heard   []string
}

func newEchoFixture(t *testing.T) *echoFixture {
	t.Helper()
	f := &echoFixture{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.RequestURI())
		f.heard = append(f.heard, r.Header.Get("Authorization")+r.Header.Get("Cookie"))
		f.mu.Unlock()
		if tok := r.URL.Query().Get("t"); tok != "tok" && !strings.HasPrefix(tok, "tok-") {
			http.NotFound(w, r)
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_ = json.NewEncoder(w).Encode(map[string]string{"address": host})
	}))
	t.Cleanup(srv.Close)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(srv.Certificate())
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	// httptest's certificate is valid for example.com.
	f.url = "https://example.com:" + port + "/echo?t=tok"
	alt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alt.Close() })
	go func() {
		for {
			c, err := alt.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	f.altPort = portOf(t, alt.Addr().String())
	return f
}

func (f *echoFixture) spec(mod ...func(*TestSpec)) TestSpec {
	s := TestSpec{allowDenied: true, EchoURL: f.url, AltPort: f.altPort, Timeout: 10 * time.Second, RootCAs: f.roots,
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}
	for _, m := range mod {
		m(&s)
	}
	return s
}

// limitedProxy is an HTTP CONNECT proxy that only lets one port through
// (403 for every other).
func limitedProxy(t *testing.T, allowPort int) *testProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tp := &testProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if _, p, _ := net.SplitHostPort(req.Host); p != strconv.Itoa(allowPort) {
					_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				pipe(c, br, up)
			}()
		}
	}()
	return tp
}

func testCfg(eps ...Endpoint) Config {
	return Config{Mode: ModePool, PoolID: "p1", AppliesTo: AppliesAll, Strategy: StrategyPriority, Endpoints: eps}
}

func TestPoolTestEchoThroughFakeProxyGivesExitAddressAndFamilies(t *testing.T) {
	echo := newEchoFixture(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128)), n)

	res := p.Test(context.Background(), echo.spec())
	if len(res) != 1 {
		t.Fatalf("results %+v", res)
	}
	r := res[0]
	if !r.OK || r.Class != "" || r.EndpointID != "e1" {
		t.Fatalf("result %+v", r)
	}
	// The echo saw the proxy, not the sensor: the proxy dialed it.
	if r.ExitIP != "127.0.0.1" {
		t.Fatalf("exit %q", r.ExitIP)
	}
	if len(r.Families) != 1 || r.Families[0] != "v4" {
		t.Fatalf("families %v", r.Families)
	}
	if r.PortRestricted == nil || *r.PortRestricted {
		t.Fatalf("port restricted %v", r.PortRestricted)
	}
	// The only thing the echo got was the token, no credential or cookie.
	echo.mu.Lock()
	defer echo.mu.Unlock()
	if len(echo.paths) != 1 || echo.paths[0] != "/echo?t=tok" || echo.heard[0] != "" {
		t.Fatalf("echo saw %v %v", echo.paths, echo.heard)
	}
}

func TestPoolTestDetectsPortRestrictedProxy(t *testing.T) {
	echo := newEchoFixture(t)
	tp := limitedProxy(t, mustAtoi(t, echoPort(t, echo.url)))
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128)), n)

	r := p.Test(context.Background(), echo.spec())[0]
	if !r.OK {
		t.Fatalf("a proxy that carries 443 is up: %+v", r)
	}
	if r.PortRestricted == nil || !*r.PortRestricted {
		t.Fatalf("a 443-only proxy was not detected: %v", r.PortRestricted)
	}
}

func echoPort(t *testing.T, u string) string {
	t.Helper()
	i := strings.LastIndex(u, ":")
	j := strings.Index(u[i:], "/")
	return u[i+1 : i+j]
}

func TestPoolTestClassifiesFailures(t *testing.T) {
	echo := newEchoFixture(t)
	n := newNetmap()
	// Wrong credentials: quarantine-class proxy_auth.
	auth := httpProxy(t, 200, "alice", "pw-1", "")
	n.add("10.0.0.5:3128", auth.addr())
	// A proxy that is not there.
	p := newTestPool(t, testCfg(
		Endpoint{ID: "bad", Scheme: SchemeHTTP, Host: "10.0.0.5", Port: 3128, Weight: 1, Auth: true},
		ep("down", SchemeHTTP, "10.0.0.9", 3128)), n)
	if err := p.SetCredentials([]Credential{{EndpointID: "bad", Username: "alice", Password: "wrong-pw"}}); err != nil {
		t.Fatal(err)
	}
	res := p.Test(context.Background(), echo.spec())
	if len(res) != 2 {
		t.Fatalf("results %+v", res)
	}
	if res[0].OK || res[0].Class != egress.ClassProxyAuth {
		t.Fatalf("bad credentials: %+v", res[0])
	}
	if res[1].OK || res[1].Class != egress.ClassProxyDown {
		t.Fatalf("down: %+v", res[1])
	}
	for _, r := range res {
		if strings.Contains(r.Error, "wrong-pw") || strings.Contains(r.Error, "alice") {
			t.Fatalf("credential in the error: %q", r.Error)
		}
	}
	// The attempts count towards the report, which feeds the platform's health.
	rep := p.Report()
	got := map[string]EndpointReport{}
	for _, e := range rep.Endpoints {
		got[e.EndpointID] = e
	}
	if got["bad"].ProxyAuth != 1 || got["down"].ProxyDown != 1 {
		t.Fatalf("report %+v", rep)
	}
}

func TestPoolTestAnEchoThatAnswersNoAddressIsNotAProxyFailure(t *testing.T) {
	echo := newEchoFixture(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128)), n)
	spec := echo.spec(func(s *TestSpec) { s.EchoURL = strings.Replace(s.EchoURL, "t=tok", "t=wrong", 1) })
	r := p.Test(context.Background(), spec)[0]
	if r.OK || r.Class != ClassEchoFailed {
		t.Fatalf("result %+v", r)
	}
}

func TestPoolTestRefusesAnEchoThatIsNotHTTPS(t *testing.T) {
	n := newNetmap()
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128)), n)
	for _, u := range []string{"http://example.com/echo", "", "https:///x", "https://example.com:0/x"} {
		r := p.Test(context.Background(), TestSpec{EchoURL: u})[0]
		if r.OK || r.Class != ClassEchoFailed {
			t.Fatalf("%q: %+v", u, r)
		}
	}
	if n.total() != 0 {
		t.Fatalf("dialed %d times with an unusable echo address", n.total())
	}
}

func TestDialEndpointTestsAQuarantinedBreaker(t *testing.T) {
	target := echoServer(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128)), n)
	for range 3 { // open the breaker: the proxy is not reachable
		n.mu.Lock()
		delete(n.m, "10.0.0.5:3128")
		n.mu.Unlock()
		_, _ = p.Dial(context.Background(), "tcp", target.String())
	}
	if ok, _ := p.acquire(0); ok {
		t.Fatal("breaker should be open")
	}
	n.add("10.0.0.5:3128", tp.addr())
	c, err := p.DialEndpoint(context.Background(), "e1", target)
	if err != nil {
		t.Fatalf("a test must reach an endpoint whose breaker is open: %v", err)
	}
	_ = c.Close()
	if _, err := p.DialEndpoint(context.Background(), "nope", target); err == nil {
		t.Fatal("unknown endpoint")
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPoolTestNeverTunnelsToADeniedEchoAddress(t *testing.T) {
	echo := newEchoFixture(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128)), n)
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "localhost-by-resolver"} {
		spec := echo.spec(func(s *TestSpec) {
			s.allowDenied = false
			s.EchoURL = "https://" + host + "/echo?t=tok"
			s.Resolve = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
		})
		r := p.Test(context.Background(), spec)[0]
		if r.OK || r.Class != ClassEchoFailed {
			t.Fatalf("%s: %+v", host, r)
		}
	}
	if _, dials := tp.seen(); len(dials) != 0 {
		t.Fatalf("the proxy was asked to connect to %v", dials)
	}
}
