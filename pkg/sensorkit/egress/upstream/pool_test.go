package upstream

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

func ep(id, scheme, host string, port int) Endpoint {
	return Endpoint{ID: id, Scheme: scheme, Host: host, Port: port, Weight: 1}
}

func portOf(t *testing.T, addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func upErr(t *testing.T, err error) *egress.UpstreamError {
	t.Helper()
	var ue *egress.UpstreamError
	if !errors.As(err, &ue) {
		t.Fatalf("error %v is not an *egress.UpstreamError", err)
	}
	return ue
}

func TestHTTPConnectTunnelKeepsBufferedBytes(t *testing.T) {
	target := echoServer(t)
	tp := httpProxy(t, 200, "", "", "early:")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("e1", SchemeHTTP, "10.0.0.5", 3128)}}, n)
	c, err := p.Dial(egress.WithTargetHost(context.Background(), "example.com"), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := roundTrip(t, c); got != "early:echo:ping\n" {
		t.Fatalf("got %q", got)
	}
	if ec, ok := c.(egress.EndpointConn); !ok || ec.UpstreamEndpoint() != "e1" {
		t.Fatal("tunnel does not name its endpoint")
	}
	auth, dials := tp.seen()
	if auth[0] != "" {
		t.Fatalf("Proxy-Authorization sent without credentials: %q", auth[0])
	}
	if dials[0] != target.String() {
		t.Fatalf("CONNECT %q, want the address %s", dials[0], target)
	}
	r := p.Report()
	if len(r.Endpoints) != 1 || r.Endpoints[0].OK != 1 || r.PoolID != "p1" {
		t.Fatalf("report %+v", r)
	}
}

func TestHTTPConnectSendsBasicAuth(t *testing.T) {
	target := echoServer(t)
	tp := httpProxy(t, 200, "alice", "pw-1", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	e := ep("e1", SchemeHTTP, "10.0.0.5", 3128)
	e.Auth = true
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", AppliesTo: AppliesAll, Endpoints: []Endpoint{e}}, n)
	if err := p.SetCredentials([]Credential{{EndpointID: "e1", Username: "alice", Password: "pw-1"}}); err != nil {
		t.Fatal(err)
	}
	c, err := p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, c); got != "echo:ping\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSOCKS5TunnelWithAuth(t *testing.T) {
	target := echoServer(t)
	tp := socksProxy(t, 0, "bob", "pw-2")
	n := newNetmap()
	n.add("10.0.0.6:1080", tp.addr())
	for _, scheme := range []string{SchemeSOCKS5, SchemeSOCKS5H} {
		e := ep("e1", scheme, "10.0.0.6", 1080)
		e.Username, e.Password = "bob", "pw-2"
		p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", AppliesTo: AppliesAll, Endpoints: []Endpoint{e}}, n)
		c, err := p.Dial(context.Background(), "tcp", target.String())
		if err != nil {
			t.Fatal(err)
		}
		if got := roundTrip(t, c); got != "echo:ping\n" {
			t.Fatalf("%s: got %q", scheme, got)
		}
	}
	_, dials := tp.seen()
	if dials[0] != target.String() {
		t.Fatalf("CONNECT %q, want %s", dials[0], target)
	}
}

func TestSOCKS5IPv6Target(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	_ = ln.Close()
	tp := socksProxy(t, 0x05, "", "")
	n := newNetmap()
	n.add("10.0.0.6:1080", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("e1", SchemeSOCKS5, "10.0.0.6", 1080)}}, n)
	_, err = p.Dial(context.Background(), "tcp", "[2001:db8::1]:443")
	if ue := upErr(t, err); ue.Class != egress.ClassTargetUnreachable {
		t.Fatalf("class %s", ue.Class)
	}
	if _, dials := tp.seen(); len(dials) != 1 || dials[0] != "[2001:db8::1]:443" {
		t.Fatalf("dials %v", dials)
	}
}

func TestProxyDownFailoverIsBoundedByEndpoints(t *testing.T) {
	n := newNetmap() // nothing mapped: every endpoint refuses
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", AppliesTo: AppliesAll, Endpoints: []Endpoint{
		ep("a", SchemeHTTP, "10.0.0.1", 3128), ep("b", SchemeSOCKS5, "10.0.0.2", 1080), ep("c", SchemeHTTP, "10.0.0.3", 3128)}}, n)
	_, err := p.Dial(context.Background(), "tcp", "203.0.113.7:443")
	ue := upErr(t, err)
	if ue.Class != egress.ClassProxyDown || !ue.Final {
		t.Fatalf("got %+v", ue)
	}
	if got := n.total(); got != 3 {
		t.Fatalf("%d attempts, want exactly 3 (one per endpoint)", got)
	}
	if n.count("203.0.113.7:443") != 0 {
		t.Fatal("the target was dialed directly")
	}
}

func TestProxyAuthDoesNotFailOver(t *testing.T) {
	target := echoServer(t)
	bad := httpProxy(t, 200, "alice", "right", "")
	good := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:3128", bad.addr())
	n.add("10.0.0.2:3128", good.addr())
	a := ep("a", SchemeHTTP, "10.0.0.1", 3128)
	a.Username, a.Password = "alice", "wrong"
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", Strategy: StrategyPriority, AppliesTo: AppliesAll,
		Endpoints: []Endpoint{a, ep("b", SchemeHTTP, "10.0.0.2", 3128)}}, n)
	_, err := p.Dial(context.Background(), "tcp", target.String())
	if ue := upErr(t, err); ue.Class != egress.ClassProxyAuth || !ue.Final || ue.Endpoint != "a" {
		t.Fatalf("got %+v", ue)
	}
	if good.conns.Load() != 0 {
		t.Fatal("a 407 failed over to the next endpoint")
	}
	// The endpoint is unusable for the rest of the job: the next
	// connection goes to b.
	c, err := p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if bad.conns.Load() != 1 {
		t.Fatalf("the endpoint that refused our credentials was tried %d times", bad.conns.Load())
	}
}

func TestSOCKSAuthFailureIsProxyAuth(t *testing.T) {
	tp := socksProxy(t, 0, "bob", "right")
	n := newNetmap()
	n.add("10.0.0.6:1080", tp.addr())
	e := ep("e1", SchemeSOCKS5, "10.0.0.6", 1080)
	e.Username, e.Password = "bob", "wrong"
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", AppliesTo: AppliesAll, Endpoints: []Endpoint{e}}, n)
	_, err := p.Dial(context.Background(), "tcp", "203.0.113.7:443")
	if ue := upErr(t, err); ue.Class != egress.ClassProxyAuth {
		t.Fatalf("class %s", ue.Class)
	}
	// Without credentials against a proxy that requires them.
	p2 := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("e1", SchemeSOCKS5, "10.0.0.6", 1080)}}, n)
	_, err = p2.Dial(context.Background(), "tcp", "203.0.113.7:443")
	if ue := upErr(t, err); ue.Class != egress.ClassProxyAuth {
		t.Fatalf("class %s", ue.Class)
	}
}

func TestTargetAnswersDoNotFailOver(t *testing.T) {
	cases := []struct {
		name  string
		first func(t *testing.T) *testProxy
		class string
	}{
		{"connect 502", func(t *testing.T) *testProxy { return httpProxy(t, 502, "", "", "") }, egress.ClassTargetUnreachable},
		{"connect 504", func(t *testing.T) *testProxy { return httpProxy(t, 504, "", "", "") }, egress.ClassTargetUnreachable},
		{"connect 403", func(t *testing.T) *testProxy { return httpProxy(t, 403, "", "", "") }, egress.ClassTargetRefused},
		{"socks 2", func(t *testing.T) *testProxy { return socksProxy(t, 2, "", "") }, egress.ClassTargetRefused},
		{"socks 4", func(t *testing.T) *testProxy { return socksProxy(t, 4, "", "") }, egress.ClassTargetUnreachable},
		{"socks 5", func(t *testing.T) *testProxy { return socksProxy(t, 5, "", "") }, egress.ClassTargetUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.first(t)
			second := httpProxy(t, 200, "", "", "")
			n := newNetmap()
			scheme := SchemeHTTP
			if strings.HasPrefix(tc.name, "socks") {
				scheme = SchemeSOCKS5
			}
			n.add("10.0.0.1:1", first.addr())
			n.add("10.0.0.2:1", second.addr())
			p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", Strategy: StrategyPriority, AppliesTo: AppliesAll,
				Endpoints: []Endpoint{ep("a", scheme, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1)}}, n)
			_, err := p.Dial(context.Background(), "tcp", "203.0.113.7:443")
			if ue := upErr(t, err); ue.Class != tc.class {
				t.Fatalf("class %s, want %s", ue.Class, tc.class)
			}
			if second.conns.Load() != 0 {
				t.Fatal("an answer about the target failed over")
			}
			r := p.Report()
			if r.Endpoints[0].TargetRefused+r.Endpoints[0].TargetUnreachable != 1 {
				t.Fatalf("report %+v", r)
			}
		})
	}
}

func TestGarbageReplyIsProxyDownAndFailsOver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH\r\n\r\n"))
			_ = c.Close()
		}
	}()
	target := echoServer(t)
	good := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:1", ln.Addr().String())
	n.add("10.0.0.2:1", good.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p1", Strategy: StrategyPriority, AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1)}}, n)
	c, err := p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	r := p.Report()
	if len(r.Endpoints) != 2 || r.Endpoints[0].ProxyDown != 1 || r.Endpoints[1].OK != 1 {
		t.Fatalf("report %+v", r)
	}
	if !strings.HasPrefix(r.Endpoints[0].LastError, "proxy_down: http://10.0.0.1:1") {
		t.Fatalf("last_error %q", r.Endpoints[0].LastError)
	}
}

func TestStickyMovesOnlyTheRemovedEndpointsHosts(t *testing.T) {
	var eps []Endpoint
	for i := range 6 {
		e := ep(fmt.Sprintf("e%d", i), SchemeHTTP, fmt.Sprintf("10.0.0.%d", i+1), 3128)
		e.Weight = float64(i + 1)
		eps = append(eps, e)
	}
	n := newNetmap()
	full := newTestPool(t, Config{Mode: ModePool, PoolID: "p", Endpoints: eps}, n)
	less := newTestPool(t, Config{Mode: ModePool, PoolID: "p", Endpoints: append(append([]Endpoint{}, eps[:2]...), eps[3:]...)}, n)
	counts := map[string]int{}
	moved := 0
	for h := range 3000 {
		host := fmt.Sprintf("host-%d.example", h)
		a := full.cfg.Endpoints[full.rank(host)[0]].ID
		b := less.cfg.Endpoints[less.rank(host)[0]].ID
		counts[a]++
		if a != b {
			if a != "e2" {
				t.Fatalf("host %s moved from %s to %s although %s stayed", host, a, b, a)
			}
			moved++
		}
		if again := full.cfg.Endpoints[full.rank(host)[0]].ID; again != a {
			t.Fatal("ranking is not stable")
		}
	}
	if moved != counts["e2"] {
		t.Fatalf("moved %d, e2 had %d", moved, counts["e2"])
	}
	// Weights spread the hosts: e5 (weight 6) carries more than e0 (1).
	if counts["e5"] <= 3*counts["e0"] {
		t.Fatalf("weights not honored: %v", counts)
	}
	// Another job ranks differently (the key is part of the hash).
	other := newTestPool(t, Config{Mode: ModePool, PoolID: "p", Endpoints: eps}, n, func(o *Options) { o.Key = "job-2" })
	diff := 0
	for h := range 200 {
		host := fmt.Sprintf("host-%d.example", h)
		if full.rank(host)[0] != other.rank(host)[0] {
			diff++
		}
	}
	if diff == 0 {
		t.Fatal("the job key does not take part in the ranking")
	}
}

func TestPriorityOrderIsHonored(t *testing.T) {
	target := echoServer(t)
	second := httpProxy(t, 200, "", "", "")
	third := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.2:1", second.addr())
	n.add("10.0.0.3:1", third.addr())
	eps := []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1), ep("c", SchemeHTTP, "10.0.0.3", 1)}
	eps[0].Weight, eps[2].Weight = 100, 100
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", Strategy: StrategyPriority, AppliesTo: AppliesAll, Endpoints: eps}, n)
	for range 5 {
		c, err := p.Dial(egress.WithTargetHost(context.Background(), "x.example"), "tcp", target.String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	if second.conns.Load() != 5 || third.conns.Load() != 0 {
		t.Fatalf("second %d third %d", second.conns.Load(), third.conns.Load())
	}
}

func TestBreakerOpensAndHalfOpens(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	n := newNetmap()
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1)}}, n, func(o *Options) {
		o.now = func() time.Time { return now }
		o.jitter = func() float64 { return 0.5 } // no jitter
	})
	dial := func() error {
		_, err := p.Dial(context.Background(), "tcp", "203.0.113.7:443")
		return err
	}
	for range 3 {
		_ = dial()
	}
	if n.total() != 3 {
		t.Fatalf("%d dials", n.total())
	}
	// Open: no attempt at all.
	if err := dial(); !errors.Is(err, ErrNoEndpoint) || n.total() != 3 {
		t.Fatalf("breaker not open: %v, %d dials", err, n.total())
	}
	now = now.Add(29 * time.Second)
	_ = dial()
	if n.total() != 3 {
		t.Fatal("breaker closed early")
	}
	// Half-open: one probe; it fails, the back-off doubles to 60 s.
	now = now.Add(2 * time.Second)
	_ = dial()
	if n.total() != 4 {
		t.Fatalf("no probe: %d dials", n.total())
	}
	now = now.Add(59 * time.Second)
	_ = dial()
	if n.total() != 4 {
		t.Fatal("back-off did not double")
	}
	// The proxy is back: the probe succeeds and the breaker closes.
	target := echoServer(t)
	tp := httpProxy(t, 200, "", "", "")
	n.add("10.0.0.1:1", tp.addr())
	now = now.Add(2 * time.Second)
	c, err := p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	c, err = p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatalf("breaker did not close: %v", err)
	}
	_ = c.Close()
}

func TestBreakerJitterBounds(t *testing.T) {
	for _, j := range []float64{0, 0.999} {
		now := time.Unix(1_000_000, 0)
		p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
			Endpoints: []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1)}}, newNetmap(), func(o *Options) {
			o.now = func() time.Time { return now }
			o.jitter = func() float64 { return j }
		})
		for range 3 {
			_, _ = p.Dial(context.Background(), "tcp", "203.0.113.7:443")
		}
		d := p.state[0].openUntil.Sub(now)
		if d < 24*time.Second || d > 36*time.Second {
			t.Fatalf("open for %v, want 30s ±20%%", d)
		}
	}
}

func TestBreakerBackoffCapsAtTenMinutes(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1)}}, newNetmap(), func(o *Options) {
		o.now = func() time.Time { return now }
		o.jitter = func() float64 { return 0.5 }
	})
	for range 3 {
		_, _ = p.Dial(context.Background(), "tcp", "203.0.113.7:443")
	}
	for range 10 {
		now = p.state[0].openUntil
		_, _ = p.Dial(context.Background(), "tcp", "203.0.113.7:443")
	}
	if b := p.state[0].backoff; b != 10*time.Minute {
		t.Fatalf("back-off %v", b)
	}
}

func TestAppliesToPublicDialsInternalTargetsDirectly(t *testing.T) {
	target := echoServer(t) // 127.0.0.1: not public
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesPublic,
		Endpoints: []Endpoint{ep("e1", SchemeHTTP, "10.0.0.5", 3128)}}, n)
	c, err := p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, c); got != "echo:ping\n" {
		t.Fatalf("got %q", got)
	}
	if tp.conns.Load() != 0 {
		t.Fatal("an internal target went through the org default pool")
	}
	for _, a := range []string{"10.1.2.3", "192.168.1.1", "100.64.0.1", "fd12::1", "127.0.0.1"} {
		if isPublic(netip.MustParseAddr(a)) {
			t.Fatalf("%s counted as public", a)
		}
	}
	if !isPublic(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("8.8.8.8 not public")
	}
}

func TestDeniedEndpointsAreRefused(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "fd00:ec2::254", "100.100.100.200",
		"0.0.0.0", "0.1.2.3", "240.0.0.1", "255.255.255.255", "224.0.0.1", "ff02::1", "::", "::ffff:127.0.0.1",
		"localhost", "a.localhost", "metadata.google.internal", "bad host", "-x.example"} {
		cfg := Config{Mode: ModePool, PoolID: "p", Endpoints: []Endpoint{ep("e", SchemeHTTP, h, 3128)}}
		if err := cfg.Validate(nil); err == nil {
			t.Errorf("endpoint %q accepted", h)
		}
	}
	for _, h := range []string{"10.0.0.5", "192.168.1.1", "172.16.0.1", "100.64.1.1", "fd12::1", "proxy.corp.example", "203.0.113.9"} {
		cfg := Config{Mode: ModePool, PoolID: "p", Endpoints: []Endpoint{ep("e", SchemeSOCKS5, h, 1080)}}
		if err := cfg.Validate(nil); err != nil {
			t.Errorf("endpoint %q refused: %v", h, err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	base := func() Config {
		return Config{Mode: ModePool, PoolID: "p", Endpoints: []Endpoint{ep("e", SchemeHTTP, "10.0.0.1", 3128)}}
	}
	c := base()
	if err := c.Validate(nil); err != nil || c.Strategy != StrategySticky || c.AppliesTo != AppliesPublic {
		t.Fatalf("defaults: %v %+v", err, c)
	}
	bad := []func(*Config){
		func(c *Config) { c.Mode = "direct" },
		func(c *Config) { c.PoolID = "" },
		func(c *Config) { c.Strategy = "spread" },
		func(c *Config) { c.AppliesTo = "some" },
		func(c *Config) { c.Endpoints[0].Scheme = "ftp" },
		func(c *Config) { c.Endpoints[0].Port = 0 },
		func(c *Config) { c.Endpoints[0].Port = 70000 },
		func(c *Config) { c.Endpoints[0].Weight = 0 },
		func(c *Config) { c.Endpoints[0].ID = "" },
		func(c *Config) { c.Endpoints = append(c.Endpoints, c.Endpoints[0]) },
		func(c *Config) {
			for range MaxEndpoints {
				c.Endpoints = append(c.Endpoints, ep(fmt.Sprint(len(c.Endpoints)), SchemeHTTP, "10.0.0.1", 1))
			}
		},
	}
	for i, mod := range bad {
		c := base()
		mod(&c)
		if err := c.Validate(nil); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	empty := Config{Mode: ModePool, PoolID: "p"}
	if err := empty.Validate(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty pool: %v", err)
	}
}

func TestAllowList(t *testing.T) {
	allow, err := ParseAllow(" proxy.corp.example:3128, 10.0.0.5 ,[fd12::1]:1080,[fd12::2]")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host string
		port int
		ok   bool
	}{
		{"proxy.corp.example", 3128, true}, {"PROXY.corp.example.", 3128, true}, {"proxy.corp.example", 8080, false},
		{"10.0.0.5", 1, true}, {"10.0.0.6", 1, false}, {"fd12::1", 1080, true}, {"fd12::1", 1081, false}, {"fd12::2", 9, true},
	} {
		if got := allow.Allows(c.host, c.port); got != c.ok {
			t.Errorf("%s:%d = %v", c.host, c.port, got)
		}
	}
	cfg := Config{Mode: ModePool, PoolID: "p", Endpoints: []Endpoint{ep("e", SchemeHTTP, "10.0.0.7", 3128)}}
	if err := cfg.Validate(allow); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("got %v", err)
	}
	if a, err := ParseAllow(""); err != nil || a != nil {
		t.Fatal("empty list should be nil")
	}
	for _, s := range []string{"x:0", "x:99999", "127.0.0.1:80", "[fd12::1", ",", "x:"} {
		if _, err := ParseAllow(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestHostNameEndpointResolvingToLoopbackIsRefusedAtDial(t *testing.T) {
	n := newNetmap()
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("e", SchemeHTTP, "proxy.corp.example", 3128)}}, n, func(o *Options) {
		o.lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("127.0.0.1")}, nil
		}
	})
	_, err := p.Dial(context.Background(), "tcp", "203.0.113.7:443")
	if ue := upErr(t, err); ue.Class != egress.ClassProxyDown || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("got %v", err)
	}
	if n.total() != 0 {
		t.Fatal("dialed an endpoint whose name resolves to loopback")
	}
}

func TestHostNameEndpointDialsTheCheckedAddress(t *testing.T) {
	target := echoServer(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	lookups := 0
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("e", SchemeHTTP, "proxy.corp.example", 3128)}}, n, func(o *Options) {
		o.lookup = func(context.Context, string) ([]netip.Addr, error) {
			lookups++
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		}
	})
	c, err := p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if n.count("10.0.0.5:3128") != 1 || lookups != 1 {
		t.Fatalf("dials %d lookups %d", n.count("10.0.0.5:3128"), lookups)
	}
}

// tlsConnectProxy is an https proxy (CONNECT over TLS) with httptest's
// certificate (valid for example.com).
func tlsConnectProxy(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		hj, _ := w.(http.Hijacker)
		c, brw, err := hj.Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_ = brw.Flush()
		pipe(c, brw, up)
		_ = up.Close()
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func TestHTTPSProxyVerifiesTheCertificate(t *testing.T) {
	target := echoServer(t)
	srv, roots := tlsConnectProxy(t)
	n := newNetmap()
	n.add("10.0.0.5:8443", srv.Listener.Addr().String())
	cfg := Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("e", SchemeHTTPS, "example.com", 8443)}}
	lookup := func(o *Options) {
		o.lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		}
	}
	// System roots: httptest's certificate is untrusted.
	p := newTestPool(t, cfg, n, lookup)
	_, err := p.Dial(context.Background(), "tcp", target.String())
	if ue := upErr(t, err); ue.Class != egress.ClassProxyDown || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("untrusted proxy certificate accepted: %v", err)
	}
	// Trusted: the tunnel works over TLS.
	p = newTestPool(t, cfg, n, lookup, func(o *Options) { o.RootCAs = roots })
	c, err := p.Dial(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, c); got != "echo:ping\n" {
		t.Fatalf("got %q", got)
	}
	// The name must match: the same certificate under another name fails.
	cfg.Endpoints[0].Host = "proxy.other.example"
	p = newTestPool(t, cfg, n, lookup, func(o *Options) { o.RootCAs = roots })
	if _, err := p.Dial(context.Background(), "tcp", target.String()); err == nil {
		t.Fatal("certificate accepted for another name")
	}
}

func TestCredentialsNeverInErrorsReportsOrFormatting(t *testing.T) {
	const user, pass = "admin-user-x", "s3cret-pass-y"
	bad := httpProxy(t, 200, "other", "other", "")
	n := newNetmap()
	n.add("10.0.0.1:3128", bad.addr())
	a := ep("a", SchemeHTTP, "10.0.0.1", 3128)
	b := ep("b", SchemeSOCKS5, "10.0.0.2", 1080) // down
	cfg := Config{Mode: ModePool, PoolID: "p", Strategy: StrategyPriority, AppliesTo: AppliesAll, Endpoints: []Endpoint{b, a}}
	p := newTestPool(t, cfg, n)
	if err := p.SetCredentials([]Credential{{EndpointID: "a", Username: user, Password: pass}, {EndpointID: "b", Username: user, Password: pass}}); err != nil {
		t.Fatal(err)
	}
	_, err := p.Dial(context.Background(), "tcp", "203.0.113.7:443")
	rep, _ := json.Marshal(p.Report())
	cfgJSON, _ := json.Marshal(p.cfg)
	withCreds := p.endpoint(1)
	texts := []string{err.Error(), string(rep), string(cfgJSON), fmt.Sprintf("%v %+v %#v %s", withCreds, withCreds, withCreds, withCreds),
		fmt.Sprintf("%v %+v", p.cfg, p.cfg)}
	for _, s := range texts {
		if strings.Contains(s, user) || strings.Contains(s, pass) {
			t.Fatalf("credentials leaked: %s", s)
		}
	}
	if got := sanitize("proxy_down", "dial http://u:"+pass+"@10.0.0.1:3128 failed\n", Endpoint{Password: pass}); strings.Contains(got, pass) || strings.Contains(got, "u:") || strings.Contains(got, "\n") {
		t.Fatalf("sanitize: %q", got)
	}
	if got := sanitize("proxy_down", strings.Repeat("x", 500), Endpoint{}); len(got) > maxLastError {
		t.Fatalf("last_error %d bytes", len(got))
	}
}

func TestCallerCancelTeachesNothing(t *testing.T) {
	// A proxy that never answers the CONNECT.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { buf := make([]byte, 1024); _, _ = c.Read(buf); time.Sleep(3 * time.Second); _ = c.Close() }()
		}
	}()
	n := newNetmap()
	n.add("10.0.0.1:1", ln.Addr().String())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1)}}, n)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = p.Dial(ctx, "tcp", "203.0.113.7:443")
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("handshake not bounded by the context: %v after %v", err, time.Since(start))
	}
	if p.Report().Used() {
		t.Fatalf("a canceled dial was counted: %+v", p.Report())
	}
	// The pool's own attempt timeout: the proxy took the request and the
	// target did not answer in time.
	p = newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1)}}, n, func(o *Options) { o.AttemptTimeout = 200 * time.Millisecond })
	_, err = p.Dial(context.Background(), "tcp", "203.0.113.7:443")
	if ue := upErr(t, err); ue.Class != egress.ClassTargetUnreachable {
		t.Fatalf("class %s", ue.Class)
	}
}
