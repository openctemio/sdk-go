package upstream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

// pathForwarder serves a forwarder whose Dial is a one-endpoint pool, for
// the target name app.example at 203.0.113.7, with its own reach recorder.
func pathForwarder(t *testing.T, scheme string, proxy *testProxy) (*egress.Forwarder, string) {
	t.Helper()
	n := newNetmap()
	if proxy != nil {
		n.add("10.0.0.1:1", proxy.addr())
	}
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", scheme, "10.0.0.1", 1)}}, n)
	scope := egress.Scope{Names: map[string][]netip.Addr{"app.example": {netip.MustParseAddr("203.0.113.7")}}}
	fw := egress.New(scope, egress.Limits{})
	fw.Dial = p.Dial
	fw.Reach = reach.NewRecorder()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = fw.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fw, ln.Addr().String()
}

func gapOf(fw *egress.Forwarder, host string) (adapt.Gap, bool) {
	for _, g := range fw.TargetRate().Summary().Gaps {
		if g.Host == host {
			return g, true
		}
	}
	return adapt.Gap{}, false
}

// SECURITY (silent false negative): a connection the pool could not carry
// never reached the target. The host gets a proxy_unavailable coverage gap,
// so the scan ends partial and never reads as "nothing found" (nor closes
// findings by absence), and nothing is learned about the target: no reach
// observation, no back-off.
func TestPathFaultIsACoverageGapNotATargetFact(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
		proxy  func(t *testing.T) *testProxy
	}{
		{"every endpoint down", SchemeHTTP, func(*testing.T) *testProxy { return nil }},
		{"proxy refuses our credentials", SchemeHTTP, func(t *testing.T) *testProxy { return httpProxy(t, 407, "", "", "") }},
		{"proxy refuses our credentials with 401", SchemeHTTP, func(t *testing.T) *testProxy { return httpProxy(t, 401, "", "", "") }},
		{"connect proxy refuses the port", SchemeHTTP, func(t *testing.T) *testProxy { return httpProxy(t, 403, "", "", "") }},
		{"socks ruleset refuses", SchemeSOCKS5, func(t *testing.T) *testProxy { return socksProxy(t, 2, "", "") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fw, addr := pathForwarder(t, tc.scheme, tc.proxy(t))
			c, resp := connectVia(t, addr, "app.example:8080")
			_ = c.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatal("tunnel up")
			}
			g, ok := gapOf(fw, "app.example")
			if !ok || g.Reason != adapt.GapProxyUnavailable {
				t.Fatalf("gaps %+v, want app.example proxy_unavailable", fw.TargetRate().Summary().Gaps)
			}
			if strings.Contains(g.Detail, "10.0.0.1") {
				t.Fatalf("gap detail names the proxy: %q", g.Detail)
			}
			if rep := fw.Reach.Report(); rep.Targets != 0 {
				t.Fatalf("a path failure was recorded about the target: %+v", rep)
			}
			if s := fw.TargetRate().Summary(); s.Throttled != 0 || s.Unreachable != 0 {
				t.Fatalf("the target's rate moved: %+v", s)
			}
		})
	}
}

// What a proxy says about the target is a reach fact, so a host that does
// not answer through the pool is unreached (the coverage is partial, as
// on the direct path), and a refused port is a working path. The reach
// detail never names the proxy.
func TestProxyAnswersAboutTheTargetAreReachFacts(t *testing.T) {
	cases := []struct {
		name      string
		scheme    string
		proxy     func(t *testing.T) *testProxy
		class     reach.Class
		unreached int
	}{
		{"connect 502", SchemeHTTP, func(t *testing.T) *testProxy { return httpProxy(t, 502, "", "", "") }, reach.NoRoute, 1},
		{"connect 500 (unable to connect)", SchemeHTTP, func(t *testing.T) *testProxy { return httpProxy(t, 500, "", "", "") }, reach.NoRoute, 1},
		{"connect 504", SchemeHTTP, func(t *testing.T) *testProxy { return httpProxy(t, 504, "", "", "") }, reach.Timeout, 1},
		{"socks host unreachable", SchemeSOCKS5, func(t *testing.T) *testProxy { return socksProxy(t, 4, "", "") }, reach.NoRoute, 1},
		{"socks general failure", SchemeSOCKS5, func(t *testing.T) *testProxy { return socksProxy(t, 1, "", "") }, reach.Timeout, 1},
		{"socks connection refused", SchemeSOCKS5, func(t *testing.T) *testProxy { return socksProxy(t, 5, "", "") }, reach.PortClosed, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fw, addr := pathForwarder(t, tc.scheme, tc.proxy(t))
			c, _ := connectVia(t, addr, "app.example:8080")
			_ = c.Close()
			rep := fw.Reach.Report()
			if rep.Targets != 1 || rep.Classes[tc.class] != 1 || rep.Unreached != tc.unreached {
				t.Fatalf("reach %+v, want one target of class %s (unreached %d)", rep.Summary, tc.class, tc.unreached)
			}
			for _, u := range rep.UnreachedList {
				if strings.Contains(u.Detail, "10.0.0.1") {
					t.Fatalf("reach detail names the proxy: %q", u.Detail)
				}
			}
			if _, ok := gapOf(fw, "app.example"); ok {
				t.Fatal("an answer about the target made a path gap")
			}
		})
	}
}

// A CONNECT 401 is the proxy refusing our credentials (only the proxy can
// answer before the tunnel is up): the endpoint is out for the job and the
// platform hears proxy_auth. A CONNECT 500 is a live proxy that could not
// reach the target: never proxy_down, so a port scan of closed ports
// through such a proxy does not quarantine it.
func TestProxyStatusClasses(t *testing.T) {
	for code, want := range map[int]string{401: egress.ClassProxyAuth, 500: egress.ClassTargetUnreachable, 501: egress.ClassProxyDown} {
		tp := httpProxy(t, code, "", "", "")
		n := newNetmap()
		n.add("10.0.0.1:1", tp.addr())
		p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
			Endpoints: []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1)}}, n)
		for i := range breakerThreshold + 1 {
			_, err := p.Dial(context.Background(), "tcp", "203.0.113.7:8080")
			ue := upErr(t, err)
			if code == 401 && i > 0 {
				// The endpoint refused our credentials: no endpoint left.
				if !errors.Is(err, ErrNoEndpoint) {
					t.Fatalf("CONNECT 401, attempt %d: %v", i, err)
				}
				continue
			}
			if ue.Class != want {
				t.Fatalf("CONNECT %d: class %s, want %s", code, ue.Class, want)
			}
		}
		r := p.Report().Endpoints[0]
		switch code {
		case 401:
			if r.ProxyAuth != 1 || tp.conns.Load() != 1 {
				t.Fatalf("401: report %+v, %d connections (the endpoint must be out after the first)", r, tp.conns.Load())
			}
		case 500:
			if r.ProxyDown != 0 || r.TargetUnreachable != int64(breakerThreshold+1) {
				t.Fatalf("500: report %+v", r)
			}
		}
	}
}
