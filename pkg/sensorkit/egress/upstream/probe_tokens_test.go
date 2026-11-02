package upstream

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPoolTestUsesEachEndpointsOwnEchoURL(t *testing.T) {
	echo := newEchoFixture(t)
	a := httpProxy(t, 200, "", "", "")
	b := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", a.addr())
	n.add("10.0.0.6:3128", b.addr())
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128), ep("e2", SchemeHTTP, "10.0.0.6", 3128)), n)
	base := strings.TrimSuffix(echo.url, "tok")
	res := p.Test(context.Background(), echo.spec(func(s *TestSpec) {
		s.EndpointURLs = map[string]string{"e1": base + "tok-e1", "e2": base + "tok-e2"}
	}))
	if len(res) != 2 || !res[0].OK || !res[1].OK {
		t.Fatalf("results %+v", res)
	}
	// Each endpoint's request carried its own token, never the shared one,
	// so each observation names the endpoint that made it.
	echo.mu.Lock()
	defer echo.mu.Unlock()
	if !slices.Equal(echo.paths, []string{"/echo?t=tok-e1", "/echo?t=tok-e2"}) {
		t.Fatalf("echo saw %v", echo.paths)
	}
}

func TestPoolTestRefusesAnEndpointEchoOffThePlatformEcho(t *testing.T) {
	echo := newEchoFixture(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128)), n)
	port := echoPort(t, echo.url)
	for _, u := range []string{
		"https://elsewhere.example:" + port + "/echo?t=tok-e1", // another host
		"https://example.com:1/echo?t=tok-e1",                  // another port
		"http://example.com:" + port + "/echo?t=tok-e1",        // not https
	} {
		res := p.Test(context.Background(), echo.spec(func(s *TestSpec) { s.EndpointURLs = map[string]string{"e1": u} }))
		if len(res) != 1 || res[0].OK || res[0].Class != ClassEchoFailed {
			t.Fatalf("%s: result %+v, want echo_failed", u, res)
		}
	}
	if tp.conns.Load() != 0 {
		t.Fatal("an echo address off the platform's echo was tunneled to")
	}
}

func TestPoolTestOnlyTheNamedEndpoints(t *testing.T) {
	echo := newEchoFixture(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.6:3128", tp.addr())
	p := newTestPool(t, testCfg(ep("e1", SchemeHTTP, "10.0.0.5", 3128), ep("e2", SchemeHTTP, "10.0.0.6", 3128)), n)
	res := p.Test(context.Background(), echo.spec(func(s *TestSpec) { s.Endpoints = []string{"e2"} }))
	if len(res) != 1 || res[0].EndpointID != "e2" || !res[0].OK {
		t.Fatalf("results %+v, want only e2", res)
	}
	if n.count("10.0.0.5:3128") != 0 {
		t.Fatal("an endpoint left out was connected to")
	}
	if res := p.Test(context.Background(), echo.spec(func(s *TestSpec) { s.Endpoints = []string{} })); len(res) != 0 {
		t.Fatalf("an empty list tested %+v", res)
	}
}

func TestProbeGateOncePerEndpointPerInterval(t *testing.T) {
	g := NewProbeGate()
	clk := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return clk }
	if !g.Take("p", "a") || g.Take("p", "a") {
		t.Fatal("a second probe of one endpoint within the interval was allowed")
	}
	if !g.Take("p", "b") || !g.Take("q", "a") {
		t.Fatal("another endpoint, or the same id in another pool, was refused")
	}
	clk = clk.Add(ProbeInterval - time.Second)
	if g.Take("p", "a") {
		t.Fatal("probe allowed before the interval passed")
	}
	clk = clk.Add(time.Second)
	if !g.Take("p", "a") {
		t.Fatal("probe refused after the interval")
	}
	// Bounded: once full of recent entries, a new endpoint is refused;
	// entries past the interval make room.
	for i := range maxProbeEntries {
		g.Take("fill", string(rune('A'+i%26))+strings.Repeat("x", i/26))
	}
	if g.Take("new", "endpoint") {
		t.Fatal("a full gate took a new endpoint")
	}
	clk = clk.Add(ProbeInterval)
	if !g.Take("new", "endpoint") {
		t.Fatal("old entries did not make room")
	}
}
