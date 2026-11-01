package upstream

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

func seeded(seed uint64) func(*Options) {
	return func(o *Options) { o.rand = rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)).Float64 }
}

func TestFirstPickWeightIsPlatformWeightTimesFloorPlusScoreSquared(t *testing.T) {
	eps := []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1), ep("c", SchemeHTTP, "10.0.0.3", 1)}
	eps[1].Weight = 2
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", Endpoints: eps}, newNetmap(), seeded(1))
	// a: healthy, no handshake seen (score 1); b: half its tunnels failed
	// and 1 s handshakes (score 0.5 / 2 = 0.25); c: every tunnel failed
	// (score 0, still pickable at the floor).
	p.state[1].okRate, p.state[1].latency = 0.5, 1
	p.state[2].okRate = 0
	want := []float64{1 * (0.05 + 1), 2 * (0.05 + 0.0625), 1 * 0.05}
	for i, w := range want {
		if got := p.pickWeight(i); math.Abs(got-w) > 1e-12 {
			t.Fatalf("endpoint %s weight %v, want %v", eps[i].ID, got, w)
		}
	}
	// The first picks of new hosts follow the weights (seeded: the same
	// counts on every run).
	counts := map[string]int{}
	const hosts = 20000
	for h := range hosts {
		order, slot := p.order(fmt.Sprintf("h%d.example", h))
		if slot != -1 {
			t.Fatal("a host nobody dialed has a slot")
		}
		counts[eps[order[0]].ID]++
	}
	total := want[0] + want[1] + want[2]
	for i, w := range want {
		got := float64(counts[eps[i].ID]) / hosts
		if math.Abs(got-w/total) > 0.015 {
			t.Fatalf("endpoint %s got %.3f of first picks, want %.3f (%v)", eps[i].ID, got, w/total, counts)
		}
	}
}

func TestLocalScoreFollowsTheProxysOwnOutcomesOnly(t *testing.T) {
	target := echoServer(t)
	good := httpProxy(t, 200, "", "", "")
	refusing := httpProxy(t, 502, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:1", good.addr())
	n.add("10.0.0.2:1", refusing.addr())
	eps := []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1), ep("c", SchemeHTTP, "10.0.0.3", 1)}
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", Strategy: StrategyPriority, AppliesTo: AppliesAll, Endpoints: eps}, n)
	for _, id := range []string{"a", "b", "c"} {
		c, err := p.DialEndpoint(context.Background(), id, target)
		if err == nil {
			_ = c.Close()
		}
	}
	if s := p.state[0]; s.okRate != 1 || s.latency <= 0 {
		t.Fatalf("a carried a tunnel: okRate %v latency %v", s.okRate, s.latency)
	}
	// b answered that the target is unreachable: that is the target's
	// answer, the proxy is up and its score does not move.
	if s := p.state[1]; s.okRate != 1 {
		t.Fatalf("a target's answer moved b's score: okRate %v", s.okRate)
	}
	// c is down.
	if s := p.state[2]; math.Abs(s.okRate-(1-ewmaAlpha)) > 1e-12 {
		t.Fatalf("c is down: okRate %v, want %v", s.okRate, 1-ewmaAlpha)
	}
}

// pickFor returns a rand hook value that makes the first pick of host the
// endpoint id among endpoints of equal weight.
func pickFor(p *Pool, host, id string) float64 {
	idx := p.rank(host)
	for k, i := range idx {
		if p.cfg.Endpoints[i].ID == id {
			return (float64(k) + 0.5) / float64(len(idx))
		}
	}
	panic("no endpoint " + id)
}

func TestStickySlotMovesOnlyOnProxyFailure(t *testing.T) {
	target := echoServer(t)
	a := httpProxy(t, 200, "", "", "")
	b := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:1", a.addr())
	n.add("10.0.0.2:1", b.addr())
	eps := []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1)}
	var pick float64
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll, Endpoints: eps}, n,
		func(o *Options) { o.rand = func() float64 { return pick } })
	const host = "app.example"
	pick = pickFor(p, host, "a")
	ctx := egress.WithTargetHost(context.Background(), host)
	dial := func() string {
		t.Helper()
		c, err := p.Dial(ctx, "tcp", target.String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// The target answers whatever it answers (a 403, a 429): the pool
		// never sees it and the slot cannot move because of it.
		return c.(egress.EndpointConn).UpstreamEndpoint()
	}
	if got := dial(); got != "a" {
		t.Fatalf("first pick %s, want a", got)
	}
	// Later draws would pick b: the slot keeps a.
	pick = pickFor(p, host, "b")
	for range 5 {
		if got := dial(); got != "a" {
			t.Fatalf("the slot moved to %s without a proxy failure", got)
		}
	}
	// a goes down: the connection fails over to b and the slot moves.
	n.remove("10.0.0.1:1")
	if got := dial(); got != "b" {
		t.Fatalf("after a went down the connection went through %s, want b", got)
	}
	// a is back: the host stays on b.
	n.add("10.0.0.1:1", a.addr())
	pick = pickFor(p, host, "a")
	if got := dial(); got != "b" {
		t.Fatalf("the slot went back to %s once a recovered", got)
	}
}

func TestStickySlotStaysOnATargetsAnswerThroughTheProxy(t *testing.T) {
	target := echoServer(t)
	unreach := httpProxy(t, 502, "", "", "")
	other := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:1", unreach.addr())
	n.add("10.0.0.2:1", other.addr())
	eps := []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1)}
	var pick float64
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll, Endpoints: eps}, n,
		func(o *Options) { o.rand = func() float64 { return pick } })
	const host = "app.example"
	pick = pickFor(p, host, "a")
	ctx := egress.WithTargetHost(context.Background(), host)
	// Establish the slot on a.
	p.keepSlot(host, -1, 0)
	for range 3 {
		_, err := p.Dial(ctx, "tcp", target.String())
		if ue := upErr(t, err); ue.Class != egress.ClassTargetUnreachable || ue.Endpoint != "a" {
			t.Fatalf("error %+v, want target_unreachable through a", ue)
		}
	}
	if other.conns.Load() != 0 {
		t.Fatal("a target's answer was retried through another endpoint")
	}
	if p.slots[host] != 0 {
		t.Fatalf("slot moved to %d on a target's answer", p.slots[host])
	}
}

func TestMaxConnsBoundsOpenConnections(t *testing.T) {
	target := echoServer(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:1", tp.addr())
	e := ep("a", SchemeHTTP, "10.0.0.1", 1)
	e.MaxConns = 2
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll, Endpoints: []Endpoint{e}}, n)
	ctx := egress.WithTargetHost(context.Background(), "app.example")
	c1, err := p.Dial(ctx, "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	c2, err := p.Dial(ctx, "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	// Full: a third connection waits and fails when its caller gives up,
	// as the path's failure (proxy_down, final), and never reaches the proxy.
	before := tp.conns.Load()
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	_, err = p.Dial(tctx, "tcp", target.String())
	cancel()
	if !errors.Is(err, ErrEndpointBusy) {
		t.Fatalf("third connection: %v, want ErrEndpointBusy", err)
	}
	if ue := upErr(t, err); ue.Class != egress.ClassProxyDown || !ue.Final || !ue.PathFault() {
		t.Fatalf("third connection error %+v, want a final path fault", ue)
	}
	if tp.conns.Load() != before {
		t.Fatal("a connection over the limit reached the proxy")
	}
	// A waiting connection goes through as soon as one closes.
	done := make(chan error, 1)
	go func() {
		c, err := p.Dial(ctx, "tcp", target.String())
		if err == nil {
			_ = c.Close()
		}
		done <- err
	}()
	_ = c1.Close()
	if err := <-done; err != nil {
		t.Fatalf("waiting connection after one closed: %v", err)
	}
	// Closing twice frees one slot only.
	_ = c1.Close()
	if got := len(p.sem[0]); got != 1 {
		t.Fatalf("%d connections counted open, want 1", got)
	}
	_ = c2.Close()
	if got := len(p.sem[0]); got != 0 {
		t.Fatalf("%d connections counted open after all closed", got)
	}
}

func TestMaxConnsCountsFailedHandshakesBack(t *testing.T) {
	target := echoServer(t)
	n := newNetmap() // the endpoint is down
	e := ep("a", SchemeHTTP, "10.0.0.1", 1)
	e.MaxConns = 1
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll, Endpoints: []Endpoint{e}}, n)
	for range 2 {
		if _, err := p.Dial(egress.WithTargetHost(context.Background(), "x.example"), "tcp", target.String()); errors.Is(err, ErrEndpointBusy) {
			t.Fatal("a failed attempt kept its connection slot")
		}
	}
	if got := len(p.sem[0]); got != 0 {
		t.Fatalf("%d slots held after failed attempts", got)
	}
}

func TestFirstPickAvoidsAFullEndpoint(t *testing.T) {
	target := echoServer(t)
	a := httpProxy(t, 200, "", "", "")
	b := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:1", a.addr())
	n.add("10.0.0.2:1", b.addr())
	eps := []Endpoint{ep("a", SchemeHTTP, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1)}
	eps[0].MaxConns = 1
	var pick float64
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll, Endpoints: eps}, n,
		func(o *Options) { o.rand = func() float64 { return pick } })
	pick = pickFor(p, "one.example", "a")
	held, err := p.Dial(egress.WithTargetHost(context.Background(), "one.example"), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if held.(egress.EndpointConn).UpstreamEndpoint() != "a" {
		t.Fatal("setup: first host not on a")
	}
	// A new host would draw a, which is full: it starts on b.
	pick = 0
	c, err := p.Dial(egress.WithTargetHost(context.Background(), "two.example"), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.(egress.EndpointConn).UpstreamEndpoint(); got != "b" {
		t.Fatalf("new host started on %s, want b (a is full)", got)
	}
}

func TestMaxConnsValidation(t *testing.T) {
	for _, mc := range []int{-1, MaxEndpointConns + 1} {
		e := ep("a", SchemeHTTP, "10.0.0.1", 1)
		e.MaxConns = mc
		cfg := Config{Mode: ModePool, PoolID: "p", Endpoints: []Endpoint{e}}
		if err := cfg.Validate(nil); err == nil {
			t.Fatalf("max_conns %d accepted", mc)
		}
	}
}

func TestSOCKS5HSendsANameScopedTargetByName(t *testing.T) {
	target := echoServer(t)
	tp := socksProxy(t, 0, "", "")
	tp.resolve("app.example", target.String())
	n := newNetmap()
	n.add("10.0.0.1:1080", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeSOCKS5H, "10.0.0.1", 1080)}}, n)
	port := target.Port()
	// Scoped by name: the proxy gets the name and resolves it.
	ctx := egress.WithScopedName(egress.WithTargetHost(context.Background(), "app.example"))
	c, err := p.Dial(ctx, "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, c); got != "echo:ping\n" {
		t.Fatalf("got %q", got)
	}
	_ = c.Close()
	// Not scoped by name (an address target, or a vendor host): by address.
	c, err = p.Dial(egress.WithTargetHost(context.Background(), "app.example"), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_, dials := tp.seen()
	if len(dials) != 2 || dials[0] != fmt.Sprintf("app.example:%d", port) || dials[1] != target.String() {
		t.Fatalf("CONNECT targets %v, want the name then the address", dials)
	}
}

func TestSOCKS5WithoutHKeepsTheAddress(t *testing.T) {
	target := echoServer(t)
	tp := socksProxy(t, 0, "", "")
	n := newNetmap()
	n.add("10.0.0.1:1080", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeSOCKS5, "10.0.0.1", 1080)}}, n)
	ctx := egress.WithScopedName(egress.WithTargetHost(context.Background(), "app.example"))
	c, err := p.Dial(ctx, "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, dials := tp.seen(); len(dials) != 1 || dials[0] != target.String() {
		t.Fatalf("socks5 CONNECT %v, want the address", dials)
	}
}

func TestSOCKS5HByNameFailureIsFinal(t *testing.T) {
	target := echoServer(t)
	tp := socksProxy(t, 0, "", "") // knows no name: host unreachable
	n := newNetmap()
	n.add("10.0.0.1:1080", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeSOCKS5H, "10.0.0.1", 1080)}}, n)
	ctx := egress.WithScopedName(egress.WithTargetHost(context.Background(), "gone.example"))
	_, err := p.Dial(ctx, "tcp", target.String())
	ue := upErr(t, err)
	if ue.Class != egress.ClassTargetUnreachable || !ue.Final {
		t.Fatalf("error %+v, want a final target_unreachable (the name was asked for every address)", ue)
	}
}

func TestSOCKS5HInternalTargetOfAPublicPoolIsDialedDirect(t *testing.T) {
	target := echoServer(t) // loopback: not public
	tp := socksProxy(t, 0, "", "")
	n := newNetmap()
	n.add("10.0.0.1:1080", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesPublic,
		Endpoints: []Endpoint{ep("a", SchemeSOCKS5H, "10.0.0.1", 1080)}}, n)
	ctx := egress.WithScopedName(egress.WithTargetHost(context.Background(), "intranet.example"))
	c, err := p.Dial(ctx, "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if tp.conns.Load() != 0 {
		t.Fatal("a name whose checked address is internal went to the proxy by name")
	}
}

var _ net.Conn = (*conn)(nil)

func TestNameTooLongForSOCKSGoesByAddress(t *testing.T) {
	if validName(string(make([]byte, 0))) {
		t.Fatal("empty name valid")
	}
	long := ""
	for len(long) < 300 {
		long += "abcdefghij."
	}
	long += "example"
	target := netip.MustParseAddrPort("127.0.0.1:1")
	tp := socksProxy(t, 1, "", "")
	n := newNetmap()
	n.add("10.0.0.1:1080", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("a", SchemeSOCKS5H, "10.0.0.1", 1080)}}, n)
	_, _ = p.Dial(egress.WithScopedName(egress.WithTargetHost(context.Background(), long)), "tcp", target.String())
	if _, dials := tp.seen(); len(dials) != 1 || dials[0] != target.String() {
		t.Fatalf("CONNECT %v, want the address for a name over 255 bytes", dials)
	}
}
