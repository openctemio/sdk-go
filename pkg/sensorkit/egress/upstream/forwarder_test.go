package upstream

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

// startForwarder serves a forwarder whose Dial is the pool.
func startForwarder(t *testing.T, scope egress.Scope, p *Pool) (*egress.Forwarder, string) {
	t.Helper()
	fw := egress.New(scope, egress.Limits{})
	fw.Dial = p.Dial
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = fw.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fw, ln.Addr().String()
}

func connectVia(t *testing.T, fwAddr, dest string) (net.Conn, *http.Response) {
	t.Helper()
	c, err := net.Dial("tcp", fwAddr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "CONNECT "+dest+" HTTP/1.1\r\nHost: "+dest+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, resp
}

func TestOutOfScopeTargetIsRefusedBeforeAnyUpstreamDial(t *testing.T) {
	target := echoServer(t)
	tp := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.5:3128", tp.addr())
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll,
		Endpoints: []Endpoint{ep("e1", SchemeHTTP, "10.0.0.5", 3128)}}, n)
	scope := egress.Scope{Prefixes: []netip.Prefix{netip.PrefixFrom(target.Addr(), 32)}, Ports: []int{int(target.Port())}}
	fw, addr := startForwarder(t, scope, p)

	for _, dest := range []string{"203.0.113.9:443", "169.254.169.254:80", "127.0.0.1:1"} {
		c, resp := connectVia(t, addr, dest)
		_ = c.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status %d", dest, resp.StatusCode)
		}
	}
	if tp.conns.Load() != 0 || n.total() != 0 {
		t.Fatalf("the proxy saw %d connections for refused targets", tp.conns.Load())
	}

	// In scope: through the proxy, recorded with the endpoint.
	c, resp := connectVia(t, addr, target.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_, _ = io.WriteString(c, "ping\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	_ = c.Close()
	if line != "echo:ping\n" {
		t.Fatalf("got %q", line)
	}
	if tp.conns.Load() != 1 {
		t.Fatalf("proxy connections %d", tp.conns.Load())
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		recs, _ := fw.Records()
		var found bool
		for _, r := range recs {
			if r.Verdict == egress.Allowed && r.Endpoint == "e1" {
				found = true
			}
			if strings.Contains(r.Reason, "s3cret") {
				t.Fatal("credential in a record")
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no record names the endpoint: %+v", recs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestForwarderPassesTheTargetHostAndStopsOnProxyFailure(t *testing.T) {
	n := newNetmap() // every endpoint down
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll, Endpoints: []Endpoint{
		ep("a", SchemeHTTP, "10.0.0.1", 1), ep("b", SchemeHTTP, "10.0.0.2", 1)}}, n)
	a1, a2 := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	scope := egress.Scope{Names: map[string][]netip.Addr{"app.example": {a1, a2}}}
	var hosts []string
	fw := egress.New(scope, egress.Limits{})
	fw.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		hosts = append(hosts, egress.TargetHost(ctx))
		return p.Dial(ctx, network, addr)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fw.Serve(ctx, ln) }()
	c, resp := connectVia(t, ln.Addr().String(), "APP.example.:443")
	_ = c.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("tunnel up with every endpoint down")
	}
	// One Dial (the second address is not tried after the pool gave up),
	// two endpoint attempts.
	if len(hosts) != 1 || hosts[0] != "app.example" {
		t.Fatalf("dials %v", hosts)
	}
	if n.total() != 2 {
		t.Fatalf("%d endpoint attempts", n.total())
	}
	if n.count("203.0.113.1:443")+n.count("203.0.113.2:443") != 0 {
		t.Fatal("target dialed directly")
	}
}

func TestForwarderCarriesAConnectionPastAProxyThatRefusesCredentials(t *testing.T) {
	target := echoServer(t)
	bad := httpProxy(t, 200, "alice", "right", "")
	good := httpProxy(t, 200, "", "", "")
	n := newNetmap()
	n.add("10.0.0.1:3128", bad.addr())
	n.add("10.0.0.2:3128", good.addr())
	a := ep("a", SchemeHTTP, "10.0.0.1", 3128)
	a.Username, a.Password = "alice", "wrong"
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", Strategy: StrategyPriority, AppliesTo: AppliesAll,
		Endpoints: []Endpoint{a, ep("b", SchemeHTTP, "10.0.0.2", 3128)}}, n)
	scope := egress.Scope{Prefixes: []netip.Prefix{netip.PrefixFrom(target.Addr(), 32)}, Ports: []int{int(target.Port())}}
	fw, addr := startForwarder(t, scope, p)
	c, resp := connectVia(t, addr, target.String())
	defer func() { _ = c.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: the connection was lost to a 407 on one endpoint", resp.StatusCode)
	}
	if _, total := fw.TargetRate().Gaps(); total != 0 {
		t.Fatalf("%d coverage gaps for a host that was carried", total)
	}
	if n.count(target.String()) != 0 {
		t.Fatal("target dialed directly")
	}
}

func TestForwarderMarksAGapWhenEveryProxyRefusesCredentials(t *testing.T) {
	target := echoServer(t)
	bad := httpProxy(t, 200, "alice", "right", "")
	n := newNetmap()
	n.add("10.0.0.1:3128", bad.addr())
	a := ep("a", SchemeHTTP, "10.0.0.1", 3128)
	a.Username, a.Password = "alice", "wrong"
	p := newTestPool(t, Config{Mode: ModePool, PoolID: "p", AppliesTo: AppliesAll, Endpoints: []Endpoint{a}}, n)
	scope := egress.Scope{Prefixes: []netip.Prefix{netip.PrefixFrom(target.Addr(), 32)}, Ports: []int{int(target.Port())}}
	fw, addr := startForwarder(t, scope, p)
	c, resp := connectVia(t, addr, target.String())
	_ = c.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("tunnel up with every endpoint refusing")
	}
	if _, total := fw.TargetRate().Gaps(); total != 1 {
		t.Fatalf("%d gaps, want 1", total)
	}
	if n.count(target.String()) != 0 {
		t.Fatal("target dialed directly")
	}
}
