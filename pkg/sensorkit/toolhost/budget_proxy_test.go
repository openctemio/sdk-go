package toolhost

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// loopbackPool is a job's proxy pool for a test: every connection the
// forwarder opens, to whatever address, reaches the local server at addr,
// and it counts the connections open at once.
type loopbackPool struct {
	addr string

	mu         sync.Mutex
	open, peak int
	total      int
}

func (p *loopbackPool) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.open++
	p.total++
	p.peak = max(p.peak, p.open)
	p.mu.Unlock()
	return &countedConn{Conn: c, p: p}, nil
}

func (p *loopbackPool) counts() (peak, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak, p.total
}

type countedConn struct {
	net.Conn
	p    *loopbackPool
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() {
		c.p.mu.Lock()
		c.p.open--
		c.p.mu.Unlock()
	})
	return c.Conn.Close()
}

// SECURITY: a tool of network egress-proxy that hammers one of its targets
// through its task forwarder gets no more than the budget there: the
// target never has more requests in flight, and the forwarder never more
// connections open to it, than the budget's in-flight bound, and the
// requests arrive at the budget's rate.
func TestEgressProxyToolIsHeldToTheBudgetOnTheWire(t *testing.T) {
	var mu sync.Mutex
	var inflight, maxIn int
	var arrivals atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrivals.Add(1)
		mu.Lock()
		inflight++
		maxIn = max(maxIn, inflight)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		inflight--
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pool := &loopbackPool{addr: srv.Listener.Addr().String()}

	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	m := tool.Manifest{Name: "proxied", Tier: tool.T1, Class: tool.TargetScan, Permissions: tool.Permissions{Network: tool.NetEgressProxy}}
	const name = "proxied-target.example.com"
	task := tool.Task{Targets: []tool.Target{{Ref: "t0", Type: "web_origin", Value: "http://" + name + ":" + port + "/"}}}
	confined := statusBackend{st: executor.Status{NetworkEnforced: true}}
	h := &Host{Backend: confined, TargetRates: adapt.NewSensorRate(),
		// The name's public address: the job's pool, not this address, is
		// what the connection reaches (loopbackPool).
		lookupVendor: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.114.10")}, nil
		}}
	p := &prepared{m: m, task: task, targetRate: 160, budget: budgetOf(m, task, RunOptions{HostBudget: &gentle}), egress: pool}
	if p.budget == nil {
		t.Fatal("an egress-proxy task has no budget")
	}
	eg, err := h.startEgress(context.Background(), confined, p)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.stop()
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		Proxy:               http.ProxyURL(&url.URL{Scheme: "http", Host: "forwarder"}),
		MaxIdleConnsPerHost: 16,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", eg.proxyPath())
		},
	}}
	const d = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+name+":"+port+"/", nil)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	client.CloseIdleConnections()
	peak, conns := pool.counts()
	mu.Lock()
	in := maxIn
	mu.Unlock()
	total := int(arrivals.Load())
	t.Logf("MEASURED egress-proxy tool, budget %d/s and %d in flight, 12 workers for %s: %d requests, %d in flight at most, %d connections (at most %d open at once)",
		gentle.RPS, gentle.Inflight, elapsed.Round(time.Millisecond), total, in, conns, peak)
	if total == 0 {
		t.Fatal("the target was never reached")
	}
	if in > gentle.Inflight || peak > gentle.Inflight {
		t.Fatalf("%d requests in flight and %d connections open at once at a target whose budget is %d", in, peak, gentle.Inflight)
	}
	if bound := float64(gentle.RPS)*elapsed.Seconds() + float64(gentle.RPS); float64(total) > bound {
		t.Fatalf("%d requests in %s: more than the budget of %d/s (bound %.0f)", total, elapsed, gentle.RPS, bound)
	}
}
