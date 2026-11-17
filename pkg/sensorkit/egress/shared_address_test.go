package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// vhosts is one server that serves several names at one address, as a CDN
// edge or a shared host does: hostile.example.com answers every request
// with a vendor's challenge page, every other name with an ordinary page.
func vhosts(t *testing.T) (port int, served func(name string) int) {
	t.Helper()
	var mu sync.Mutex
	n := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, _, _ := strings.Cut(r.Host, ":")
		if name == "hostile.example.com" {
			w.Header().Set("Cf-Mitigated", "challenge")
			w.Header().Set("Retry-After", "300")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mu.Lock()
		n[name]++
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ = strconv.Atoi(u.Port())
	return port, func(name string) int {
		mu.Lock()
		defer mu.Unlock()
		return n[name]
	}
}

// proxyGet requests target through the forwarder at proxy on a connection
// of its own and returns the status.
func proxyGet(t *testing.T, proxy, target string) (int, error) {
	t.Helper()
	pu, _ := url.Parse("http://" + proxy)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}}
	resp, err := c.Get(target)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Body.Close()
}

// SECURITY: one name of a shared address cannot deny the other names of
// that address. hostile.example.com and victim.example.com are served at
// one address. One challenge page (with a long Retry-After) from the
// hostile name backs that name off; the healthy name still gets every
// request, in the same task and in the tenant's next task on the sensor,
// and is no coverage gap.
func TestChallengeOnOneNameLeavesTheOtherNamesOfItsAddress(t *testing.T) {
	port, served := vhosts(t)
	shared := adapt.NewSensorRate()
	const tenant = "tenant-a"
	task := func() (*Forwarder, string) {
		f, proxy := budgetForwarder(t, adapt.DefaultBudget(), "hostile.example.com", "victim.example.com")
		f.TargetRate().Share(shared, tenant)
		return f, proxy
	}
	at := func(name string) string { return "http://" + name + ":" + strconv.Itoa(port) + "/" }

	f, proxy := task()
	if status, err := proxyGet(t, proxy, at("hostile.example.com")); err != nil || status != http.StatusForbidden {
		t.Fatalf("the hostile name's first answer: %d %v", status, err)
	}
	for i := range 5 {
		if status, err := proxyGet(t, proxy, at("victim.example.com")); err != nil || status != http.StatusOK {
			t.Fatalf("request %d of the healthy name in the same task: status %d, %v", i+1, status, err)
		}
	}
	// The hostile name itself is backed off: the forwarder refuses it.
	if status, _ := proxyGet(t, proxy, at("hostile.example.com")); status != http.StatusServiceUnavailable {
		t.Fatalf("the challenged name was not refused by the forwarder: %d", status)
	}
	s := f.TargetRate().Summary()
	if s.GapsTotal != 1 || s.Gaps[0].Host != "hostile.example.com" || s.Gaps[0].Reason != adapt.GapBlocked {
		t.Fatalf("gaps %+v", s.Gaps)
	}
	if hs := statOf(s, "127.0.0.1"); hs == nil || !hs.Address || hs.CircuitOpens != 0 || hs.Backoffs == 0 {
		t.Fatalf("the address was not slowed, or its breaker opened: %+v", s.HostStats)
	}
	if until := shared.Cooldown(tenant, "127.0.0.1"); !until.IsZero() {
		t.Fatalf("a cooldown of the address started, until %v", until)
	}

	// The tenant's next task on the sensor.
	next, proxy2 := task()
	for i := range 5 {
		if status, err := proxyGet(t, proxy2, at("victim.example.com")); err != nil || status != http.StatusOK {
			t.Fatalf("request %d of the healthy name in the next task: status %d, %v", i+1, status, err)
		}
	}
	if got := served("victim.example.com"); got != 10 {
		t.Fatalf("the healthy name got %d of 10 requests", got)
	}
	if status, _ := proxyGet(t, proxy2, at("hostile.example.com")); status != http.StatusServiceUnavailable {
		t.Fatalf("the challenged name is not in its cooldown in the next task: %d", status)
	}
	if g, n := next.TargetRate().Gaps(); n != 1 || g[0].Host != "hostile.example.com" {
		t.Fatalf("gaps of the next task %+v", g)
	}
}

// slotForwarder is a forwarder whose hosts get slots connection slots, for
// names that are all pinned to 127.0.0.1.
func slotForwarder(t *testing.T, slots int, wait, idle time.Duration, names ...string) (*Forwarder, string) {
	t.Helper()
	scope := Scope{Names: map[string][]netip.Addr{}}
	for _, n := range names {
		scope.Names[n] = []netip.Addr{addr("127.0.0.1")}
	}
	f := New(scope, Limits{Rate: 1000, PerHostRate: 1000, PerHostConns: slots, DialTimeout: wait, SlotIdle: idle})
	return f, serve(t, f)
}

// keepAliveClient is a tool's HTTP client that keeps its connections to
// the forwarder's tunnels alive.
func keepAliveClient(proxy string) *http.Client {
	pu, _ := url.Parse("http://" + proxy)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a test server's certificate
}

func fetchOK(c *http.Client, target string) error {
	resp, err := c.Get(target)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

// Idle kept-alive tunnels of one name do not starve the other names of
// its address: a.example.com keeps as many HTTPS tunnels open and idle as
// the address has slots, and b.example.com, reached at the same address,
// still gets every request, with no coverage gap. The idle tunnels then
// carry further requests.
func TestIdleTunnelsOfOneNameDoNotStarveAnother(t *testing.T) {
	m := newMeter(t, true)
	m.delay = 150 * time.Millisecond // two requests at once open two tunnels
	f, proxy := slotForwarder(t, 2, 3*time.Second, 100*time.Millisecond, "a.example.com", "b.example.com")
	a := keepAliveClient(proxy)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fetchOK(a, m.url("a.example.com")); err != nil {
				t.Errorf("a: %v", err)
			}
		}()
	}
	wg.Wait()
	m.mu.Lock()
	conns := m.connsN
	m.mu.Unlock()
	if conns != 2 {
		t.Fatalf("a holds %d tunnels, want 2 (every slot of the address)", conns)
	}
	b := keepAliveClient(proxy)
	for i := range 3 {
		if err := fetchOK(b, m.url("b.example.com")); err != nil {
			t.Fatalf("request %d of b was refused behind a's idle tunnels: %v", i+1, err)
		}
	}
	// The idle tunnels of a still work: they take a slot again for a request.
	b.CloseIdleConnections()
	for i := range 2 {
		if err := fetchOK(a, m.url("a.example.com")); err != nil {
			t.Fatalf("request %d on a's kept-alive tunnel: %v", i+1, err)
		}
	}
	m.mu.Lock()
	after := m.connsN
	m.mu.Unlock()
	if after != 3 {
		t.Fatalf("the target saw %d connections, want 3 (a's two tunnels were reused, b opened one)", after)
	}
	if s := f.TargetRate().Summary(); s.GapsTotal != 0 {
		t.Fatalf("gaps %+v", s.Gaps)
	}
	if _, _, _, _, maxIn := m.counts(time.Time{}); maxIn > 2 {
		t.Fatalf("%d requests in flight at the address, 2 slots", maxIn)
	}
}

// A tunnel with a request in flight keeps its slot: giving slots back is
// for tunnels the host answered and that are quiet, never for one that
// waits for an answer, however long the host takes. (A kept-alive tunnel
// past its first request: there the host's bytes after a request are its
// answer.)
func TestTunnelWithARequestInFlightKeepsItsSlot(t *testing.T) {
	m := newMeter(t, true)
	m.delay = 1500 * time.Millisecond // the host takes its time over every answer
	f, proxy := slotForwarder(t, 1, 300*time.Millisecond, 50*time.Millisecond, "a.example.com")
	tool := keepAliveClient(proxy)
	if err := fetchOK(tool, m.url("a.example.com")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond) // the tunnel is idle: its slot is given back
	done := make(chan error, 1)
	go func() { done <- fetchOK(tool, m.url("a.example.com")) }()
	// Wait until the second request is in flight at the target.
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		in := m.inflight
		m.mu.Unlock()
		if in == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the request never reached the target")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // several idle checks pass while the host is silent
	if err := fetchOK(keepAliveClient(proxy), m.url("a.example.com")); err == nil {
		t.Fatal("a second connection got the slot of a tunnel whose request is in flight")
	}
	if err := <-done; err != nil {
		t.Fatalf("the request in flight: %v", err)
	}
	m.mu.Lock()
	conns := m.connsN
	m.mu.Unlock()
	if conns != 1 {
		t.Fatalf("the target saw %d connections, want the one kept-alive tunnel", conns)
	}
	if _, _, _, _, maxIn := m.counts(time.Time{}); maxIn != 1 {
		t.Fatalf("%d requests in flight, 1 slot", maxIn)
	}
	// The refused connection is a coverage gap of the host.
	g, n := f.TargetRate().Gaps()
	if n != 1 || g[0].Host != "a.example.com" || g[0].Reason != adapt.GapRateFloor || g[0].Detail != adapt.GapDetailHostBusy {
		t.Fatalf("gaps %+v", g)
	}
}

// A connection refused for lack of a slot is a coverage gap of the host it
// was for: the host's own slots, or the slots of the address it shares
// with another name. The name that holds the slot is no gap.
func TestConnectionRefusedForLackOfASlotIsACoverageGap(t *testing.T) {
	_, port := echoServer(t)
	t.Run("the host's own slots", func(t *testing.T) {
		f, _ := slotForwarder(t, 1, 100*time.Millisecond, -1, "a.example.com")
		c, _, err := f.dial(t.Context(), "connect", "a.example.com", port)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if g, n := f.TargetRate().Gaps(); n != 0 {
			t.Fatalf("gaps before any refusal: %+v", g)
		}
		if _, _, err := f.dial(t.Context(), "connect", "a.example.com", port); !errors.Is(err, ErrHostBusy) {
			t.Fatalf("second connection: %v", err)
		}
		g, n := f.TargetRate().Gaps()
		if n != 1 || g[0].Host != "a.example.com" || g[0].Reason != adapt.GapRateFloor || g[0].Detail != adapt.GapDetailHostBusy {
			t.Fatalf("gaps %+v", g)
		}
	})
	t.Run("the slots of a shared address", func(t *testing.T) {
		f, _ := slotForwarder(t, 1, 100*time.Millisecond, -1, "a.example.com", "b.example.com")
		c, _, err := f.dial(t.Context(), "connect", "a.example.com", port)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, _, err := f.dial(t.Context(), "connect", "b.example.com", port); !errors.Is(err, ErrHostBusy) {
			t.Fatalf("b beside a: %v", err)
		}
		g, n := f.TargetRate().Gaps()
		if n != 1 || g[0].Host != "b.example.com" || g[0].Reason != adapt.GapRateFloor {
			t.Fatalf("gaps %+v", g)
		}
	})
}

// The slots of one connection: given back while it is parked, taken again
// on resume (waiting like a new connection), and never given back twice.
func TestConnSlotsParkAndResume(t *testing.T) {
	f, _ := slotForwarder(t, 1, 100*time.Millisecond, -1, "a.example.com", "b.example.com")
	_, port := echoServer(t)
	c, _, err := f.dial(t.Context(), "connect", "a.example.com", port)
	if err != nil {
		t.Fatal(err)
	}
	sl := slotsOf(c)
	if sl == nil {
		t.Fatal("a tool's connection holds no slots")
	}
	sl.park(func() bool { return false })
	if _, _, err := f.dial(t.Context(), "connect", "b.example.com", port); !errors.Is(err, ErrHostBusy) {
		t.Fatalf("a connection that is not quiet gave its slots back: %v", err)
	}
	sl.park(nil)
	sl.park(nil)
	c2, _, err := f.dial(t.Context(), "connect", "b.example.com", port)
	if err != nil {
		t.Fatalf("b after a was parked: %v", err)
	}
	// The address's one slot is b's now: a cannot resume until b ends.
	if err := sl.resume(t.Context()); !errors.Is(err, ErrHostBusy) {
		t.Fatalf("resume beside b: %v", err)
	}
	_ = c2.Close()
	if err := sl.resume(t.Context()); err != nil {
		t.Fatalf("resume after b closed: %v", err)
	}
	if _, _, err := f.dial(t.Context(), "connect", "b.example.com", port); !errors.Is(err, ErrHostBusy) {
		t.Fatalf("a resumed connection holds no slot: %v", err)
	}
	_ = c.Close()
	_ = c.Close()
	if err := sl.resume(t.Context()); err != nil {
		t.Fatalf("resume of a closed connection: %v", err)
	}
	c3, _, err := f.dial(t.Context(), "connect", "b.example.com", port)
	if err != nil {
		t.Fatalf("a closed connection kept its slots: %v", err)
	}
	_ = c3.Close()
	// The canary's connection holds none.
	cc, err := f.DialTarget(t.Context(), "a.example.com", port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	if slotsOf(cc) != nil {
		t.Fatal("the canary's connection holds slots")
	}
	var nilSlots *connSlots
	nilSlots.park(nil)
	nilSlots.drop()
	if err := nilSlots.resume(context.Background()); err != nil {
		t.Fatal(err)
	}
}
