package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/openctemio/sdk-go/pkg/scopelimit"
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
// still gets every request, with no coverage gap: its connection closes
// the oldest idle tunnel of a and takes its slot. a's requests then still
// succeed (on its tunnel left open, or a new one), and the target never
// has more connections open than the address has slots.
func TestIdleTunnelsOfOneNameDoNotStarveAnother(t *testing.T) {
	m := newMeter(t, true)
	m.delay = 150 * time.Millisecond // two requests at once open two tunnels
	pool := &dialCounter{}
	f, proxy := slotForwarderDial(t, 2, 3*time.Second, 100*time.Millisecond, pool.dial, "a.example.com", "b.example.com")
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
	if _, total := pool.counts(); total != 2 {
		t.Fatalf("a holds %d tunnels, want 2 (every slot of the address)", total)
	}
	time.Sleep(300 * time.Millisecond) // a's tunnels are idle
	b := keepAliveClient(proxy)
	for i := range 3 {
		if err := fetchOK(b, m.url("b.example.com")); err != nil {
			t.Fatalf("request %d of b was refused behind a's idle tunnels: %v", i+1, err)
		}
	}
	b.CloseIdleConnections()
	for i := range 2 {
		if err := fetchOK(a, m.url("a.example.com")); err != nil {
			t.Fatalf("request %d of a after one of its tunnels was closed: %v", i+1, err)
		}
	}
	// b is never a gap. a's tunnels were closed after their first answer,
	// which the forwarder cannot tell from an answer cut short: a may be a
	// gap of the sensor's own bound (slots_full), never of anything else.
	g, _ := f.TargetRate().Gaps()
	for _, x := range g {
		if x.Host != "a.example.com" || x.Reason != adapt.GapSlotsFull {
			t.Fatalf("gaps %+v", g)
		}
	}
	if peak, _ := pool.counts(); peak > 2 {
		t.Fatalf("%d connections open at once at an address with 2 slots", peak)
	}
	if _, _, _, _, maxIn := m.counts(time.Time{}); maxIn > 2 {
		t.Fatalf("%d requests in flight at the address, 2 slots", maxIn)
	}
}

// A tunnel with a request in flight keeps its slot and is never closed for
// another connection: closing is for tunnels the host answered and that
// are quiet, never for one that waits for an answer, however long the
// host takes. The connection that waited is refused, and its host is a
// coverage gap of the sensor's own bound (slots_full), not of the host.
func TestTunnelWithARequestInFlightKeepsItsSlot(t *testing.T) {
	m := newMeter(t, true)
	m.delay = 1500 * time.Millisecond // the host takes its time over every answer
	f, proxy := slotForwarder(t, 1, 300*time.Millisecond, 50*time.Millisecond, "a.example.com")
	tool := keepAliveClient(proxy)
	if err := fetchOK(tool, m.url("a.example.com")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond) // the tunnel is idle
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
	g, n := f.TargetRate().Gaps()
	if n != 1 || g[0].Host != "a.example.com" || g[0].Reason != adapt.GapSlotsFull || g[0].Detail != adapt.GapDetailSlotsFull {
		t.Fatalf("gaps %+v", g)
	}
}

// A connection refused for lack of a slot is a coverage gap of the host it
// was for, with the reason of the sensor's own bound (slots_full): the
// host's own slots, or the slots of the address it shares with another
// name. The name that holds the slot is no gap, and no gap says the host
// pushed back.
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
		if n != 1 || g[0].Host != "a.example.com" || g[0].Reason != adapt.GapSlotsFull || g[0].Detail != adapt.GapDetailSlotsFull {
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
		if n != 1 || g[0].Host != "b.example.com" || g[0].Reason != adapt.GapSlotsFull {
			t.Fatalf("gaps %+v", g)
		}
	})
}

// The slots of one connection: held while it is open, idle ones closed
// for a connection that waits for them, a busy one never, and freed once.
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
		t.Fatalf("a connection that is not quiet was closed for another: %v", err)
	}
	sl.park(nil)
	sl.park(nil)
	if err := sl.resume(); err != nil {
		t.Fatalf("resume of an idle connection: %v", err)
	}
	if _, _, err := f.dial(t.Context(), "connect", "b.example.com", port); !errors.Is(err, ErrHostBusy) {
		t.Fatalf("a resumed connection was closed for another: %v", err)
	}
	sl.park(nil)
	c2, _, err := f.dial(t.Context(), "connect", "b.example.com", port)
	if err != nil {
		t.Fatalf("b beside a's idle connection: %v", err)
	}
	if !sl.wasEvicted() {
		t.Fatal("a's idle connection stayed open beside b: two connections on one slot")
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("the closed connection still writes")
	}
	if err := sl.resume(); !errors.Is(err, errSlotEvicted) {
		t.Fatalf("resume of a closed connection: %v", err)
	}
	_ = c.Close()
	_ = c.Close()
	// b holds the one slot: a closed connection freed it once.
	if _, _, err := f.dial(t.Context(), "connect", "a.example.com", port); !errors.Is(err, ErrHostBusy) {
		t.Fatalf("a closed connection freed its slot twice: %v", err)
	}
	_ = c2.Close()
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
	nilSlots.attach(nil)
	if err := nilSlots.resume(); err != nil || nilSlots.wasEvicted() {
		t.Fatal(err)
	}
}

// Two resumes of one connection at once (and a close for another
// connection racing them) leave it holding its slots once: closing it
// frees exactly its slots, never twice.
func TestConcurrentResumesHoldTheSlotsOnce(t *testing.T) {
	_, port := echoServer(t)
	f, _ := slotForwarder(t, 1, 50*time.Millisecond, -1, "a.example.com", "b.example.com")
	for i := range 200 {
		c, _, err := f.dial(t.Context(), "connect", "a.example.com", port)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		sl := slotsOf(c)
		sl.park(nil)
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() { defer wg.Done(); _ = sl.resume() }()
		}
		if i%2 == 1 {
			// A waiting connection may close it while it is idle.
			wg.Add(1)
			go func() {
				defer wg.Done()
				f.hostMu.Lock()
				v := f.evictLocked(sl.hostPool)
				f.hostMu.Unlock()
				v.close()
			}()
		}
		wg.Wait()
		_ = c.Close()
		f.hostMu.Lock()
		held := len(f.hostConns["a.example.com"].ch) + len(f.hostConns["127.0.0.1"].ch)
		f.hostMu.Unlock()
		if held != 0 {
			t.Fatalf("round %d: %d slot(s) still held after the connection closed", i, held)
		}
	}
}

// On a kept-alive connection the forwarder reads (a guarded destination),
// the connection holds its slot while open and is idle between requests:
// another name of its address closes it then and takes the slot. The tool
// sees its idle connection closed (no answer that reads as the host
// refusing it, no coverage gap), and its next connection works again.
func TestGuardedKeepAliveConnectionIsClosedForAnotherWhileIdle(t *testing.T) {
	s := &site{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	port := portOf(t, srv.URL)
	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}, "free.test": {addr("127.0.0.1")}},
		Limits: []scopelimit.Limit{{Host: "app.test", Ports: strconv.Itoa(port), PathPrefix: "/api/"}}},
		Limits{Rate: 1000, PerHostRate: 1000, PerHostConns: 1, DialTimeout: 300 * time.Millisecond})
	pa := serve(t, f)
	c, err := net.Dial("tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	status := func() (string, error) {
		t.Helper()
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return "", err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.Status, nil
	}
	connect := func() {
		t.Helper()
		fmt.Fprintf(c, "CONNECT app.test:%d HTTP/1.1\r\nHost: app.test\r\n\r\n", port)
		line, err := br.ReadString('\n')
		if err != nil || !strings.Contains(line, " 200 ") {
			t.Fatalf("CONNECT: %q %v", line, err)
		}
		for line != "\r\n" {
			if line, err = br.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
		}
	}
	request := func() (string, error) {
		t.Helper()
		fmt.Fprintf(c, "GET /api/a HTTP/1.1\r\nHost: app.test:%d\r\n\r\n", port)
		return status()
	}
	connect()
	if got, err := request(); err != nil || !strings.HasPrefix(got, "200") {
		t.Fatalf("first request: %s %v", got, err)
	}
	// The guarded connection is open and idle: another name takes the
	// address's one slot, closing it.
	other, _, err := f.dial(t.Context(), "connect", "free.test", port)
	if err != nil {
		t.Fatalf("another name behind an idle guarded connection: %v", err)
	}
	if got, err := request(); err == nil {
		t.Fatalf("the closed guarded connection answered %s", got)
	}
	if g, n := f.TargetRate().Gaps(); n != 0 {
		t.Fatalf("closing an idle connection made a gap: %+v", g)
	}
	_ = other.Close()
	// A new guarded connection works again, request after request.
	c2, err := net.Dial("tcp", pa)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	c, br = c2, bufio.NewReader(c2)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	connect()
	for i := range 3 {
		if got, err := request(); err != nil || !strings.HasPrefix(got, "200") {
			t.Fatalf("request %d on a kept-alive guarded connection: %s %v", i+1, got, err)
		}
	}
}

// dialCounter is a forwarder's Dial that counts the connections it opened
// to the target and how many were open at once.
type dialCounter struct {
	mu                sync.Mutex
	open, peak, total int
}

func (d *dialCounter) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.open++
	d.total++
	d.peak = max(d.peak, d.open)
	d.mu.Unlock()
	return &countedConn{Conn: c, d: d}, nil
}

func (d *dialCounter) counts() (peak, total int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.peak, d.total
}

type countedConn struct {
	net.Conn
	d    *dialCounter
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() {
		c.d.mu.Lock()
		c.d.open--
		c.d.mu.Unlock()
	})
	return c.Conn.Close()
}

// slotForwarderDial is slotForwarder with the forwarder's Dial set before
// it serves.
func slotForwarderDial(t *testing.T, slots int, wait, idle time.Duration, dial func(context.Context, string, string) (net.Conn, error), names ...string) (*Forwarder, string) {
	t.Helper()
	scope := Scope{Names: map[string][]netip.Addr{}}
	for _, n := range names {
		scope.Names[n] = []netip.Addr{addr("127.0.0.1")}
	}
	f := New(scope, Limits{Rate: 1000, PerHostRate: 1000, PerHostConns: slots, DialTimeout: wait, SlotIdle: idle})
	f.Dial = dial
	return f, serve(t, f)
}

// SECURITY: the connections open to a host never exceed its slots. Ten
// tools keep HTTPS tunnels alive to one host whose budget allows one
// connection, each sending a request now and then: the forwarder never has
// more than one connection open to the host (an idle tunnel is closed when
// another one needs the slot), every request is served, and no coverage
// gap is made.
func TestOpenConnectionsNeverExceedTheSlots(t *testing.T) {
	m := newMeter(t, true)
	pool := &dialCounter{}
	f, proxy := slotForwarderDial(t, 1, 5*time.Second, 50*time.Millisecond, pool.dial, "a.example.com")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []error
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := keepAliveClient(proxy)
			defer c.CloseIdleConnections()
			for range 4 {
				if err := fetchOK(c, m.url("a.example.com")); err != nil {
					mu.Lock()
					failed = append(failed, err)
					mu.Unlock()
				}
				time.Sleep(150 * time.Millisecond) // the tunnel goes idle, and stays open
			}
		}()
	}
	wg.Wait()
	peak, total := pool.counts()
	m.mu.Lock()
	served := len(m.served)
	m.mu.Unlock()
	t.Logf("MEASURED ten keep-alive tools, one slot: %d requests served, %d connections opened, at most %d open at once", served, total, peak)
	if peak > 1 {
		t.Fatalf("%d connections open at once to a host with one slot", peak)
	}
	if len(failed) != 0 {
		t.Fatalf("%d request(s) failed: %v", len(failed), failed[0])
	}
	if s := f.TargetRate().Summary(); s.GapsTotal != 0 {
		t.Fatalf("gaps %+v", s.Gaps)
	}
	// A waiting request is served once an idle connection is closed: a's
	// tunnel is idle, b's request takes its slot at once (well before the
	// wait for a slot ends).
	a, b := keepAliveClient(proxy), keepAliveClient(proxy)
	if err := fetchOK(a, m.url("a.example.com")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	if err := fetchOK(b, m.url("a.example.com")); err != nil {
		t.Fatalf("a request behind an idle connection: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the request waited %s behind an idle connection", d)
	}
	if peak, _ := pool.counts(); peak > 1 {
		t.Fatalf("%d connections open at once to a host with one slot", peak)
	}
}

// SECURITY: a name that answers slowly on a shared address cannot make
// coverage gaps that blame its neighbors. slow.example.com holds the
// address's one slot with a request in flight; the connection of
// other.example.com that finds no slot is refused with a gap of the
// sensor's own bound (slots_full), never one that says the host pushed back
// (rate_floor), and the slow name gets none.
func TestSlowNameOnASharedAddressBlamesNoNeighbor(t *testing.T) {
	inflight := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "slow.example.com") {
			inflight <- struct{}{}
			time.Sleep(time.Second)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)
	f, proxy := slotForwarder(t, 1, 200*time.Millisecond, 50*time.Millisecond, "slow.example.com", "other.example.com")
	at := func(name string) string { return "http://" + name + ":" + strconv.Itoa(port) + "/" }
	done := make(chan error, 1)
	go func() {
		status, err := proxyGet(t, proxy, at("slow.example.com"))
		if err == nil && status != http.StatusOK {
			err = fmt.Errorf("status %d", status)
		}
		done <- err
	}()
	<-inflight
	if status, err := proxyGet(t, proxy, at("other.example.com")); err == nil && status == http.StatusOK {
		t.Fatal("other.example.com got the slot of a request in flight")
	}
	if err := <-done; err != nil {
		t.Fatalf("the slow name's request: %v", err)
	}
	g, n := f.TargetRate().Gaps()
	if n != 1 || g[0].Host != "other.example.com" || g[0].Reason != adapt.GapSlotsFull {
		t.Fatalf("gaps %+v", g)
	}
	for _, x := range g {
		if x.Reason == adapt.GapRateFloor {
			t.Fatalf("a slot refusal reads as the host pushing back: %+v", x)
		}
	}
}

// An answer that pauses after its first bytes, on a tunnel's first request,
// looks idle to the forwarder, and a connection that waits for the slot
// closes the tunnel: the tool sees the answer cut short. The forwarder could
// not tell, so the host is a coverage gap of the sensor's own bound
// (slots_full): the cut answer is never read as a host fully scanned.
func TestCutAnswerOnAnUnsureTunnelLeavesAGap(t *testing.T) {
	firstBytes := make(chan struct{})
	var once sync.Once
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.Header().Set("Content-Length", "10")
		_, _ = io.WriteString(w, "01234")
		w.(http.Flusher).Flush()
		once.Do(func() { close(firstBytes) })
		select {
		case <-time.After(800 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "56789")
	}))
	t.Cleanup(srv.Close)
	su, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := func(path string) string { return "https://a.example.com:" + su.Port() + path }
	// 1 slot; a tunnel quiet for 5 x 40ms on its first request counts as idle.
	f, proxy := slotForwarder(t, 1, 3*time.Second, 40*time.Millisecond, "a.example.com")

	cut := make(chan error, 1)
	go func() {
		resp, err := keepAliveClient(proxy).Get(target("/slow"))
		if err != nil {
			cut <- err
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body) // fetchOK ignores a body cut short
		cut <- err
	}()
	select { // the slow answer's first bytes are on their way, the tunnel holds the slot
	case <-firstBytes:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow request never reached the server")
	}
	time.Sleep(20 * time.Millisecond)
	if err := fetchOK(keepAliveClient(proxy), target("/fast")); err != nil {
		t.Fatalf("the waiting connection: %v", err)
	}
	if err := <-cut; err == nil {
		t.Fatal("the slow answer arrived whole: the tunnel was not closed for the waiting connection")
	}
	g, n := f.TargetRate().Gaps()
	if n != 1 || g[0].Host != "a.example.com" || g[0].Reason != adapt.GapSlotsFull || g[0].Detail != adapt.GapDetailSlotsFull {
		t.Fatalf("a cut answer left gaps %+v (%d), want one slots_full gap on a.example.com", g, n)
	}
}
