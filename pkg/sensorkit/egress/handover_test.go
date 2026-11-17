package egress

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// poolCounts sums the state of every slot pool of f: connections waiting,
// pending unsure tunnels, idle connections and connections being closed.
func poolCounts(f *Forwarder) (waiters, pending, idle, closing int) {
	f.hostMu.Lock()
	defer f.hostMu.Unlock()
	for _, p := range f.hostConns {
		waiters += p.waiters
		pending += p.pending
		idle += len(p.idle)
		closing += p.closing
	}
	return waiters, pending, idle, closing
}

// h2OfferingClient is a tool's HTTP client whose TLS hello offers HTTP/2
// (as Go's default transport, Chrome and most scan tools do), through the
// forwarder at proxy.
func h2OfferingClient(proxy string) *http.Client {
	pu, _ := url.Parse("http://" + proxy)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a test server's certificate
}

// A connection whose client leaves while it waits for its slot stops
// waiting at once: it closes no other connection for the slot (the unsure
// tunnel that holds it stays open and keeps working), opens no connection
// to the target and makes no coverage gap. Tools give up on a connection
// they waited too long for, and drop one they dialed ahead once a
// kept-alive connection came free.
func TestWaiterWhoseClientLeftStopsWaiting(t *testing.T) {
	m := newMeter(t, true)
	pool := &dialCounter{}
	const unsure = 600 * time.Millisecond
	f, proxy := slotForwarderUnsure(t, 1, 300*time.Millisecond, 40*time.Millisecond, unsure, pool.dial, "a.example.com", "b.example.com")
	a := keepAliveClient(proxy)
	defer a.CloseIdleConnections()
	if err := fetchOK(a, m.url("a.example.com")); err != nil {
		t.Fatal(err)
	}
	// a's tunnel holds the address's slot: one request carried, quiet and
	// unsure. b's client asks for a tunnel, waits, and leaves.
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(c, "CONNECT b.example.com:%d HTTP/1.1\r\nHost: b.example.com:%d\r\n\r\n", m.port(), m.port()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for w, _, _, _ := poolCounts(f); w == 0; w, _, _, _ = poolCounts(f) {
		if time.Now().After(deadline) {
			t.Fatal("b's connection never waited for a slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	_ = c.Close()
	left := time.Now()
	for w, _, _, _ := poolCounts(f); w != 0; w, _, _, _ = poolCounts(f) {
		if time.Since(left) > 250*time.Millisecond {
			t.Fatalf("the connection kept waiting %s after its client left", time.Since(left))
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("MEASURED the wait ended %s after the client left", time.Since(left))
	// Long past the time a's unsure tunnel needs to count as idle: nothing
	// closed it, and nothing dialed the target for b.
	time.Sleep(unsure + 300*time.Millisecond)
	if _, total := pool.counts(); total != 1 {
		t.Fatalf("the target saw %d connections, want a's one tunnel only", total)
	}
	if err := fetchOK(a, m.url("a.example.com")); err != nil {
		t.Fatalf("a's tunnel after b's client left: %v", err)
	}
	if peak, total := pool.counts(); peak != 1 || total != 1 {
		t.Fatalf("peak %d, total %d: a's tunnel was closed for a connection nobody waited for", peak, total)
	}
	if s := f.TargetRate().Summary(); s.GapsTotal != 0 {
		t.Fatalf("a client that left made gaps %+v", s.Gaps)
	}
	var found bool
	recs, _ := f.Records()
	for _, r := range recs {
		if r.Host == "b.example.com" {
			found = true
			if r.Verdict != Refused || !strings.Contains(r.Reason, "client left") {
				t.Fatalf("b's record %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("b's connection was not recorded")
	}
	if w, p, _, cl := poolCounts(f); w != 0 || p > 1 || cl != 0 {
		t.Fatalf("pools: waiters %d, pending %d, closing %d", w, p, cl)
	}
}

// The same over SOCKS5: the client sends its request and leaves before the
// reply.
func TestSOCKSWaiterWhoseClientLeftStopsWaiting(t *testing.T) {
	_, port := echoServer(t)
	pool := &dialCounter{}
	f, proxy := slotForwarderUnsure(t, 1, 300*time.Millisecond, 40*time.Millisecond, 600*time.Millisecond, pool.dial, "a.example.com", "b.example.com")
	held, _, err := f.dial(t.Context(), "connect", "a.example.com", port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	name := "b.example.com"
	req := append([]byte{socksVersion, 1, 0x00, socksVersion, socksConnect, 0x00, atypDomain, byte(len(name))}, name...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for w, _, _, _ := poolCounts(f); w == 0; w, _, _, _ = poolCounts(f) {
		if time.Now().After(deadline) {
			t.Fatal("b's connection never waited for a slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = c.Close()
	left := time.Now()
	for w, _, _, _ := poolCounts(f); w != 0; w, _, _, _ = poolCounts(f) {
		if time.Since(left) > 250*time.Millisecond {
			t.Fatalf("the connection kept waiting %s after its client left", time.Since(left))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, total := pool.counts(); total != 1 {
		t.Fatalf("the target saw %d connections, want the held one only", total)
	}
	if s := f.TargetRate().Summary(); s.GapsTotal != 0 {
		t.Fatalf("a client that left made gaps %+v", s.Gaps)
	}
}

// Ordinary keep-alive reuse by a client that offers HTTP/2 to a server
// that answers over HTTP/1.1 (Go's default transport, Chrome and most scan
// tools offer it) makes no coverage gap: three requests on one tunnel, the
// host answered each, and the tunnel is closed, once quiet for
// answeredSlotIdle times SlotIdle (well before the unsure time), for a
// connection to another name of its address. The waiting connection is
// served, the connections open never exceed the one slot.
func TestHTTP2OfferingClientReuseLeavesNoGap(t *testing.T) {
	m := newMeter(t, true) // HTTP/1.1 only
	pool := &dialCounter{}
	const unsure = 600 * time.Millisecond
	f, proxy := slotForwarderUnsure(t, 1, 300*time.Millisecond, 40*time.Millisecond, unsure, pool.dial, "a.example.com", "b.example.com")
	a := h2OfferingClient(proxy)
	defer a.CloseIdleConnections()
	for i := range 3 {
		if err := fetchOK(a, m.url("a.example.com")); err != nil {
			t.Fatalf("request %d of a: %v", i+1, err)
		}
	}
	if _, total := pool.counts(); total != 1 {
		t.Fatalf("a opened %d tunnels, want one reused", total)
	}
	quietFrom := time.Now()
	b := keepAliveClient(proxy)
	defer b.CloseIdleConnections()
	if err := fetchOK(b, m.url("b.example.com")); err != nil {
		t.Fatalf("b behind a's quiet tunnel: %v", err)
	}
	waited := time.Since(quietFrom)
	t.Logf("MEASURED b served %s after a's tunnel went quiet (unsure idle %s, answered %s)", waited, unsure, answeredSlotIdle*40*time.Millisecond)
	if waited >= unsure {
		t.Fatalf("b waited %s: a tunnel the host had answered on was held as long as an unanswered one (%s)", waited, unsure)
	}
	if peak, total := pool.counts(); peak != 1 || total != 2 {
		t.Fatalf("peak %d, total %d; want at most 1 open, 2 opened", peak, total)
	}
	if s := f.TargetRate().Summary(); s.GapsTotal != 0 {
		t.Fatalf("keep-alive reuse by a client that offers HTTP/2 made gaps %+v", s.Gaps)
	}
}

// An HTTP/2-offering client's tunnel whose only request is still
// outstanding when it is closed for a waiter (its answer paused after its
// first bytes, which may as well have been the end of the TLS handshake)
// still leaves one slots_full gap.
func TestHTTP2OfferingTunnelCutWithARequestOutstandingLeavesAGap(t *testing.T) {
	srv, firstBytes := pausingServer(t)
	su, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := func(name, path string) string { return "https://" + name + ":" + su.Port() + path }
	const unsure = 600 * time.Millisecond
	f, proxy := slotForwarderUnsure(t, 1, 200*time.Millisecond, 40*time.Millisecond, unsure, nil, "a.example.com", "b.example.com")
	cut := make(chan error, 1)
	go func() {
		resp, err := h2OfferingClient(proxy).Get(target("a.example.com", "/slow"))
		if err != nil {
			cut <- err
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body) // a body cut short is an error
		cut <- err
	}()
	select {
	case <-firstBytes:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow request never reached the server")
	}
	time.Sleep(20 * time.Millisecond)
	if err := fetchOK(keepAliveClient(proxy), target("b.example.com", "/fast")); err != nil {
		t.Fatalf("the waiting connection: %v", err)
	}
	if err := <-cut; err == nil {
		t.Fatal("the slow answer arrived whole: the tunnel was not closed for the waiting connection")
	}
	g, n := f.TargetRate().Gaps()
	if n != 1 || g[0].Host != "a.example.com" {
		t.Fatalf("gaps %+v (%d), want one slots_full gap on a.example.com", g, n)
	}
}

// pausingServer answers /slow with 5 bytes of a 10-byte body, then pauses
// 3 s; firstBytes is closed once the first bytes were sent.
func pausingServer(t *testing.T) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	firstBytes := make(chan struct{})
	var once sync.Once
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.Header().Set("Content-Length", "10")
		_, _ = w.Write([]byte("01234"))
		w.(http.Flusher).Flush()
		once.Do(func() { close(firstBytes) })
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte("56789"))
	}))
	t.Cleanup(srv.Close)
	return srv, firstBytes
}

// SECURITY (no slot lost, none exceeded): a connection closed for a waiter
// always serves that waiter, also when the waiter's wait ends while the
// closed connection is still freeing its slot; and once a waiter has been
// refused, no connection is closed for it. The waiter's timer races the
// close, many times over: either the held connection was closed and the
// waiter got its slot, or it was not and the waiter was refused.
func TestEvictionForAWaiterIsNeverWasted(t *testing.T) {
	_, port := echoServer(t)
	const wait = 30 * time.Millisecond
	f, _ := slotForwarder(t, 1, wait, 10*time.Millisecond, "a.example.com")
	var served, refused int
	for i := range 200 {
		held, _, err := f.dial(t.Context(), "connect", "a.example.com", port)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		sl := slotsOf(held)
		type result struct {
			c   net.Conn
			err error
		}
		got := make(chan result, 1)
		go func() {
			c, _, err := f.dial(t.Context(), "connect", "a.example.com", port)
			got <- result{c, err}
		}()
		// The held connection goes idle around the time the waiter's wait
		// ends: closed for the waiter while it still waits.
		time.Sleep(wait - 5*time.Millisecond + time.Duration(rand.IntN(10000))*time.Microsecond)
		sl.park(nil)
		r := <-got
		evicted := sl.wasEvicted()
		switch {
		case evicted && r.err != nil:
			t.Fatalf("round %d: the held connection was closed for the waiter, and the waiter was refused: %v", i, r.err)
		case !evicted && !errors.Is(r.err, ErrHostBusy):
			t.Fatalf("round %d: the slot stayed held, and the waiter got %v", i, r.err)
		case evicted:
			served++
			_ = r.c.Close()
		default:
			refused++
		}
		_ = held.Close()
		if w, p, idle, cl := poolCounts(f); w != 0 || p != 0 || idle != 0 || cl != 0 {
			t.Fatalf("round %d: pools waiters %d, pending %d, idle %d, closing %d", i, w, p, idle, cl)
		}
	}
	t.Logf("MEASURED 200 rounds: %d waiters served by a closed connection, %d refused with the slot still held", served, refused)
}

// When the forwarder can tell that the host's bytes after the client's
// last request were an answer (answerSeen), and how long the tunnel must
// then be quiet to count as idle: on a TLS tunnel's first request it
// cannot (a TLS 1.3 session ticket may follow it), so the tunnel stays
// unsure; once a further request followed the host's bytes it can, also
// for a client that offered HTTP/2 (which then counts as idle after
// answeredSlotIdle times SlotIdle, not after the unsure time); a tunnel
// that is not TLS has no tickets.
func TestTunnelMeterAnswerSeen(t *testing.T) {
	f := New(Scope{}, Limits{SlotIdle: 40 * time.Millisecond})
	f.unsureIdle = time.Second
	h2hello := append([]byte{recHandshake, 0x03, 0x01, 0, 64}, bytes.Repeat([]byte{0x11}, 64)...)
	copy(h2hello[5+20:], []byte{0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	for _, tc := range []struct {
		name  string
		hello []byte
		turn  time.Duration // idle time once the host answered and the client asked again
	}{
		{"offers HTTP/2", h2hello, answeredSlotIdle * 40 * time.Millisecond},
		{"HTTP/1.1 only", record(recHandshake, 200), 40 * time.Millisecond},
	} {
		m, _, _ := meterFor(t)
		for _, r := range [][]byte{tc.hello, record(recChangeCipherSpec, 1), record(recApplicationData, 53), record(recApplicationData, 300)} {
			if _, err := m.Write(r); err != nil {
				t.Fatal(err)
			}
		}
		m.hostSpoke.Store(true) // a session ticket, or the start of the answer
		if m.answerSeen() || f.slotIdleFor(m) != time.Second {
			t.Fatalf("%s, first request: answer seen %t, idle after %s", tc.name, m.answerSeen(), f.slotIdleFor(m))
		}
		if _, err := m.Write(record(recApplicationData, 300)); err != nil { // a further request
			t.Fatal(err)
		}
		if !m.answerSeen() || f.slotIdleFor(m) != tc.turn {
			t.Fatalf("%s, after a turn: answer seen %t, idle after %s, want %s", tc.name, m.answerSeen(), f.slotIdleFor(m), tc.turn)
		}
	}
	raw, _, _ := meterFor(t)
	if _, err := raw.Write([]byte("GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if !raw.answerSeen() {
		t.Fatal("a tunnel that is not TLS: its host's bytes after the request are its answer")
	}
}
