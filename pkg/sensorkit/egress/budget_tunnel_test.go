package egress

// The budget on tunnels the forwarder passes through unread (ordinary
// HTTPS), on the names of one address, and for the canary: measured on the
// target's side against servers in this process on loopback addresses.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// Client modes of hammerMode.
const (
	modeKeepAlive = "keep-alive" // HTTP/1.1, connections reused
	modeHTTP2     = "http2"      // one multiplexed connection for all workers
)

// hammerMode is hammer with connection reuse: workers clients that request
// target through the forwarder as fast as they are let, on kept-alive
// HTTP/1.1 connections or as streams of one HTTP/2 connection.
func hammerMode(ctx context.Context, wg *sync.WaitGroup, proxyAddr, target string, workers int, mode string) {
	pu, _ := url.Parse("http://" + proxyAddr)
	transport := func() *http.Transport {
		return &http.Transport{Proxy: http.ProxyURL(pu), ForceAttemptHTTP2: mode == modeHTTP2, MaxIdleConnsPerHost: workers,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // a test server's certificate
	}
	shared := transport()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := shared
			if mode == modeKeepAlive {
				tr = transport()
			}
			c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			for ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				resp, err := c.Do(req)
				if err != nil {
					select {
					case <-ctx.Done():
					case <-time.After(10 * time.Millisecond):
					}
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}
}

// tunnels is how many connections the target accepted, and the bytes the
// tool sent on the tunnels that ended.
func tunnels(f *Forwarder, m *meter) (n int, bytesOut int64) {
	recs, _ := f.Records()
	for _, r := range recs {
		if r.Protocol == "connect" && r.Verdict == Allowed {
			bytesOut += r.BytesOut
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connsN, bytesOut
}

// SECURITY: HTTPS passed through, with connections kept alive: a tool that
// sends request after request on one tunnel gets no more than the budget.
// Every further request on a tunnel waits for the host's rate, so what the
// target counts is within rate x time plus the one token a bucket holds,
// and the requests in flight are within the budget's connections. Before,
// a tunnel took one token and then carried any number of requests.
func TestKeepAliveTunnelsStayUnderTheBudget(t *testing.T) {
	b := adapt.DefaultBudget()
	m := newMeterAt(t, true, "127.0.0.1", true)
	m.delay = 2 * time.Millisecond
	f, proxy := budgetForwarder(t, b, "a.example.com")
	const d = 8 * time.Second
	start := time.Now()
	run(t, d, func(ctx context.Context, wg *sync.WaitGroup) {
		hammerMode(ctx, wg, proxy, m.url("a.example.com"), 32, modeKeepAlive)
	})
	total, peak, recent, _, maxIn := m.counts(start.Add(6 * time.Second))
	conns, _ := tunnels(f, m)
	t.Logf("MEASURED HTTPS keep-alive (HTTP/1.1), budget %d/s and %d in flight, 32 workers as fast as they can: %d requests in %s over %d tunnels (bound %d = rate x time + 1), peak %d in any one second, %d in the last 2 s, %d in flight at most",
		b.RPS, b.Inflight, total, d, conns, b.RPS*int(d.Seconds())+1, peak, recent, maxIn)
	if overTotal(total, b.RPS, d) || overBudget(peak, b.RPS) {
		t.Fatalf("%d requests in %s, peak %d/s: more than the budget of %d/s", total, d, peak, b.RPS)
	}
	if maxIn > b.Inflight {
		t.Fatalf("%d requests in flight, budget %d", maxIn, b.Inflight)
	}
	// The connections were reused: this is the case under test.
	if conns == 0 || total < 4*conns {
		t.Fatalf("%d requests over %d tunnels: the client did not keep its connections alive", total, conns)
	}
	// It does reach the budget.
	if recent < b.RPS*2*7/10 {
		t.Fatalf("only %d requests in the last 2 s: the host never reached its budget of %d/s", recent, b.RPS)
	}
	if s := f.TargetRate().Summary(); s.Backoffs != 0 || s.CircuitOpens != 0 || s.GapsTotal != 0 {
		t.Fatalf("summary %+v", s)
	}
}

// HTTP/2 on a tunnel: many streams on one connection. The client offers
// HTTP/2 in its hello, so the forwarder counts every record it sends: a
// client that writes each request in a record of its own (Go's, used here
// and by the scan tools) is held to the budget's rate although the
// forwarder never reads a request, for a target that answers at once and
// for one that answers slowly (where streams pile up between two answers).
// Streams in flight are not bounded by the connection slots: one
// connection carries many.
func TestHTTP2TunnelStaysUnderTheBudgetRate(t *testing.T) {
	b := adapt.DefaultBudget()
	for _, delay := range []time.Duration{2 * time.Millisecond, 300 * time.Millisecond} {
		t.Run("target answers in "+delay.String(), func(t *testing.T) {
			m := newMeterAt(t, true, "127.0.0.1", true)
			m.delay = delay
			f, proxy := budgetForwarder(t, b, "a.example.com")
			const d = 6 * time.Second
			run(t, d, func(ctx context.Context, wg *sync.WaitGroup) {
				hammerMode(ctx, wg, proxy, m.url("a.example.com"), 32, modeHTTP2)
			})
			total, peak, _, _, maxIn := m.counts(time.Time{})
			conns, out := tunnels(f, m)
			m.mu.Lock()
			h2 := m.h2N
			m.mu.Unlock()
			t.Logf("MEASURED HTTP/2 on kept-alive tunnels, budget %d/s, 32 streams as fast as they can, target answers in %s: %d requests in %s (%d over HTTP/2; bound %d = rate x time + 1), peak %d in any one second, %d streams in flight at most, %d connection(s), %d client bytes",
				b.RPS, delay, total, d, h2, b.RPS*int(d.Seconds())+1, peak, maxIn, conns, out)
			if h2 == 0 {
				t.Fatal("no request arrived over HTTP/2: the case under test did not run")
			}
			if overTotal(total, b.RPS, d) || overBudget(peak, b.RPS) {
				t.Fatalf("%d requests in %s, peak %d/s: more than the budget of %d/s over HTTP/2", total, d, peak, b.RPS)
			}
		})
	}
}

// SECURITY: six names of one server get one server's budget. Each name has
// its own state, and all of them share the state of the address they are
// dialed at: what the target counts, over all six names, is within one
// budget, in rate and in flight.
func TestNamesOfOneAddressShareItsBudget(t *testing.T) {
	b := adapt.DefaultBudget()
	m := newMeter(t, true)
	m.delay = 30 * time.Millisecond
	names := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com"}
	f, proxy := budgetForwarder(t, b, names...)
	const d = 6 * time.Second
	run(t, d, func(ctx context.Context, wg *sync.WaitGroup) {
		for _, n := range names {
			hammer(ctx, wg, proxy, m.url(n), 8)
		}
	})
	total, peak, _, _, maxIn := m.counts(time.Time{})
	t.Logf("MEASURED six names of one address, budget %d/s and %d in flight, 8 workers per name: %d requests in %s (bound %d = rate x time + 1; six budgets would be %d), peak %d in any one second, %d in flight at most",
		b.RPS, b.Inflight, total, d, b.RPS*int(d.Seconds())+1, 6*b.RPS*int(d.Seconds()), peak, maxIn)
	if overTotal(total, b.RPS, d) || overBudget(peak, b.RPS) {
		t.Fatalf("%d requests in %s, peak %d/s: the address got more than one budget of %d/s", total, d, peak, b.RPS)
	}
	if maxIn > b.Inflight {
		t.Fatalf("%d requests in flight at the address, budget %d", maxIn, b.Inflight)
	}
	s := f.TargetRate().Summary()
	if s.Hosts != len(names) || s.GapsTotal != 0 {
		t.Fatalf("summary %+v", s)
	}
}

// Every spelling of one host is one key in the forwarder: the connection
// slots (and the rate, and the breaker) of a host are shared by its
// spellings.
func TestAliasFormsShareOneBudgetKey(t *testing.T) {
	for _, forms := range [][]string{
		{"127.0.0.1", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]", "0x7f000001", "2130706433", "0177.0.0.1", "127.1"},
		{"2001:db8::1", "[2001:DB8::1]", "2001:db8:0:0:0:0:0:1", "2001:0db8::0001"},
		{"bücher.example", "BÜCHER.example.", "xn--bcher-kva.example", "XN--BCHER-KVA.EXAMPLE"},
		{"a.example.com", "A.Example.Com."},
	} {
		for _, f := range forms[1:] {
			if hostKey(f) != hostKey(forms[0]) {
				t.Errorf("hostKey(%q) = %q, hostKey(%q) = %q", f, hostKey(f), forms[0], hostKey(forms[0]))
			}
		}
	}
	// On the wire: two spellings of one name, pinned to two addresses so
	// that only the name's key can be what they share, and two spellings of
	// one address.
	_, port := echoServer(t)
	ln2, err := net.Listen("tcp", "127.0.0.2:"+strconv.Itoa(port))
	if err != nil {
		t.Skipf("no second loopback listener: %v", err)
	}
	t.Cleanup(func() { _ = ln2.Close() })
	scope := Scope{
		Names:    map[string][]netip.Addr{"bücher.example": {addr("127.0.0.1")}, "xn--bcher-kva.example": {addr("127.0.0.2")}},
		Prefixes: []netip.Prefix{pfx("127.0.0.1/32")},
	}
	f := New(scope, Limits{Rate: 1000, PerHostRate: 1000, PerHostConns: 1, DialTimeout: 200 * time.Millisecond})
	for _, pair := range [][2]string{{"bücher.example", "xn--bcher-kva.example"}, {"127.0.0.1", "::ffff:127.0.0.1"}} {
		c, _, err := f.dial(t.Context(), "connect", pair[0], port)
		if err != nil {
			t.Fatalf("%s: %v", pair[0], err)
		}
		if _, _, err := f.dial(t.Context(), "connect", pair[1], port); !errors.Is(err, ErrHostBusy) {
			t.Fatalf("%s got a slot of its own beside %s: %v", pair[1], pair[0], err)
		}
		_ = c.Close()
		c2, _, err := f.dial(t.Context(), "connect", pair[1], port)
		if err != nil {
			t.Fatalf("%s after %s closed: %v", pair[1], pair[0], err)
		}
		_ = c2.Close()
	}
}

// The canary and the forwarder count a host under one key: push-back on
// the canary's request to a target written as an internationalized name, as
// an IPv6 address in a long form or as a hexadecimal IPv4 address slows the
// tool's connections to that host, whichever spelling the tool uses.
func TestCanaryPushbackOnAnAliasFormSlowsTheToolsConnections(t *testing.T) {
	cases := []struct {
		name string
		// listen is the address the target listens on, canaryHost the host
		// in the job's target as written, toolHost the host the tool
		// connects to.
		listen, canaryHost, toolHost string
	}{
		{"an internationalized name", "127.0.0.1", "bücher.example", "xn--bcher-kva.example"},
		{"an IPv6 address in a long form", "::1", "[0:0:0:0:0:0:0:1]", "[::1]"},
		{"a hexadecimal IPv4 address", "127.0.0.1", "0x7f000001", "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			quick(t)
			m := newMeterAt(t, false, tc.listen, false)
			m.canaryOnly.Store(true)
			port := m.port()
			target := "http://" + tc.canaryHost + ":" + strconv.Itoa(port) + "/"
			scope := Scope{Names: map[string][]netip.Addr{}, Prefixes: []netip.Prefix{netip.PrefixFrom(addr(tc.listen), addr(tc.listen).BitLen())}}
			for _, h := range []string{tc.canaryHost, tc.toolHost} {
				if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err != nil {
					scope.Names[h] = []netip.Addr{addr(tc.listen)}
				}
			}
			b := adapt.DefaultBudget()
			f := New(scope, Limits{Rate: float64(b.RPS), PerHostRate: float64(b.RPS), PerHostConns: b.Inflight})
			proxy := serve(t, f)
			targets, _ := adapt.CanaryTargets([]string{target})
			if len(targets) != 1 || targets[0].Host != hostKey(tc.toolHost) {
				t.Fatalf("the canary watches %+v, the forwarder counts the tool's connections under %q", targets, hostKey(tc.toolHost))
			}
			stop := canary(t, f, nil, target)
			// The canary is answered 429; wait until that reached the rate.
			deadline := time.Now().Add(5 * time.Second)
			for f.TargetRate().Rate(hostKey(tc.toolHost)) > 2 {
				if time.Now().After(deadline) {
					t.Fatalf("the canary's push-back did not lower the rate of %q: %+v", hostKey(tc.toolHost), f.TargetRate().Summary())
				}
				time.Sleep(20 * time.Millisecond)
			}
			const d = 3 * time.Second
			run(t, d, func(ctx context.Context, wg *sync.WaitGroup) {
				hammer(ctx, wg, proxy, "http://"+tc.toolHost+":"+strconv.Itoa(port)+"/", 8)
			})
			stop()
			total, _, _, _, _ := m.counts(time.Time{})
			s := f.TargetRate().Summary()
			// At the floor of one request a second (two for a moment after
			// a clean window): well under the start rate of 5/s that a key
			// of its own would have doubled from.
			t.Logf("MEASURED canary push-back on %s: the tool's connections to %s got %d requests in %s (bound %d), canary %+v", tc.canaryHost, tc.toolHost, total, d, 2*int(d.Seconds())+2, s.Canary)
			if total > 2*int(d.Seconds())+2 {
				t.Fatalf("the tool sent %d requests in %s to a host whose canary is pushed back", total, d)
			}
			if total == 0 || s.CircuitOpens != 0 {
				t.Fatalf("the tool's connections were stopped, not slowed: %d requests, %+v", total, s)
			}
		})
	}
}

// SECURITY: a target that answers only the recognizable canary with 429
// (and a long Retry-After) and serves the tool's requests does not end its
// own scan: the scan is slowed, every request of the tool arrives, no
// connection is refused, no breaker opens and the host is no coverage gap.
func TestCanaryOnlyPushbackSlowsAndTheScanCompletes(t *testing.T) {
	quick(t)
	b := adapt.DefaultBudget()
	m := newMeter(t, true)
	m.canaryOnly.Store(true)
	f, proxy := budgetForwarder(t, b, "example.com")
	target := m.url("example.com")
	stop := canary(t, f, m.roots(), target)
	const requests = 12
	pu, _ := url.Parse("http://" + proxy)
	var next, failed atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a test server's certificate
			for next.Add(1) <= requests {
				resp, err := c.Get(target)
				if err != nil {
					failed.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	el := time.Since(start)
	stop()
	total, _, _, _, _ := m.counts(time.Time{})
	s := f.TargetRate().Summary()
	t.Logf("MEASURED canary-only push-back (429, Retry-After: 300, to the canary alone): %d of %d tool requests arrived in %.1f s, %d failed, %d back-off(s), %d breaker opening(s), %d gap(s), lowest rate %.3g/s, canary %+v",
		total, requests, el.Seconds(), failed.Load(), s.Backoffs, s.CircuitOpens, s.GapsTotal, s.Min, s.Canary)
	if total != requests || failed.Load() != 0 {
		t.Fatalf("the scan did not complete: %d of %d requests arrived, %d failed", total, requests, failed.Load())
	}
	if s.CircuitOpens != 0 || s.GapsTotal != 0 || s.Unreachable != 0 {
		t.Fatalf("the canary alone opened a breaker or made a gap: %+v", s)
	}
	for _, r := range f.Refusals() {
		t.Fatalf("a connection was refused: %+v", r)
	}
	// It was slowed: the canary's push-back halved the rate.
	if s.Backoffs == 0 || s.Canary == nil || s.Canary.Pushback == 0 || s.Min > float64(b.RPS)/4 {
		t.Fatalf("the canary's push-back did not slow the host: %+v canary %+v", s, s.Canary)
	}
}

// The canary's push-back together with resets of the tool's own
// connections opens the breaker; the outcome records that evidence.
func TestCanaryPushbackWithToolResetsOpensTheBreaker(t *testing.T) {
	quick(t)
	b := adapt.DefaultBudget()
	m := newMeter(t, true)
	m.canaryOnly.Store(true)
	m.resetTool.Store(true)
	f, proxy := budgetForwarder(t, b, "example.com")
	target := m.url("example.com")
	stop := canary(t, f, m.roots(), target)
	run(t, 4*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
		hammer(ctx, wg, proxy, target, 8)
	})
	stop()
	s := f.TargetRate().Summary()
	hs := statOf(s, "example.com")
	t.Logf("MEASURED canary 429 and the tool's connections reset: %d breaker opening(s), gaps %+v, host %+v", s.CircuitOpens, s.Gaps, hs)
	if s.CircuitOpens == 0 || hs == nil || hs.OpenedBy != adapt.EvidenceCanaryAndConnection || hs.Resets < adapt.TargetRate.CorroborateFailures || hs.HTTP429 == 0 {
		t.Fatalf("summary %+v host %+v", s, hs)
	}
	if len(s.Gaps) != 1 || s.Gaps[0].Reason != adapt.GapThrottled || !strings.Contains(s.Gaps[0].Detail, "opened_by="+adapt.EvidenceCanaryAndConnection) {
		t.Fatalf("gaps %+v", s.Gaps)
	}
}

// record builds one TLS record header and body.
func record(typ byte, n int) []byte {
	return append([]byte{typ, 0x03, 0x03, byte(n >> 8), byte(n)}, bytes.Repeat([]byte{0xab}, n)...)
}

// meterFor returns a meter that counts its tokens, with its clock.
func meterFor(t *testing.T) (*tunnelMeter, *bytes.Buffer, *time.Time) {
	t.Helper()
	var out bytes.Buffer
	m := newTunnelMeter(&out, func(bool) error { return nil })
	now := m.born
	m.now = func() time.Time { return now }
	return m, &out, &now
}

// The tunnel meter on synthetic record streams: handshakes cost nothing,
// the first request is the connection's, each further request (client
// application data after the host spoke) takes one token, and every byte
// passes unchanged whatever the chunking.
func TestTunnelMeterCountsRequests(t *testing.T) {
	hello := record(recHandshake, 200)
	tls13 := [][]byte{hello, record(recChangeCipherSpec, 1), record(recApplicationData, 53)} // ClientHello; CCS, Finished
	tls12 := [][]byte{hello, record(recHandshake, 70), record(recChangeCipherSpec, 1), record(recHandshake, 40)}
	req := record(recApplicationData, 300)
	for name, handshake := range map[string][][]byte{"TLS 1.3": tls13, "TLS 1.2": tls12} {
		for _, chunk := range []int{1, 3, 7, 4096} {
			t.Run(fmt.Sprintf("%s in chunks of %d", name, chunk), func(t *testing.T) {
				m, out, _ := meterFor(t)
				var sent bytes.Buffer
				write := func(p []byte) {
					sent.Write(p)
					for len(p) > 0 {
						n := min(chunk, len(p))
						if w, err := m.Write(p[:n]); err != nil || w != n {
							t.Fatalf("Write = %d, %v", w, err)
						}
						p = p[n:]
					}
				}
				for _, r := range handshake {
					write(r)
					m.hostSpoke.Store(true) // the server's flight, its session tickets
				}
				if m.charged != 0 {
					t.Fatalf("the handshake took %d token(s)", m.charged)
				}
				write(req) // the first request: covered by the token of the dial
				if m.charged != 0 {
					t.Fatalf("the first request took %d token(s)", m.charged)
				}
				for i := 1; i <= 5; i++ {
					m.hostSpoke.Store(true) // the answer
					write(req)
					if m.charged != i {
						t.Fatalf("after %d further request(s): %d token(s)", i, m.charged)
					}
				}
				// A request in two records with no answer between: one token.
				m.hostSpoke.Store(true)
				write(record(recApplicationData, 200))
				write(record(recApplicationData, 900))
				if m.charged != 6 {
					t.Fatalf("a request in two records: %d token(s)", m.charged)
				}
				// The alert that ends the connection (close_notify) is not
				// a request: it takes no token and waits for none.
				m.hostSpoke.Store(true)
				write(record(recApplicationData, 19))
				if m.charged != 6 {
					t.Fatalf("the closing alert took a token: %d", m.charged)
				}
				// Short records in a row are counted: a request cannot be
				// passed in pieces too short to count.
				write(record(recApplicationData, 20))
				if m.charged != 7 {
					t.Fatalf("two short records in a row: %d token(s)", m.charged)
				}
				if err := m.Flush(); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out.Bytes(), sent.Bytes()) {
					t.Fatal("the meter changed the stream")
				}
			})
		}
	}
}

// What the meter cannot tell apart is bounded in bytes: client data beyond
// tunnelTurnBytes with no answer between takes another token (streams of
// HTTP/2, pipelined requests, an upload).
func TestTunnelMeterBoundsBytesPerToken(t *testing.T) {
	m, _, _ := meterFor(t)
	for _, r := range [][]byte{record(recHandshake, 200), record(recChangeCipherSpec, 1), record(recApplicationData, 53)} {
		_, _ = m.Write(r)
	}
	const n, size = 200, 100 // 200 small requests back to back: 20 kB
	for range n {
		if _, err := m.Write(record(recApplicationData, size)); err != nil {
			t.Fatal(err)
		}
	}
	want := (n*size - 1) / tunnelTurnBytes
	if m.charged < want {
		t.Fatalf("%d bytes of client data with no answer took %d token(s), want at least %d", n*size, m.charged, want)
	}
	// A tunnel that is not TLS is counted by turns and bytes too.
	raw, out, _ := meterFor(t)
	_, _ = raw.Write([]byte("GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n"))
	if raw.mode != tunnelRaw || raw.charged != 0 {
		t.Fatalf("mode %d, %d token(s)", raw.mode, raw.charged)
	}
	for i := 1; i <= 3; i++ {
		raw.hostSpoke.Store(true)
		_, _ = raw.Write([]byte("GET /next HTTP/1.1\r\nHost: a.example.com\r\n\r\n"))
		if raw.charged != i {
			t.Fatalf("raw request %d: %d token(s)", i, raw.charged)
		}
	}
	_, _ = raw.Write(bytes.Repeat([]byte("x"), tunnelTurnBytes+1))
	if raw.charged != 4 || out.Len() == 0 {
		t.Fatalf("a large write with no answer: %d token(s)", raw.charged)
	}
}

// A client whose hello offers HTTP/2 may send requests without the host
// speaking between them: every record of it takes a token, one for each
// tunnelTurnBytes, so streams multiplexed on the tunnel are counted.
func TestTunnelMeterCountsEveryRecordOfAClientThatOffersHTTP2(t *testing.T) {
	// A hello with an ALPN extension naming h2 and http/1.1, among other bytes.
	hello := append([]byte{recHandshake, 0x03, 0x01, 0, 64}, bytes.Repeat([]byte{0x11}, 64)...)
	copy(hello[5+20:], []byte{0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	for _, chunk := range []int{1, 2, 4096} {
		m, _, _ := meterFor(t)
		write := func(p []byte) {
			for len(p) > 0 {
				n := min(chunk, len(p))
				if _, err := m.Write(p[:n]); err != nil {
					t.Fatal(err)
				}
				p = p[n:]
			}
		}
		write(hello)
		if !m.h2 {
			t.Fatalf("chunks of %d: the offer of h2 in the hello was not seen", chunk)
		}
		write(record(recChangeCipherSpec, 1))
		write(record(recApplicationData, 53)) // Finished
		write(record(recApplicationData, 80)) // the client's preface and settings: the connection's own
		write(record(recApplicationData, 26)) // a settings acknowledgement: not a request
		for range 50 {                        // 50 requests, the host never speaks between them
			write(record(recApplicationData, 60))
		}
		if m.charged != 50 {
			t.Fatalf("chunks of %d: 50 multiplexed requests took %d token(s)", chunk, m.charged)
		}
		write(record(recApplicationData, 3*tunnelTurnBytes)) // an upload: a token for each 4 KiB
		if m.charged != 53 {
			t.Fatalf("chunks of %d: a 12 KiB record took %d token(s)", chunk, m.charged-50)
		}
	}
	// A hello that offers only http/1.1 is counted by turns.
	plain := append([]byte{recHandshake, 0x03, 0x01, 0, 64}, bytes.Repeat([]byte{0x11}, 64)...)
	copy(plain[5+20:], []byte{0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	m, _, _ := meterFor(t)
	for _, r := range [][]byte{plain, record(recChangeCipherSpec, 1), record(recApplicationData, 53), record(recApplicationData, 80), record(recApplicationData, 60), record(recApplicationData, 60)} {
		_, _ = m.Write(r)
	}
	if m.h2 || m.charged != 0 {
		t.Fatalf("a client that does not offer h2: h2 %t, %d token(s) with the host silent", m.h2, m.charged)
	}
}

// A tunnel past its lifetime, and a tunnel to a host that is backed off,
// carry no further request: the tunnel ends before a byte of that request
// is passed on.
func TestTunnelMeterEndsTheTunnel(t *testing.T) {
	m, out, now := meterFor(t)
	_, _ = m.Write([]byte("first request"))
	m.hostSpoke.Store(true)
	*now = now.Add(tunnelLifetime + time.Second)
	before := out.Len()
	if _, err := m.Write([]byte("second request")); !errors.Is(err, errTunnelLifetime) {
		t.Fatalf("a request past the lifetime: %v", err)
	}
	if out.Len() != before {
		t.Fatal("bytes of the refused request were passed on")
	}
	var buf bytes.Buffer
	refused := newTunnelMeter(&buf, func(bool) error { return adapt.ErrHostUnavailable })
	_, _ = refused.Write([]byte("first request"))
	refused.hostSpoke.Store(true)
	before = buf.Len()
	if _, err := refused.Write([]byte("second request")); !errors.Is(err, adapt.ErrHostUnavailable) || buf.Len() != before {
		t.Fatalf("a request to a host that is backed off: %v, %d bytes passed", err, buf.Len()-before)
	}
}

// An open breaker stops kept-alive tunnels too, not only new connections:
// the next request on the tunnel ends it.
func TestOpenBreakerEndsKeptAliveTunnels(t *testing.T) {
	old := adapt.TargetRate
	adapt.TargetRate.ThrottleSpacing = 10 * time.Millisecond
	t.Cleanup(func() { adapt.TargetRate = old })
	b := adapt.DefaultBudget()
	m := newMeter(t, true)
	f, proxy := budgetForwarder(t, b, "a.example.com")
	pu, _ := url.Parse("http://" + proxy)
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // a test server's certificate
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	get := func() error {
		resp, err := c.Get(m.url("a.example.com"))
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}
	if err := get(); err != nil {
		t.Fatal(err)
	}
	// The host's breaker opens (push-back read elsewhere on the tool's own
	// traffic).
	for range adapt.TargetRate.ThrottleRun {
		f.TargetRate().ReportHTTP("a.example.com", http.StatusTooManyRequests, "")
		time.Sleep(adapt.TargetRate.ThrottleSpacing)
	}
	if err := get(); err == nil {
		t.Fatal("a request on a kept-alive tunnel reached a host whose breaker is open")
	}
	if total, _, _, _, _ := m.counts(time.Time{}); total != 1 {
		t.Fatalf("%d requests arrived, want the first only", total)
	}
}
