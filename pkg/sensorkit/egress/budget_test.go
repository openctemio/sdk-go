package egress

// The per-host budget, end to end and measured on the target's side: a
// "tool" (plain HTTP clients that send as fast as they can through the
// forwarder, as a scanner whose flags ask for far more than the budget
// would) against servers in this process on 127.0.0.1 that count what
// arrives. Nothing here leaves the test process.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
)

// meter is a target that counts, on its own side, when each request
// arrived and how many were in flight, and answers as its mode says.
type meter struct {
	srv *httptest.Server
	// limit, when above 0, is the most requests per second the target
	// serves: a request over it gets 429 with Retry-After. unavailable
	// answers 503 to everything; reset closes every connection with a
	// reset before reading it.
	limit       atomic.Int64
	retryAfter  string
	unavailable atomic.Bool
	reset       atomic.Bool
	delay       time.Duration

	mu       sync.Mutex
	arrivals []time.Time
	served   []time.Time // arrivals answered 200
	refused  int         // 429 and 503 answers
	inflight int
	maxIn    int
}

func newMeter(t *testing.T, useTLS bool) *meter {
	t.Helper()
	m := &meter{retryAfter: "1", delay: 5 * time.Millisecond}
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		m.mu.Lock()
		m.arrivals = append(m.arrivals, now)
		m.inflight++
		m.maxIn = max(m.maxIn, m.inflight)
		over := false
		if lim := m.limit.Load(); lim > 0 {
			n := 0
			for i := len(m.served) - 1; i >= 0 && now.Sub(m.served[i]) < time.Second; i-- {
				n++
			}
			over = int64(n) >= lim
		}
		down := m.unavailable.Load()
		if over || down {
			m.refused++
		} else {
			m.served = append(m.served, now)
		}
		m.mu.Unlock()
		defer func() { m.mu.Lock(); m.inflight--; m.mu.Unlock() }()
		time.Sleep(m.delay)
		switch {
		case down:
			w.WriteHeader(http.StatusServiceUnavailable)
		case over:
			if m.retryAfter != "" {
				w.Header().Set("Retry-After", m.retryAfter)
			}
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	})
	m.srv = httptest.NewUnstartedServer(h)
	inner := m.srv.Listener
	m.srv.Listener = &resetListener{Listener: inner, reset: &m.reset}
	if useTLS {
		m.srv.StartTLS()
	} else {
		m.srv.Start()
	}
	t.Cleanup(m.srv.Close)
	return m
}

// resetListener resets accepted connections while reset is set.
type resetListener struct {
	net.Listener
	reset *atomic.Bool
}

func (l *resetListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !l.reset.Load() {
			return c, nil
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
	}
}

// roots are the authorities of the target's test certificate (it names
// example.com), for a canary that verifies it.
func (m *meter) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	if c := m.srv.Certificate(); c != nil {
		pool.AddCert(c)
	}
	return pool
}

func (m *meter) port() int { return m.srv.Listener.Addr().(*net.TCPAddr).Port }

// url is the target's URL under name (a name the forwarder pins to
// 127.0.0.1), so two targets in one process are two hosts.
func (m *meter) url(name string) string {
	scheme := "http"
	if m.srv.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + name + ":" + strconv.Itoa(m.port()) + "/"
}

// counts returns the arrivals in all, the most in any one-second window,
// how many arrived since the given time, the refused answers and the most
// requests in flight.
func (m *meter) counts(since time.Time) (total, peak, recent, refused, maxIn int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := slices.Clone(m.arrivals)
	slices.SortFunc(a, func(x, y time.Time) int { return x.Compare(y) })
	lo := 0
	for hi := range a {
		for a[hi].Sub(a[lo]) >= time.Second {
			lo++
		}
		peak = max(peak, hi-lo+1)
		if !a[hi].Before(since) {
			recent++
		}
	}
	return len(a), peak, recent, m.refused, m.maxIn
}

// overBudget reports whether peak arrivals in one second are above the
// budget. The forwarder lets at most rps+1 connections start in any one
// second (a token bucket of one token). What the target counts is when its
// handler ran, after a handshake and the scheduler's delay each, so on a
// loaded machine requests that left evenly spaced can land bunched: half
// the budget on top is allowed for that. The count over the whole run
// (overTotal) has no such slack.
func overBudget(peak, rps int) bool { return peak > rps+rps/2+1 }

// overTotal reports whether total requests in d are more than the budget
// lets through: rps a second and the bucket's one token.
func overTotal(total, rps int, d time.Duration) bool {
	return float64(total) > float64(rps)*d.Seconds()+1
}

// budgetForwarder is a forwarder as the tool host makes one for a task
// under budget b whose job covers hosts hosts: the task's rate is the
// budget of every host at once, each host is held to the budget.
func budgetForwarder(t *testing.T, b adapt.HostBudget, names ...string) (*Forwarder, string) {
	t.Helper()
	scope := Scope{Names: map[string][]netip.Addr{}}
	for _, n := range names {
		scope.Names[n] = []netip.Addr{addr("127.0.0.1")}
	}
	pace := b.ToolPace(len(names), true)
	f := New(scope, Limits{Rate: float64(pace.Rate), PerHostRate: float64(b.RPS), PerHostConns: b.Inflight})
	f.TargetRate().SetBudget(b)
	return f, serve(t, f)
}

// hammer is the tool: workers clients that request url through the
// forwarder one after the other, without keep-alive, as fast as they are
// let, until ctx ends.
func hammer(ctx context.Context, wg *sync.WaitGroup, proxyAddr, target string, workers int) {
	pu, _ := url.Parse("http://" + proxyAddr)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // a test server's certificate
			c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			for ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				resp, err := c.Do(req)
				if err != nil {
					// The forwarder refused the connection (breaker open).
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

// canary starts a canary on the forwarder for the given target URLs, wired
// as the tool host wires it, and returns its stop function.
func canary(t *testing.T, f *Forwarder, roots *x509.CertPool, urls ...string) func() {
	t.Helper()
	do, release := adapt.CanaryDo(f.DialTarget, roots)
	targets, unwatched := adapt.CanaryTargets(urls)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		adapt.NewCanary(f.TargetRate(), do, nil).Run(ctx, targets, unwatched)
		close(done)
	}()
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); <-done; release() }) }
	t.Cleanup(stop)
	return stop
}

// quick shortens the controller's windows and the canary's intervals so a
// back-off and its recovery fit in a test, and restores them after.
func quick(t *testing.T) {
	t.Helper()
	oldR, oldC := adapt.TargetRate, adapt.CanaryPace
	adapt.TargetRate.Window = 250 * time.Millisecond
	adapt.TargetRate.ThrottleSpacing = 100 * time.Millisecond
	adapt.TargetRate.BreakerOpen, adapt.TargetRate.BreakerOpenMax = 600*time.Millisecond, 1200*time.Millisecond
	// A host is not given up within a test: its recovery is what is tested.
	adapt.TargetRate.BreakerMaxTrips = 50
	adapt.CanaryPace.Interval, adapt.CanaryPace.FailInterval = 250*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { adapt.TargetRate, adapt.CanaryPace = oldR, oldC })
}

func run(t *testing.T, d time.Duration, start func(ctx context.Context, wg *sync.WaitGroup)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var wg sync.WaitGroup
	start(ctx, &wg)
	wg.Wait()
}

// One host never gets more than its budget, although the job's rate over
// its eight hosts is eight times that and the tool sends as fast as it can
// with far more workers than the budget's requests in flight. HTTPS, passed
// through: the bound does not depend on reading the traffic.
func TestBudgetHoldsOneHostUnderItsRateAndInflight(t *testing.T) {
	b := adapt.DefaultBudget()
	m := newMeter(t, true)
	m.delay = 30 * time.Millisecond
	names := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com", "g.example.com", "h.example.com"}
	f, proxy := budgetForwarder(t, b, names...)
	if got := f.limits.Rate; got != 160 {
		t.Fatalf("the task's rate over eight hosts is %v, want 160", got)
	}
	start := time.Now()
	run(t, 8*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
		hammer(ctx, wg, proxy, m.url("a.example.com"), 64)
	})
	total, peak, recent, _, maxIn := m.counts(start.Add(6 * time.Second))
	t.Logf("MEASURED one host, budget %d/s and %d in flight, tool unbounded with 64 workers: %d requests in 8 s, peak %d in any one second, %d in the last 2 s, %d in flight at most",
		b.RPS, b.Inflight, total, peak, recent, maxIn)
	// A token bucket of one token at 20/s lets at most 21 requests start in
	// any one second.
	if overBudget(peak, b.RPS) {
		t.Fatalf("peak %d requests in one second, budget %d", peak, b.RPS)
	}
	// Slow start: 5/s for 2 s, 10/s for 2 s, then the budget for 4 s.
	if total > 5*2+10*2+b.RPS*4+3 {
		t.Fatalf("%d requests in 8 s, the budget with its slow start lets %d through", total, 5*2+10*2+b.RPS*4)
	}
	if maxIn > b.Inflight {
		t.Fatalf("%d requests in flight, budget %d", maxIn, b.Inflight)
	}
	// It does reach the budget (slow start 5, 10, 20 over the first 4 s).
	if recent < b.RPS*2*7/10 {
		t.Fatalf("only %d requests in the last 2 s: the host never reached its budget of %d/s", recent, b.RPS)
	}
	s := f.TargetRate().Summary()
	if s.Budget == nil || s.Budget.RPS != b.RPS || s.Ceiling != float64(b.RPS) || s.Backoffs != 0 || s.CircuitOpens != 0 {
		t.Fatalf("summary %+v", s)
	}
}

// A lower signed budget holds the host lower; a signed budget above the
// sensor's ceiling is clamped to it, and the host gets the ceiling.
func TestLowerBudgetWinsAndHigherIsClamped(t *testing.T) {
	cases := []struct {
		name    string
		job     adapt.JobBudget
		ceiling adapt.BudgetCeiling
		rps     int
		in      int
	}{
		{"signed Gentle", adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{}, 5, 2},
		{"signed 5000/s under an operator ceiling of 10/s and 3 in flight", adapt.JobBudget{Level: "custom", RPS: 5000, Inflight: 500}, adapt.BudgetCeiling{RPS: 10, Inflight: 3}, 10, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := adapt.ResolveBudget(adapt.DefaultPacing, &tc.job, tc.ceiling)
			if b.RPS != tc.rps || b.Inflight != tc.in {
				t.Fatalf("budget %+v", b)
			}
			m := newMeter(t, true)
			m.delay = 30 * time.Millisecond
			f, proxy := budgetForwarder(t, b, "a.example.com")
			run(t, 5*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
				hammer(ctx, wg, proxy, m.url("a.example.com"), 32)
			})
			total, peak, _, _, maxIn := m.counts(time.Time{})
			t.Logf("MEASURED %s: %d requests in 5 s, peak %d in any one second, %d in flight at most", tc.name, total, peak, maxIn)
			if overBudget(peak, tc.rps) || overTotal(total, tc.rps, 5*time.Second) || maxIn > tc.in {
				t.Fatalf("peak %d/s and %d in flight, budget %d/s and %d", peak, maxIn, tc.rps, tc.in)
			}
			if got := f.TargetRate().Summary().Budget; got == nil || got.Source != adapt.BudgetFromJob {
				t.Fatalf("summary budget %+v", got)
			}
		})
	}
}

// Two hosts of one job do not starve each other: one that pushes back hard
// is slowed and left alone, and the other keeps its whole budget.
func TestTwoHostsDoNotStarveEachOther(t *testing.T) {
	quick(t)
	b := adapt.DefaultBudget()
	bad, good := newMeter(t, false), newMeter(t, false)
	bad.limit.Store(1)
	bad.retryAfter = "1"
	f, proxy := budgetForwarder(t, b, "bad.example.com", "good.example.com")
	start := time.Now()
	run(t, 6*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
		hammer(ctx, wg, proxy, bad.url("bad.example.com"), 32)
		hammer(ctx, wg, proxy, good.url("good.example.com"), 32)
	})
	_, badPeak, badRecent, _, _ := bad.counts(start.Add(3 * time.Second))
	_, goodPeak, goodRecent, _, _ := good.counts(start.Add(3 * time.Second))
	t.Logf("MEASURED two hosts, last 3 s: the throttling host got %d requests (peak %d/s), the healthy host %d (peak %d/s)", badRecent, badPeak, goodRecent, goodPeak)
	goodTotal, _, _, _, _ := good.counts(time.Time{})
	if overBudget(goodPeak, b.RPS) || overBudget(badPeak, b.RPS) || overTotal(goodTotal, b.RPS, 6*time.Second) {
		t.Fatalf("a host got more than its budget: peaks %d and %d, %d in 6 s", goodPeak, badPeak, goodTotal)
	}
	if goodRecent < b.RPS*3*7/10 {
		t.Fatalf("the healthy host got %d requests in 3 s, its budget is %d/s", goodRecent, b.RPS)
	}
	if badRecent > goodRecent/3 {
		t.Fatalf("the throttling host still got %d requests in 3 s", badRecent)
	}
	s := f.TargetRate().Summary()
	var badStat *adapt.HostStat
	for i := range s.HostStats {
		if s.HostStats[i].Host == "bad.example.com" {
			badStat = &s.HostStats[i]
		}
	}
	if badStat == nil || badStat.Backoffs == 0 || badStat.HTTP429 == 0 || badStat.RetryAfterSeconds != 1 {
		t.Fatalf("summary %+v", s)
	}
}

// A target that limits requests and answers 429 with Retry-After, on plain
// HTTP (the forwarder reads every answer): the host's rate is halved, the
// Retry-After is waited out, and when the target lifts its limit the rate
// comes back to the budget.
func TestBackoffOn429AndRecovery(t *testing.T) {
	quick(t)
	b := adapt.DefaultBudget()
	m := newMeter(t, false)
	m.limit.Store(4)
	f, proxy := budgetForwarder(t, b, "a.example.com")
	var limited, lifted time.Time
	run(t, 9*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
		limited = time.Now()
		hammer(ctx, wg, proxy, m.url("a.example.com"), 32)
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
			case <-time.After(4 * time.Second):
				lifted = time.Now()
				m.limit.Store(0)
			}
		}()
	})
	total, peak, recent, refused, _ := m.counts(lifted.Add(3 * time.Second))
	_, _, afterLimit, _, _ := m.counts(lifted)
	during := total - afterLimit
	s := f.TargetRate().Summary()
	t.Logf("MEASURED 429 with Retry-After: 1 for 4 s, then lifted: %d requests while limited (%.1f/s, %d refused), %d in the last 2 s after recovery, peak %d/s, %d back-off(s), lowest rate %.3g/s",
		during, float64(during)/lifted.Sub(limited).Seconds(), refused, recent, peak, s.Backoffs, s.Min)
	if overBudget(peak, b.RPS) || overTotal(total, b.RPS, 9*time.Second) {
		t.Fatalf("peak %d/s, %d in 9 s", peak, total)
	}
	if s.Backoffs < 2 || s.Min > float64(b.RPS)/4 {
		t.Fatalf("the rate was not lowered: %+v", s)
	}
	// While limited the host was sent well under its budget.
	if float64(during) > 0.6*float64(b.RPS)*lifted.Sub(limited).Seconds() {
		t.Fatalf("%d requests in the limited %s: no back-off", during, lifted.Sub(limited))
	}
	// Recovered: the last two seconds run at most of the budget again.
	if recent < b.RPS*2*6/10 {
		t.Fatalf("only %d requests in the last 2 s: the rate did not recover", recent)
	}
	if hs := s.HostStats; len(hs) != 1 || hs[0].HTTP429 == 0 || hs[0].RetryAfterSeconds != 1 {
		t.Fatalf("host stats %+v", hs)
	}
}

// HTTPS passed through, a target that answers nothing but 429: without a
// canary the forwarder sees only bytes on tunnels it cannot read and keeps
// sending at the budget; with the canary the rate is halved, the breaker
// opens, the host is a throttled gap with the counts, and when the target
// recovers the breaker closes and the rate comes back.
func TestHTTPSWithoutInterceptionNeedsTheCanary(t *testing.T) {
	quick(t)
	b := adapt.DefaultBudget()

	blind := newMeter(t, true)
	blind.limit.Store(1)
	blind.retryAfter = ""
	fb, proxyB := budgetForwarder(t, b, "example.com")
	run(t, 3*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
		hammer(ctx, wg, proxyB, blind.url("example.com"), 32)
	})
	blindTotal, _, _, blindRefused, _ := blind.counts(time.Time{})
	if s := fb.TargetRate().Summary(); s.Backoffs != 0 || s.CircuitOpens != 0 || len(s.Gaps) != 0 {
		t.Fatalf("without a canary the forwarder is expected to be blind on HTTPS: %+v", s)
	}

	m := newMeter(t, true)
	m.limit.Store(1)
	m.retryAfter = ""
	f, proxy := budgetForwarder(t, b, "example.com")
	target := m.url("example.com")
	stop := canary(t, f, m.roots(), target)
	var lifted time.Time
	run(t, 12*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
		hammer(ctx, wg, proxy, target, 32)
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
				lifted = time.Now()
				m.limit.Store(0)
			}
		}()
	})
	stop()
	total, peak, recent, refused, _ := m.counts(lifted.Add(7 * time.Second))
	_, _, after, _, _ := m.counts(lifted)
	during := total - after
	s := f.TargetRate().Summary()
	t.Logf("MEASURED HTTPS passthrough, target answers 429 for 3 s: blind forwarder sent %d requests in 3 s (%d refused); with the canary %d requests in the limited 3 s (%d refused), %d back-off(s), %d breaker opening(s), %d in the last 2 s after recovery, peak %d/s",
		blindTotal, blindRefused, during, refused, s.Backoffs, s.CircuitOpens, recent, peak)
	if s.Backoffs < 2 || s.CircuitOpens < 1 {
		t.Fatalf("no back-off through the canary: %+v", s)
	}
	if during*2 > blindTotal {
		t.Fatalf("with the canary the throttling host still got %d requests (blind: %d)", during, blindTotal)
	}
	var gap *adapt.Gap
	for i := range s.Gaps {
		if s.Gaps[i].Host == "example.com" {
			gap = &s.Gaps[i]
		}
	}
	if gap == nil || gap.Reason != adapt.GapThrottled || !strings.Contains(gap.Detail, "429=") || !strings.Contains(gap.Detail, "circuit_opens=") {
		t.Fatalf("gaps %+v", s.Gaps)
	}
	if s.Canary == nil || s.Canary.Hosts != 1 || s.Canary.Pushback < adapt.TargetRate.ThrottleRun {
		t.Fatalf("canary summary %+v", s.Canary)
	}
	if recent < b.RPS*2*5/10 {
		t.Fatalf("only %d requests in the last 2 s: the host did not recover after the target lifted its limit", recent)
	}
	// The canary's own traffic: four requests a second at its shortened
	// interval (ten after a push-back), never the tool's rate.
	if s.Canary.Probes > 12*10 {
		t.Fatalf("the canary sent %d requests in 12 s", s.Canary.Probes)
	}
}

// Bursts of 503 answers on HTTPS lower the rate through the canary, and
// the rate climbs back after them.
func TestBackoffOn503Bursts(t *testing.T) {
	quick(t)
	b := adapt.DefaultBudget()
	m := newMeter(t, true)
	f, proxy := budgetForwarder(t, b, "example.com")
	target := m.url("example.com")
	stop := canary(t, f, m.roots(), target)
	start := time.Now()
	run(t, 9*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
		hammer(ctx, wg, proxy, target, 32)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ctx.Err() == nil && i < 2; i++ {
				time.Sleep(1200 * time.Millisecond)
				m.unavailable.Store(true)
				time.Sleep(800 * time.Millisecond)
				m.unavailable.Store(false)
			}
		}()
	})
	stop()
	total, peak, recent, refused, _ := m.counts(start.Add(7 * time.Second))
	s := f.TargetRate().Summary()
	t.Logf("MEASURED two 0.8 s bursts of 503 on HTTPS: %d refused answers, %d back-off(s), %d breaker opening(s), lowest rate %.3g/s, %d requests in the last 2 s, peak %d/s",
		refused, s.Backoffs, s.CircuitOpens, s.Min, recent, peak)
	if s.Backoffs < 1 || s.Min >= float64(b.RPS) {
		t.Fatalf("summary %+v", s)
	}
	if len(s.HostStats) == 0 || s.HostStats[0].HTTP503 == 0 {
		t.Fatalf("host stats %+v", s.HostStats)
	}
	if overBudget(peak, b.RPS) || overTotal(total, b.RPS, 9*time.Second) {
		t.Fatalf("peak %d/s, %d in 9 s", peak, total)
	}
	if recent < b.RPS*2*4/10 {
		t.Fatalf("only %d requests in the last 2 s: no recovery after the bursts", recent)
	}
}

// A target that served the scan and then resets every connection: the
// canary's resets lower the rate and open the breaker. The host is a
// coverage gap: blocked when the tool's own connections were reset twenty
// times in a row first, else throttled; its counters hold the resets
// either way. What the target served before the resets was delivered.
func TestResetsOpenTheBreaker(t *testing.T) {
	quick(t)
	b := adapt.DefaultBudget()
	m := newMeter(t, true)
	f, proxy := budgetForwarder(t, b, "example.com")
	target := m.url("example.com")
	stop := canary(t, f, m.roots(), target)
	run(t, 5*time.Second, func(ctx context.Context, wg *sync.WaitGroup) {
		hammer(ctx, wg, proxy, target, 16)
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(1500 * time.Millisecond)
			m.reset.Store(true)
		}()
	})
	stop()
	served, _, _, _, _ := m.counts(time.Time{})
	s := f.TargetRate().Summary()
	t.Logf("MEASURED resets after 1.5 s: %d requests served before, %d back-off(s), %d breaker opening(s), gaps %+v", served, s.Backoffs, s.CircuitOpens, s.Gaps)
	if served == 0 || s.Backoffs == 0 || s.CircuitOpens == 0 {
		t.Fatalf("summary %+v", s)
	}
	if len(s.Gaps) != 1 || (s.Gaps[0].Reason != adapt.GapThrottled && s.Gaps[0].Reason != adapt.GapBlocked) {
		t.Fatalf("gaps %+v", s.Gaps)
	}
	if len(s.HostStats) != 1 || s.HostStats[0].Resets == 0 || s.HostStats[0].Min >= float64(b.RPS) {
		t.Fatalf("host stats %+v", s.HostStats)
	}
}

// The canary's connection passes the same scope check as the tool's: a
// host outside the task's scope gets no canary request.
func TestCanaryDialStaysInScope(t *testing.T) {
	m := newMeter(t, false)
	f, _ := budgetForwarder(t, adapt.DefaultBudget(), "a.example.com")
	if _, err := f.DialTarget(t.Context(), "other.example.com", m.port()); err == nil {
		t.Fatal("the canary reached a host outside the scope")
	}
	c, err := f.DialTarget(t.Context(), "a.example.com", m.port())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if total, _, _, _, _ := m.counts(time.Time{}); total != 0 {
		t.Fatalf("%d requests arrived from a bare connection", total)
	}
	recs, _ := f.Records()
	if len(recs) != 2 || recs[0].Verdict != Refused || recs[1].Protocol != ProtocolCanary || recs[1].Verdict != Allowed {
		t.Fatalf("records %+v", recs)
	}
	// The canary's connections are not the tool's: the tally stays empty.
	if tl := f.Tally(); tl.Allowed != 0 || tl.Refused != 0 {
		t.Fatalf("tally %+v", tl)
	}
}

// A connection slot is freed when its connection ends, and a connection
// over the host's slots waits, then is refused.
func TestPerHostConnectionSlots(t *testing.T) {
	f := New(Scope{Prefixes: []netip.Prefix{pfx("127.0.0.1/32")}}, Limits{Rate: 1000, PerHostRate: 1000, PerHostConns: 2, DialTimeout: 200 * time.Millisecond})
	r1, err := f.hostSlot(t.Context(), "h")
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := f.hostSlot(t.Context(), "h")
	if _, err := f.hostSlot(t.Context(), "h"); !errors.Is(err, ErrHostBusy) {
		t.Fatalf("a third connection got a slot: %v", err)
	}
	if r, err := f.hostSlot(t.Context(), "other"); err != nil {
		t.Fatalf("another host shares the slots: %v", err)
	} else {
		r()
	}
	r1()
	r1() // freeing twice frees once
	r3, err := f.hostSlot(t.Context(), "h")
	if err != nil {
		t.Fatalf("no slot after one was freed: %v", err)
	}
	if _, err := f.hostSlot(t.Context(), "h"); !errors.Is(err, ErrHostBusy) {
		t.Fatalf("freeing one slot twice freed two: %v", err)
	}
	r2()
	r3()
}

// Scan time on a well-behaved host: the same 200 requests through a
// forwarder as it was before the budget (the job's rate as the host's
// ceiling, no bound on connections, no canary) and under the budget (with
// its connection slots and a canary). Set PACING_SCAN_TIME=1 to run it; it
// takes about half a minute.
func TestScanTimeOnAWellBehavedHost(t *testing.T) {
	if os.Getenv("PACING_SCAN_TIME") == "" {
		t.Skip("set PACING_SCAN_TIME=1 to measure")
	}
	b := adapt.DefaultBudget()
	const requests = 200
	measure := func(withBudget bool, delay time.Duration) time.Duration {
		m := newMeter(t, true)
		m.delay = delay
		scope := Scope{Names: map[string][]netip.Addr{"example.com": {addr("127.0.0.1")}}}
		limits := Limits{Rate: float64(b.RPS), PerHostRate: float64(b.RPS)}
		if withBudget {
			limits.PerHostConns = b.Inflight
		}
		f := New(scope, limits)
		proxy := serve(t, f)
		target := m.url("example.com")
		if withBudget {
			defer canary(t, f, m.roots(), target)()
		}
		pu, _ := url.Parse("http://" + proxy)
		var next atomic.Int64
		var wg sync.WaitGroup
		start := time.Now()
		for range 25 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true,
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a test server's certificate
				for next.Add(1) <= requests {
					resp, err := c.Get(target)
					if err != nil {
						t.Errorf("request failed: %v", err)
						return
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}()
		}
		wg.Wait()
		el := time.Since(start)
		if total, _, _, _, _ := m.counts(time.Time{}); total < requests {
			t.Errorf("only %d of %d requests arrived", total, requests)
		}
		return el
	}
	for _, delay := range []time.Duration{20 * time.Millisecond, 300 * time.Millisecond, time.Second} {
		before := measure(false, delay)
		after := measure(true, delay)
		factor := after.Seconds() / before.Seconds()
		t.Logf("MEASURED scan time, %d requests, target answers in %s: before %.1f s, under the budget %.1f s, factor %.2f", requests, delay, before.Seconds(), after.Seconds(), factor)
		// A target that answers within the budget's in-flight share
		// (8 in flight / 20 per second = 0.4 s) is not slowed.
		if delay <= 300*time.Millisecond && factor > 1.15 {
			t.Errorf("a well-behaved host scans %.2f times slower under the budget", factor)
		}
	}
}

// The canary verifies the target's certificate. A host whose certificate
// does not verify is not read: its 429 answers lower nothing, and the
// summary counts the unverified requests.
func TestCanaryDoesNotReadAnUnverifiedHost(t *testing.T) {
	quick(t)
	m := newMeter(t, true)
	m.limit.Store(1)
	m.retryAfter = ""
	f, _ := budgetForwarder(t, adapt.DefaultBudget(), "example.com")
	// nil roots: the system's, which do not know the test certificate.
	stop := canary(t, f, nil, m.url("example.com"))
	time.Sleep(1500 * time.Millisecond)
	stop()
	s := f.TargetRate().Summary()
	if s.Canary == nil || s.Canary.Unverified == 0 || s.Canary.Pushback != 0 || s.Backoffs != 0 || s.CircuitOpens != 0 {
		t.Fatalf("summary %+v canary %+v", s, s.Canary)
	}
	if total, _, _, _, _ := m.counts(time.Time{}); total != 0 {
		t.Fatalf("%d requests reached a host whose certificate did not verify", total)
	}
}
