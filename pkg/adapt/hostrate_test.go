package adapt

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/openctemio/ctis/edgeprotect"
)

// testCtl is a controller on a fake clock with no jitter.
func testCtl(t *testing.T, ceiling float64) (*HostRate, *time.Time) {
	t.Helper()
	c := NewHostRate(ceiling)
	clk := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return clk }
	c.jitter = func() float64 { return 0.5 }
	return c, &clk
}

func window(clk *time.Time) { *clk = clk.Add(TargetRate.Window) }

// clean feeds one healthy window to host and closes it.
func clean(c *HostRate, clk *time.Time, host string) {
	c.Report(host, Event{Signal: Answered})
	window(clk)
	c.Report(host, Event{Signal: Answered})
}

func TestCeilingIsTheLowestLimit(t *testing.T) {
	cases := []struct {
		in   []float64
		want float64
	}{
		{nil, TargetRate.DefaultCeiling},
		{[]float64{0, -1}, TargetRate.DefaultCeiling},
		{[]float64{150, 0, 20, 500}, 20},
		{[]float64{0, 7}, 7},
	}
	for _, tc := range cases {
		if got := Ceiling(tc.in...); got != tc.want {
			t.Errorf("Ceiling(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSlowStartConvergesToTheCeiling(t *testing.T) {
	c, clk := testCtl(t, 100)
	if r := c.Rate("a.example"); r != 25 {
		t.Fatalf("start rate = %v, want 25", r)
	}
	want := []float64{50, 100, 100, 100}
	for i, w := range want {
		clean(c, clk, "a.example")
		if r := c.Rate("a.example"); r != w {
			t.Fatalf("window %d: rate %v, want %v", i, r, w)
		}
	}
}

func TestDecreaseOn429OncePerWindowThenAdditiveIncrease(t *testing.T) {
	c, clk := testCtl(t, 100)
	clean(c, clk, "h")
	clean(c, clk, "h") // at the ceiling
	c.ReportHTTP("h", 429, "")
	c.ReportHTTP("h", 429, "") // same window: replies to the same burst
	if r := c.Rate("h"); r != 50 {
		t.Fatalf("after 429s in one window rate = %v, want 50", r)
	}
	window(clk)
	c.ReportHTTP("h", 503, "")
	if r := c.Rate("h"); r != 25 {
		t.Fatalf("after a 503 in the next window rate = %v, want 25", r)
	}
	// The window with the 503 raises nothing; then +10 % of the ceiling
	// per clean window (congestion avoidance, no slow start).
	window(clk)
	c.Report("h", Event{Signal: Answered})
	if r := c.Rate("h"); r != 25 {
		t.Fatalf("window with push-back raised the rate to %v", r)
	}
	window(clk)
	c.Report("h", Event{Signal: Answered})
	if r := c.Rate("h"); r != 35 {
		t.Fatalf("clean window: rate %v, want 35", r)
	}
	if s := c.Summary(); s.Throttled != 1 || s.Min != 25 {
		t.Fatalf("summary %+v, want 1 throttled host, min 25", s)
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	c, clk := testCtl(t, 1000)
	ctx := context.Background()
	// A short Retry-After holds the next connection.
	c.Report("h", Event{Signal: Congested, Reason: ReasonHTTP429, RetryAfter: 80 * time.Millisecond})
	start := time.Now()
	if err := c.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 70*time.Millisecond {
		t.Fatalf("Acquire returned after %v, before the Retry-After", el)
	}
	// A long one refuses connections until it passes, and the host is a
	// gap.
	c.ReportHTTP("g", 429, "120")
	if err := c.Acquire(ctx, "g"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("Acquire during a 120s Retry-After = %v, want ErrHostUnavailable", err)
	}
	*clk = clk.Add(121 * time.Second)
	if err := c.Acquire(ctx, "g"); err != nil {
		t.Fatalf("Acquire after the Retry-After = %v", err)
	}
	gaps, total := c.Gaps()
	if total != 1 || gaps[0].Host != "g" || gaps[0].Reason != GapRateFloor {
		t.Fatalf("gaps %+v (%d), want g rate_floor", gaps, total)
	}
}

func TestBreakerOpensHalfOpensAndGivesUp(t *testing.T) {
	c, clk := testCtl(t, 1000)
	ctx := context.Background()
	fail := func() { c.Report("h", Event{Signal: Failed, Reason: ReasonTimeout}) }
	for range TargetRate.BreakerFailures - 1 {
		fail()
	}
	if err := c.Acquire(ctx, "h"); err != nil {
		t.Fatalf("breaker open before %d failures: %v", TargetRate.BreakerFailures, err)
	}
	fail()
	if err := c.Acquire(ctx, "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("Acquire with the breaker open = %v", err)
	}
	// Late failures of connections opened before do not trip it again.
	fail()
	fail()
	*clk = clk.Add(TargetRate.BreakerOpen)
	if err := c.Acquire(ctx, "h"); err != nil {
		t.Fatalf("half-open probe refused: %v", err)
	}
	if err := c.Acquire(ctx, "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("second connection while the probe is in flight = %v", err)
	}
	c.Report("h", Event{Signal: Answered})
	if err := c.Acquire(ctx, "h"); err != nil {
		t.Fatalf("breaker did not close after the probe answered: %v", err)
	}
	// Second trip: open twice as long; a failed probe trips again, and the
	// third trip gives the host up.
	for range TargetRate.BreakerFailures {
		fail()
	}
	*clk = clk.Add(TargetRate.BreakerOpen)
	if err := c.Acquire(ctx, "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("second trip was not longer: %v", err)
	}
	*clk = clk.Add(TargetRate.BreakerOpen)
	if err := c.Acquire(ctx, "h"); err != nil {
		t.Fatalf("second half-open probe refused: %v", err)
	}
	fail()
	*clk = clk.Add(time.Hour)
	if err := c.Acquire(ctx, "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("given-up host accepted a connection: %v", err)
	}
	s := c.Summary()
	if s.Unreachable != 1 || s.GapsTotal != 1 || s.Gaps[0].Reason != GapBreakerOpen {
		t.Fatalf("summary %+v, want one unreachable host with a breaker_open gap", s)
	}
}

func TestBreakerJitterSpreadsTheOpenTime(t *testing.T) {
	c, clk := testCtl(t, 100)
	c.jitter = func() float64 { return 1 } // +20 %
	for range TargetRate.BreakerFailures {
		c.Report("h", Event{Signal: Failed, Reason: ReasonReset})
	}
	*clk = clk.Add(TargetRate.BreakerOpen)
	if err := c.Acquire(context.Background(), "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("jittered breaker closed at the base open time: %v", err)
	}
	*clk = clk.Add(TargetRate.BreakerOpen / 4)
	if err := c.Acquire(context.Background(), "h"); err != nil {
		t.Fatalf("breaker still open past base+20 %%: %v", err)
	}
}

func TestNeverBelowTheFloorAndAFloorGap(t *testing.T) {
	c, clk := testCtl(t, 4)
	for range 10 {
		c.ReportHTTP("h", 429, "")
		window(clk)
		if r := c.Rate("h"); r < TargetRate.Floor {
			t.Fatalf("rate %v below the floor", r)
		}
	}
	if r := c.Rate("h"); r != TargetRate.Floor {
		t.Fatalf("rate %v, want the floor", r)
	}
	gaps, _ := c.Gaps()
	if len(gaps) != 1 || gaps[0].Reason != GapRateFloor {
		t.Fatalf("gaps %+v, want rate_floor", gaps)
	}
}

func TestACeilingBelowTheFloorWins(t *testing.T) {
	c, clk := testCtl(t, 0.5)
	for range 4 {
		clean(c, clk, "h")
	}
	if r := c.Rate("h"); r != 0.5 {
		t.Fatalf("rate %v above a 0.5/s ceiling", r)
	}
}

// Whatever the targets answer, the rate stays within [floor, ceiling].
func TestRateAlwaysWithinBounds(t *testing.T) {
	for _, ceiling := range []float64{1, 3, 20, 150, 1000} {
		c, clk := testCtl(t, ceiling)
		rng := rand.New(rand.NewPCG(1, uint64(ceiling)))
		events := []Event{{Signal: Answered}, {Signal: Connected}, {Signal: Congested, Reason: ReasonHTTP429},
			{Signal: Forbidden}, {Signal: Failed, Reason: ReasonReset}}
		for i := range 5000 {
			c.Report("h", events[rng.IntN(len(events))])
			if rng.IntN(3) == 0 {
				*clk = clk.Add(time.Duration(rng.IntN(5000)) * time.Millisecond)
			}
			r := c.Rate("h")
			if r > ceiling || r < min(TargetRate.Floor, ceiling) {
				t.Fatalf("ceiling %v step %d: rate %v out of bounds", ceiling, i, r)
			}
		}
	}
}

func TestDialFailuresCountOnlyOnPortsThatAnswered(t *testing.T) {
	c, _ := testCtl(t, 100)
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	for range 50 {
		c.ReportDial("h", 81, refused) // a closed port: not push-back
	}
	if s := c.Summary(); s.Throttled != 0 {
		t.Fatalf("closed ports throttled the host: %+v", s)
	}
	c.ReportDial("h", 443, nil)
	c.ReportDial("h", 443, refused)
	if s := c.Summary(); s.Throttled != 1 {
		t.Fatalf("a refused connection on a port that answered did not count: %+v", s)
	}
	c.ReportDial("h", 443, context.Canceled)
	c.ReportDial("h", 443, fmt.Errorf("wrapped: %w", context.Canceled))
}

func TestARunOf403AfterAnswersIsABlock(t *testing.T) {
	c, _ := testCtl(t, 100)
	// A host that only ever answered 403 is not "blocking": the paths
	// probed may simply be forbidden.
	for range 2 * TargetRate.BlockRun {
		c.ReportHTTP("x", 403, "")
	}
	if _, n := c.Gaps(); n != 0 {
		t.Fatal("403s alone were read as a block")
	}
	c.ReportHTTP("h", 200, "")
	for range TargetRate.BlockRun - 1 {
		c.ReportHTTP("h", 403, "")
	}
	c.ReportHTTP("h", 404, "") // breaks the run
	for range TargetRate.BlockRun {
		c.ReportHTTP("h", 403, "")
	}
	gaps, n := c.Gaps()
	if n != 1 || gaps[0].Host != "h" || gaps[0].Reason != GapBlocked {
		t.Fatalf("gaps %+v, want h blocked", gaps)
	}
	if err := c.Acquire(context.Background(), "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("a blocked host was not backed off: %v", err)
	}
}

// A bare 403 on the very first request stays an ordinary answer, but a
// vendor's challenge or block page is a block from the first answer.
func TestAVendorBlockPageOnTheFirstRequestIsABlock(t *testing.T) {
	c, _ := testCtl(t, 100)
	c.ReportResponse("plain", 403, "", edgeprotect.Verdict{State: edgeprotect.Direct})
	c.ReportResponse("fronted", 403, "", edgeprotect.Verdict{Vendor: edgeprotect.Cloudflare, State: edgeprotect.Fronted})
	if _, n := c.Gaps(); n != 0 {
		t.Fatal("a bare 403 or a fronting marker was read as a block")
	}
	v := edgeprotect.Verdict{Vendor: edgeprotect.Cloudflare, State: edgeprotect.Challenged, Signal: "cloudflare.cf-mitigated"}
	c.ReportResponse("h", 403, "", v)
	gaps, n := c.Gaps()
	if n != 1 || gaps[0].Host != "h" || gaps[0].Reason != GapBlocked || gaps[0].Edge != "challenged" || gaps[0].Vendor != "cloudflare" {
		t.Fatalf("gaps %+v, want h blocked by a cloudflare challenge", gaps)
	}
	if err := c.Acquire(context.Background(), "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("a challenged host was not backed off: %v", err)
	}
	// A challenge answered with 503 is a block, not congestion.
	c.ReportResponse("h2", 503, "30", edgeprotect.Verdict{Vendor: edgeprotect.Cloudflare, State: edgeprotect.Challenged})
	if gaps, _ := c.Gaps(); len(gaps) != 2 {
		t.Fatalf("503 challenge: %+v", gaps)
	}
	// A rate-limit verdict stays congestion.
	c.ReportResponse("h3", 429, "", edgeprotect.Verdict{Vendor: edgeprotect.Cloudflare, State: edgeprotect.RateLimited})
	if gaps, _ := c.Gaps(); len(gaps) != 2 {
		t.Fatalf("a rate limit became a block: %+v", gaps)
	}
}

// An edge block after a run of plain 403s adds the edge to the gap that run made.
func TestEdgeBlockNamesTheGapOfAnEarlierRun(t *testing.T) {
	c, _ := testCtl(t, 100)
	c.ReportHTTP("h", 200, "")
	for range TargetRate.BlockRun {
		c.ReportHTTP("h", 403, "")
	}
	if gaps, _ := c.Gaps(); len(gaps) != 1 || gaps[0].Edge != "" {
		t.Fatalf("gaps %+v", gaps)
	}
	c.Report("h", Event{Signal: Forbidden, Edge: edgeprotect.Verdict{Vendor: edgeprotect.Akamai, State: edgeprotect.Blocked, Signal: "akamai.access-denied"}})
	if gaps, _ := c.Gaps(); len(gaps) != 1 || gaps[0].Edge != "blocked" || gaps[0].Vendor != "akamai" {
		t.Fatalf("gaps %+v", gaps)
	}
}

// State belongs to one controller (one task): a host given up by one task
// is fresh for another.
func TestStateIsPerController(t *testing.T) {
	a, _ := testCtl(t, 100)
	b, _ := testCtl(t, 100)
	for range TargetRate.BreakerFailures {
		a.Report("shared.example", Event{Signal: Failed, Reason: ReasonTimeout})
	}
	if err := b.Acquire(context.Background(), "shared.example"); err != nil {
		t.Fatalf("another task's breaker leaked: %v", err)
	}
	if _, n := b.Gaps(); n != 0 {
		t.Fatal("another task's gap leaked")
	}
}

func TestHostsPastTheBoundShareOneState(t *testing.T) {
	c, _ := testCtl(t, 100)
	c.b.MaxHosts = 2
	for _, h := range []string{"a", "b", "c", "d"} {
		c.Report(h, Event{Signal: Connected})
	}
	if s := c.Summary(); s.Hosts != 3 {
		t.Fatalf("hosts %d, want 2 tracked + 1 shared", s.Hosts)
	}
}

func TestChangesAreReported(t *testing.T) {
	c, clk := testCtl(t, 100)
	var got []Change
	c.OnChange = func(x Change) { got = append(got, x) }
	clean(c, clk, "h")
	c.ReportHTTP("h", 429, "")
	if len(got) != 2 || got[0].Reason != ReasonSlowStart || got[1].Reason != ReasonHTTP429 || got[1].To != 25 {
		t.Fatalf("changes %+v", got)
	}
}

func TestFailureReason(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.Canceled, ""},
		{errors.New("other"), ""},
		{context.DeadlineExceeded, ReasonTimeout},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, ReasonRefused},
		{&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, ReasonReset},
		{&net.DNSError{IsTimeout: true}, ReasonTimeout},
	}
	for _, tc := range cases {
		if got := FailureReason(tc.err); got != tc.want {
			t.Errorf("FailureReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":                              0,
		"x":                             0,
		"-3":                            0,
		"7":                             7 * time.Second,
		"999999":                        TargetRate.RetryAfterMax,
		"Sun, 11 Oct 2026 12:00:30 GMT": 30 * time.Second,
		"Sun, 11 Oct 2026 11:00:00 GMT": 0,
	}
	for in, want := range cases {
		if got := ParseRetryAfter(in, now); got != want {
			t.Errorf("ParseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

// A path gap (the proxy pool could not carry a connection) marks the host
// without moving its rate, and a gap the host itself caused outranks it.
func TestMarkGapKeepsTheStrongestReasonAndTheRate(t *testing.T) {
	c, _ := testCtl(t, 100)
	before := c.Rate("h")
	c.MarkGap("h", GapProxyUnavailable, "proxy down")
	if gaps, n := c.Gaps(); n != 1 || gaps[0].Reason != GapProxyUnavailable || c.Rate("h") != before {
		t.Fatalf("gaps %+v (%d), rate %v -> %v", gaps, n, before, c.Rate("h"))
	}
	c.ReportHTTP("h", 200, "")
	for range TargetRate.BlockRun {
		c.ReportHTTP("h", 403, "")
	}
	if gaps, _ := c.Gaps(); len(gaps) != 1 || gaps[0].Reason != GapBlocked {
		t.Fatalf("gaps %+v, want blocked", gaps)
	}
	c.MarkGap("h", GapProxyUnavailable, "proxy down")
	if gaps, _ := c.Gaps(); gaps[0].Reason != GapBlocked {
		t.Fatalf("a path gap replaced a block: %+v", gaps)
	}
	c.MarkGap("i", GapRateFloor, "")
	c.MarkGap("i", GapProxyUnavailable, "")
	if gaps, _ := c.Gaps(); len(gaps) != 2 || gaps[1].Reason != GapProxyUnavailable {
		t.Fatalf("gaps %+v", gaps)
	}
}

// A host given up for resets is up and refuses the connections (cause
// reset); one given up for timeouts did not answer (no_answer). A breaker
// that refused a connection while open names the cause of its trip.
func TestBreakerGapNamesTheCause(t *testing.T) {
	for _, tc := range []struct {
		reason, cause string
	}{
		{ReasonReset, GapCauseReset},
		{ReasonTimeout, GapCauseNoAnswer},
		{ReasonRefused, GapCauseRefused},
		{"other", ""},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			c, _ := testCtl(t, 1000)
			for range TargetRate.BreakerFailures {
				c.Report("h", Event{Signal: Failed, Reason: tc.reason})
			}
			if err := c.Acquire(context.Background(), "h"); !errors.Is(err, ErrHostUnavailable) {
				t.Fatalf("breaker not open: %v", err)
			}
			s := c.Summary()
			if s.GapsTotal != 1 || s.Gaps[0].Reason != GapBreakerOpen || s.Gaps[0].Cause != tc.cause {
				t.Fatalf("gaps %+v, want breaker_open with cause %q", s.Gaps, tc.cause)
			}
		})
	}
}
