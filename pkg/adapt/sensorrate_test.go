package adapt

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/openctemio/ctis/edgeprotect"
)

// sharedRig is a SensorRate and task controllers on one fake clock; the
// shared rate's waits advance the clock instead of sleeping. Task ceilings
// are high so a task's own pacing never holds a test.
type sharedRig struct {
	t     *testing.T
	clk   time.Time
	s     *SensorRate
	slept time.Duration
}

func newSharedRig(t *testing.T) *sharedRig {
	t.Helper()
	r := &sharedRig{t: t, clk: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	r.s = NewSensorRate()
	r.s.now = func() time.Time { return r.clk }
	r.s.sleep = func(_ context.Context, d time.Duration) error {
		r.slept += d
		r.clk = r.clk.Add(d)
		return nil
	}
	return r
}

func (r *sharedRig) task(tenant string) *HostRate {
	c := NewHostRate(100000)
	c.now = func() time.Time { return r.clk }
	c.jitter = func() float64 { return 0.5 }
	c.Share(r.s, tenant)
	return c
}

func (r *sharedRig) advance(d time.Duration) { r.clk = r.clk.Add(d) }

// setHostRate pins host's sensor-wide rate (after a first admission).
func (r *sharedRig) setHostRate(host string, v float64) {
	r.s.mu.Lock()
	r.s.hosts[host].rate = v
	r.s.mu.Unlock()
}

func (r *sharedRig) shareOf(tenant, host string) float64 {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return float64(r.s.hosts[host].tenants[tenant].lim.Limit())
}

var cfBlock = edgeprotect.Verdict{Vendor: edgeprotect.Cloudflare, State: edgeprotect.Blocked, Signal: "cloudflare.block-page"}

func TestSharedRateTwoTasksShareTheHostRate(t *testing.T) {
	r := newSharedRig(t)
	a, b := r.task("t1"), r.task("t1")
	ctx := context.Background()
	if err := a.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	r.setHostRate("h", 10)
	r.slept = 0
	// Ten more connections, alternating between the two tasks (the first
	// connection took the one token): one host rate of 10/s paces them
	// all 0.1 s apart, where two separate rates would have let them
	// through twice as fast.
	for i := range 10 {
		c := a
		if i%2 == 1 {
			c = b
		}
		if err := c.Acquire(ctx, "h"); err != nil {
			t.Fatal(err)
		}
	}
	if want := time.Second; math.Abs(float64(r.slept-want)) > float64(time.Millisecond) {
		t.Fatalf("ten connections of two tasks waited %v in all, want %v (one shared 10/s)", r.slept, want)
	}
	// Another host is paced on its own.
	r.slept = 0
	if err := b.Acquire(ctx, "other"); err != nil || r.slept != 0 {
		t.Fatalf("first connection to another host: err %v, waited %v", err, r.slept)
	}
}

func TestSharedRateCongestionSlowsEveryTaskOnTheHost(t *testing.T) {
	r := newSharedRig(t)
	a, b := r.task("t1"), r.task("t1")
	ctx := context.Background()
	if err := a.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	r.setHostRate("h", 40)
	a.ReportHTTP("h", 429, "")
	if err := b.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	if got := r.shareOf("t1", "h"); got != 20 {
		t.Fatalf("after one task's 429 the host's rate for every task = %v, want 20", got)
	}
}

func TestSharedRetryAfterHoldsEveryTaskOfTheTenantOnly(t *testing.T) {
	r := newSharedRig(t)
	a, b, other := r.task("t1"), r.task("t1"), r.task("t2")
	ctx := context.Background()
	for _, c := range []*HostRate{a, b, other} {
		if err := c.Acquire(ctx, "h"); err != nil {
			t.Fatal(err)
		}
	}
	// One task gets a long Retry-After: the other task of the tenant
	// honors it (it is refused until it passes and the host is a gap of
	// its own), a task of another tenant does not learn it.
	a.ReportHTTP("h", 429, "120")
	if err := b.Acquire(ctx, "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("other task of the tenant during the Retry-After: %v, want ErrHostUnavailable", err)
	}
	if gaps, _ := b.Gaps(); len(gaps) != 1 || gaps[0].Reason != GapRateFloor {
		t.Fatalf("gaps of the held task %+v, want h rate_floor", gaps)
	}
	if err := other.Acquire(ctx, "h"); err != nil {
		t.Fatalf("task of another tenant was held by the first tenant's Retry-After: %v", err)
	}
	r.advance(121 * time.Second)
	if err := b.Acquire(ctx, "h"); err != nil {
		t.Fatalf("after the Retry-After: %v", err)
	}
}

func TestSharedEdgeBlockCoolsTheTargetDownForTheTenant(t *testing.T) {
	r := newSharedRig(t)
	a, b, other := r.task("t1"), r.task("t1"), r.task("t2")
	ctx := context.Background()
	for _, c := range []*HostRate{a, b, other} {
		if err := c.Acquire(ctx, "h"); err != nil {
			t.Fatal(err)
		}
	}
	a.ReportResponse("h", 403, "", cfBlock)
	start := r.clk
	if got := r.s.Cooldown("t1", "h"); !got.Equal(start.Add(15 * time.Minute)) {
		t.Fatalf("cooldown ends %v, want 15 min after the block", got.Sub(start))
	}
	// Another task of the tenant is refused before it dials: no endpoint,
	// direct or proxied, is tried for the host. Its gap names the edge.
	err := b.Acquire(ctx, "h")
	if !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("other task during the cooldown: %v, want ErrHostUnavailable", err)
	}
	gaps, _ := b.Gaps()
	if len(gaps) != 1 || gaps[0].Reason != GapBlocked || gaps[0].Edge != "blocked" || gaps[0].Vendor != edgeprotect.Cloudflare {
		t.Fatalf("gap of the cooled-down task %+v, want h blocked by cloudflare", gaps)
	}
	// Another tenant's task is not refused.
	if err := other.Acquire(ctx, "h"); err != nil {
		t.Fatalf("another tenant's task was refused by the first tenant's cooldown: %v", err)
	}
	if !r.s.Cooldown("t2", "h").IsZero() {
		t.Fatal("the cooldown reached another tenant")
	}
	// Answers of connections opened before do not lengthen it.
	r.advance(time.Minute)
	b.ReportResponse("h", 403, "", cfBlock)
	if got := r.s.Cooldown("t1", "h"); !got.Equal(start.Add(15 * time.Minute)) {
		t.Fatalf("a block during the cooldown moved its end to %v", got.Sub(start))
	}
	r.advance(14*time.Minute + time.Second)
	if err := b.Acquire(ctx, "h"); err != nil {
		t.Fatalf("after the cooldown: %v", err)
	}
}

func TestSharedCooldownDoublesUpToSixHoursAndResetsOnAnAnswer(t *testing.T) {
	r := newSharedRig(t)
	a := r.task("t1")
	ctx := context.Background()
	if err := a.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour, 6 * time.Hour}
	for i, w := range want {
		r.s.block("t1", "h", cfBlock, "")
		got := r.s.Cooldown("t1", "h").Sub(r.clk)
		if got != w {
			t.Fatalf("block %d: cooldown %v, want %v", i+1, got, w)
		}
		r.advance(got)
	}
	// The host answers normally after a cooldown: the next block starts
	// from the base again.
	r.s.answered("t1", "h")
	r.s.block("t1", "h", cfBlock, "")
	if got := r.s.Cooldown("t1", "h").Sub(r.clk); got != 15*time.Minute {
		t.Fatalf("block after a normal answer: cooldown %v, want 15m", got)
	}
}

func TestSharedRunOf403CoolsTheTargetDown(t *testing.T) {
	r := newSharedRig(t)
	a, b := r.task("t1"), r.task("t1")
	ctx := context.Background()
	for _, c := range []*HostRate{a, b} {
		if err := c.Acquire(ctx, "h"); err != nil {
			t.Fatal(err)
		}
	}
	a.ReportHTTP("h", 200, "")
	for range TargetRate.BlockRun {
		a.ReportHTTP("h", 403, "")
	}
	if err := b.Acquire(ctx, "h"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("after a run of 403s: %v, want ErrHostUnavailable", err)
	}
	if gaps, _ := b.Gaps(); len(gaps) != 1 || gaps[0].Reason != GapBlocked || gaps[0].Edge != "" {
		t.Fatalf("gap %+v, want h blocked without an edge", gaps)
	}
}

func TestSharedFairShareBetweenTenants(t *testing.T) {
	r := newSharedRig(t)
	a, b := r.task("t1"), r.task("t2")
	ctx := context.Background()
	if err := a.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	r.setHostRate("h", 40)
	if err := a.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	if got := r.shareOf("t1", "h"); got != 40 {
		t.Fatalf("one tenant alone gets %v, want the whole 40", got)
	}
	if err := b.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	if a1, b1 := r.shareOf("t1", "h"), r.shareOf("t2", "h"); a1 != 20 || b1 != 20 {
		t.Fatalf("two tenants get %v and %v, want 20 each", a1, b1)
	}
	// Tenant 2 stops: tenant 1 gets the whole rate back.
	r.advance(SharedRate.ShareIdle + time.Second)
	if err := a.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	if got := r.shareOf("t1", "h"); got != 40 {
		t.Fatalf("after tenant 2 went idle tenant 1 gets %v, want 40", got)
	}
	// Behavior, not just the limit: with both active, 4 more connections
	// of one tenant at 20/s take 200 ms, whatever the other tenant does.
	if err := b.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	r.slept = 0
	for range 4 {
		if err := a.Acquire(ctx, "h"); err != nil {
			t.Fatal(err)
		}
	}
	if want := 200 * time.Millisecond; math.Abs(float64(r.slept-want)) > float64(time.Millisecond) {
		t.Fatalf("4 connections of one tenant waited %v, want %v (its half of 40/s)", r.slept, want)
	}
}

func TestSharedRateNeverAboveTheHighestTaskCeiling(t *testing.T) {
	r := newSharedRig(t)
	low := NewHostRate(5)
	low.now = func() time.Time { return r.clk }
	low.Share(r.s, "t1")
	if _, nb := r.s.admit("t1", "h", 5); !nb.IsZero() {
		t.Fatal("unexpected Retry-After")
	}
	for range 10 {
		r.s.answered("t1", "h")
		r.advance(TargetRate.Window)
		r.s.admit("t1", "h", 5)
	}
	if got := r.shareOf("t1", "h"); got > 5 {
		t.Fatalf("host rate %v above the only task's ceiling 5", got)
	}
}

func TestSharedTenantsPastTheBoundPaceAlone(t *testing.T) {
	r := newSharedRig(t)
	r.s.sb.MaxTenantsPerHost = 1
	a, b := r.task("t1"), r.task("t2")
	ctx := context.Background()
	if err := a.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	a.ReportResponse("h", 403, "", cfBlock)
	// t2 does not fit: it shares nothing, in particular not t1's cooldown.
	if err := b.Acquire(ctx, "h"); err != nil {
		t.Fatalf("tenant past the bound: %v", err)
	}
	b.ReportResponse("h", 403, "", cfBlock)
	if !r.s.Cooldown("t2", "h").IsZero() {
		t.Fatal("a tenant past the bound got shared state")
	}
}

func TestSharedSweepForgetsIdleHosts(t *testing.T) {
	r := newSharedRig(t)
	r.s.admit("t1", "idle", 100)
	r.s.admit("t1", "blocked", 100)
	r.s.block("t1", "blocked", cfBlock, "")
	r.advance(SharedRate.HostIdle + 2*time.Minute)
	r.s.admit("t1", "fresh", 100)
	r.s.mu.Lock()
	_, idle := r.s.hosts["idle"]
	_, blocked := r.s.hosts["blocked"]
	r.s.mu.Unlock()
	if idle {
		t.Fatal("an idle host was kept")
	}
	if !blocked {
		t.Fatal("a host whose cooldown memory is still needed was dropped")
	}
}

func TestSharedWaitHonorsCancellation(t *testing.T) {
	r := newSharedRig(t)
	r.s.sleep = sleepCtx
	r.s.admit("t1", "h", 100)
	r.setHostRate("h", 1)
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.s.wait(ctx, "t1", "h"); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := r.s.wait(ctx, "t1", "h"); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait on a canceled context: %v", err)
	}
}

func TestProcessIsOneSensorRate(t *testing.T) {
	a, b := Process(), Process()
	if a != b || a == nil {
		t.Fatal("Process is not one SensorRate per process")
	}
}
