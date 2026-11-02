package adapt

import (
	"context"
	"testing"
	"time"
)

type paceClock struct{ t time.Time }

func (c *paceClock) now() time.Time      { return c.t }
func (c *paceClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newTestPacer(ceiling float64) (*SourcePacer, *paceClock) {
	c := &paceClock{t: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)}
	p := NewSourcePacer(ceiling)
	p.now = c.now
	return p, c
}

// paceWindow feeds one window of answers with the given latency and closes it.
func paceWindow(p *SourcePacer, c *paceClock, n int, latency time.Duration) {
	for range n {
		p.Observe(SourceAnswered, latency, 0)
	}
	c.add(SourcePace.Window)
	p.Observe(SourceAnswered, latency, 0) // opens the next window, closing this one
}

func TestSourcePacerStartsAtHalfAndClimbsToCeiling(t *testing.T) {
	p, c := newTestPacer(5)
	if got := p.Rate(); got != 2.5 {
		t.Fatalf("start rate = %v, want 2.5 (half the ceiling)", got)
	}
	p.Observe(SourceAnswered, 50*time.Millisecond, 0) // opens the first window
	for range 10 {
		paceWindow(p, c, 5, 50*time.Millisecond)
	}
	if got := p.Rate(); got != 5 {
		t.Errorf("rate after clean windows = %v, want the ceiling 5", got)
	}
}

// A server three times slower than its own normal is under load: the rate
// halves before it errors.
func TestSourcePacerSlowsOnLatency(t *testing.T) {
	p, c := newTestPacer(5)
	p.Observe(SourceAnswered, 100*time.Millisecond, 0)
	for range 10 {
		paceWindow(p, c, 5, 100*time.Millisecond)
	}
	before := p.Rate()
	paceWindow(p, c, 5, 900*time.Millisecond) // 9x the baseline
	if got := p.Rate(); got != before*SourcePace.DecreaseFactor {
		t.Errorf("rate after a slow window = %v, want %v", got, before*SourcePace.DecreaseFactor)
	}
}

// Fast answers never count as slow, whatever their ratio.
func TestSourcePacerLatencyFloor(t *testing.T) {
	p, c := newTestPacer(5)
	p.Observe(SourceAnswered, 10*time.Millisecond, 0)
	paceWindow(p, c, 5, 10*time.Millisecond)
	r := p.Rate()
	paceWindow(p, c, 5, 200*time.Millisecond) // 20x, but under 250ms
	if p.Rate() < r {
		t.Errorf("rate fell on fast answers: %v -> %v", r, p.Rate())
	}
}

// Busy and failed answers halve at once, once per window, down to the floor.
func TestSourcePacerBusyAndFloor(t *testing.T) {
	p, c := newTestPacer(5)
	p.Observe(SourceBusy, 0, 0)
	p.Observe(SourceFailed, 0, 0) // same window: no second decrease
	if got := p.Rate(); got != 1.25 {
		t.Errorf("rate = %v, want 1.25", got)
	}
	for range 20 {
		c.add(SourcePace.Window)
		p.Observe(SourceFailed, 0, 0)
	}
	if got := p.Rate(); got != SourcePace.Floor {
		t.Errorf("rate = %v, want the floor %v", got, SourcePace.Floor)
	}
}

// A Retry-After holds requests (capped), and Wait honors ctx.
func TestSourcePacerRetryAfter(t *testing.T) {
	p, c := newTestPacer(5)
	p.Observe(SourceBusy, 0, time.Hour)
	if got := p.notBefore.Sub(c.now()); got != SourcePace.RetryAfterMax {
		t.Errorf("hold = %v, want the cap %v", got, SourcePace.RetryAfterMax)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Wait(ctx); err == nil {
		t.Error("Wait returned during a Retry-After")
	}
}

// A source that became slower for good becomes the new normal: the rate
// recovers instead of staying at the floor.
func TestSourcePacerBaselineDrifts(t *testing.T) {
	p, c := newTestPacer(5)
	p.Observe(SourceAnswered, 100*time.Millisecond, 0)
	paceWindow(p, c, 5, 100*time.Millisecond)
	for range 60 {
		paceWindow(p, c, 5, 600*time.Millisecond)
	}
	if got := p.Rate(); got <= SourcePace.Floor {
		t.Errorf("rate stuck at %v on a source that is slower for good", got)
	}
}

func TestSourcePacerCeilingBelowFloor(t *testing.T) {
	p, _ := newTestPacer(0.1)
	if p.Rate() != 0.1 || p.floor != 0.1 {
		t.Errorf("rate %v floor %v, want both 0.1 (the ceiling)", p.Rate(), p.floor)
	}
	if NewSourcePacer(0).Ceiling() != SourcePace.DefaultCeiling {
		t.Error("no default ceiling")
	}
}
