package adapt

import "testing"

// The budget of a scan or retest whose caller handed it none is never above
// the sensor's pacing level, nor above Standard on a sensor whose operator
// raised the level.
func TestFallbackBudgetNeverAboveTheSensorLevel(t *testing.T) {
	prev := sensorPacing.Load()
	t.Cleanup(func() { sensorPacing.Store(prev) })
	std := DefaultBudget()
	sensorPacing.Store(nil)
	if got := FallbackBudget(); got.RPS != std.RPS || got.Inflight != std.Inflight {
		t.Fatalf("no level set: %+v, want Standard", got)
	}
	gentle := ResolveBudget(PacingGentle, nil, BudgetCeiling{})
	SetSensorPacing(PacingGentle)
	if got := FallbackBudget(); got.RPS != gentle.RPS || got.Inflight != gentle.Inflight {
		t.Fatalf("a Gentle sensor: %+v, want %d/s and %d", got, gentle.RPS, gentle.Inflight)
	}
	SetSensorPacing(PacingFast)
	if got := FallbackBudget(); got.RPS != std.RPS || got.Inflight != std.Inflight {
		t.Fatalf("a Fast sensor: %+v, want Standard", got)
	}
}

// The sensor's own bound (host_busy) is the weakest gap reason: anything
// the host did itself replaces it, and it never replaces one of those.
func TestHostBusyGapIsTheWeakest(t *testing.T) {
	c := NewHostRate(20)
	c.MarkGap("a.example.com", GapHostBusy, GapDetailHostBusy)
	c.MarkGap("a.example.com", GapRateFloor, "pushed back")
	c.MarkGap("b.example.com", GapRateFloor, "pushed back")
	c.MarkGap("b.example.com", GapHostBusy, GapDetailHostBusy)
	c.MarkGap("c.example.com", GapHostBusy, GapDetailHostBusy)
	got := map[string]string{}
	gaps, _ := c.Gaps()
	for _, g := range gaps {
		got[g.Host] = g.Reason
	}
	if got["a.example.com"] != GapRateFloor || got["b.example.com"] != GapRateFloor || got["c.example.com"] != GapHostBusy {
		t.Fatalf("gaps %v", got)
	}
}
