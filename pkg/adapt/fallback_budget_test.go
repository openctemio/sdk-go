package adapt

import "testing"

// The budget of a scan or retest whose caller handed it none is never above
// the sensor's pacing level, nor above Standard on a sensor whose operator
// raised the level.
func TestFallbackBudgetNeverAboveTheSensorLevel(t *testing.T) {
	prev, prevCeiling := sensorPacing.Load(), sensorCeiling.Load()
	t.Cleanup(func() { sensorPacing.Store(prev); sensorCeiling.Store(prevCeiling) })
	std := DefaultBudget()
	sensorPacing.Store(nil)
	sensorCeiling.Store(nil)
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

// The fallback budget also stays under the operator's per-host ceiling
// (the local policy's rate.max_host_rps and rate.max_host_inflight): the
// lowest of the sensor's level, Standard and that ceiling, number by number.
func TestFallbackBudgetRespectsTheOperatorCeiling(t *testing.T) {
	prevLevel, prevCeiling := sensorPacing.Load(), sensorCeiling.Load()
	t.Cleanup(func() { sensorPacing.Store(prevLevel); sensorCeiling.Store(prevCeiling) })
	std := DefaultBudget()
	gentle := ResolveBudget(PacingGentle, nil, BudgetCeiling{})

	SetSensorPacing(PacingFast)
	SetSensorHostCeiling(BudgetCeiling{RPS: 3, Inflight: 1})
	if got := FallbackBudget(); got.RPS != 3 || got.Inflight != 1 {
		t.Fatalf("a Fast sensor under a 3/s, 1 ceiling: %+v", got)
	}
	// One number set: the other stays at the lowest of the level and Standard.
	SetSensorHostCeiling(BudgetCeiling{RPS: 2})
	if got := FallbackBudget(); got.RPS != 2 || got.Inflight != std.Inflight {
		t.Fatalf("a rate-only ceiling: %+v, want 2/s and %d", got, std.Inflight)
	}
	// A ceiling above the level and Standard changes nothing.
	SetSensorPacing(PacingGentle)
	SetSensorHostCeiling(BudgetCeiling{RPS: HardCeilingRPS, Inflight: HardCeilingInflight})
	if got := FallbackBudget(); got.RPS != gentle.RPS || got.Inflight != gentle.Inflight {
		t.Fatalf("a Gentle sensor under a high ceiling: %+v, want Gentle", got)
	}
	// A ceiling under Gentle wins over it.
	SetSensorHostCeiling(BudgetCeiling{RPS: 1, Inflight: 1})
	if got := FallbackBudget(); got.RPS != 1 || got.Inflight != 1 {
		t.Fatalf("a Gentle sensor under a 1/s, 1 ceiling: %+v", got)
	}
	// Removed (no local policy): the level and Standard only.
	SetSensorHostCeiling(BudgetCeiling{})
	SetSensorPacing(PacingFast)
	if got := FallbackBudget(); got.RPS != std.RPS || got.Inflight != std.Inflight {
		t.Fatalf("no ceiling: %+v, want Standard", got)
	}
}

// The sensor's own bound (slots_full) is the weakest gap reason: anything
// the host did itself replaces it, and it never replaces one of those.
func TestSlotsFullGapIsTheWeakest(t *testing.T) {
	c := NewHostRate(20)
	c.MarkGap("a.example.com", GapSlotsFull, GapDetailSlotsFull)
	c.MarkGap("a.example.com", GapRateFloor, "pushed back")
	c.MarkGap("b.example.com", GapRateFloor, "pushed back")
	c.MarkGap("b.example.com", GapSlotsFull, GapDetailSlotsFull)
	c.MarkGap("c.example.com", GapSlotsFull, GapDetailSlotsFull)
	got := map[string]string{}
	gaps, _ := c.Gaps()
	for _, g := range gaps {
		got[g.Host] = g.Reason
	}
	if got["a.example.com"] != GapRateFloor || got["b.example.com"] != GapRateFloor || got["c.example.com"] != GapSlotsFull {
		t.Fatalf("gaps %v", got)
	}
}
