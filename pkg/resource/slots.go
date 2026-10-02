package resource

import (
	"math"
	"sync"
)

// DefaultHardMaxSlots is the most jobs a sensor runs at once when nothing
// lower is configured.
const DefaultHardMaxSlots = 64

// ComputeSlots is how many jobs fit:
//
//	clamp(min(cap (when > 0), ⌊cpuCores / jobCores⌋, ⌊memBudget / jobMem⌋), 1, hardMax)
//
// A resource that is unknown (0) does not limit. hardMax <= 0 is
// DefaultHardMaxSlots.
func ComputeSlots(capSlots, hardMax int, cpuCores float64, memBudget int64, jobCores float64, jobMem int64) int {
	if hardMax <= 0 {
		hardMax = DefaultHardMaxSlots
	}
	n := hardMax
	if capSlots > 0 {
		n = min(n, capSlots)
	}
	if cpuCores > 0 && jobCores > 0 {
		n = min(n, int(math.Floor(cpuCores/jobCores+1e-9)))
	}
	if memBudget > 0 && jobMem > 0 {
		n = min(n, int(memBudget/jobMem))
	}
	return min(max(n, 1), hardMax)
}

// AIMD is the slot controller's congestion window: halved on a congestion
// signal (OOM kill, timeout, CPU throttling), grown by one slot per window
// of successful jobs. Safe for concurrent use.
type AIMD struct {
	mu    sync.Mutex
	limit float64
	max   int
}

// NewAIMD starts at max (no congestion seen yet).
func NewAIMD(maxSlots int) *AIMD {
	maxSlots = max(maxSlots, 1)
	return &AIMD{limit: float64(maxSlots), max: maxSlots}
}

// Limit is the current window, >= 1.
func (a *AIMD) Limit() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return max(int(a.limit), 1)
}

// Decrease halves the window (multiplicative decrease, never below 1).
func (a *AIMD) Decrease() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.limit = max(math.Floor(a.limit/2), 1)
}

// DecreaseFrom halves the window from the slots actually in use (current),
// when they are below the window: congestion at 4 slots under a window of
// 10 leaves 2, not 5.
func (a *AIMD) DecreaseFrom(current int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if current > 0 {
		a.limit = min(a.limit, float64(current))
	}
	a.limit = max(math.Floor(a.limit/2), 1)
}

// Increase grows the window by 1/window: one slot after a full window of
// successes (additive increase), up to the maximum.
func (a *AIMD) Increase() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.limit = min(a.limit+1/max(a.limit, 1), float64(a.max))
}

// SetMax changes the ceiling (the window is clamped to it).
func (a *AIMD) SetMax(maxSlots int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.max = max(maxSlots, 1)
	a.limit = min(a.limit, float64(a.max))
}
