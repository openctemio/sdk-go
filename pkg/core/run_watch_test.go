package core

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// The platform's deadline shortens the job's budget so it ends a margin
// before it; it never lengthens one, and a job always gets a floor.
func TestCapToDeadline(t *testing.T) {
	now := time.Date(2026, 10, 25, 14, 45, 0, 0, time.UTC)
	cases := []struct {
		name     string
		timeout  time.Duration
		deadline time.Time
		want     time.Duration
	}{
		{"no deadline keeps the timeout", time.Hour, time.Time{}, time.Hour},
		{"no deadline, no timeout", 0, time.Time{}, 0},
		// The incident run: 1h42m left; a tenth is 10m12s, capped to 10m.
		{"deadline caps an unbounded job", 0, now.Add(102 * time.Minute), 92 * time.Minute},
		{"deadline shorter than the timeout", 4 * time.Hour, now.Add(30 * time.Minute), 27 * time.Minute},
		{"deadline later than the timeout keeps it", 10 * time.Minute, now.Add(2 * time.Hour), 10 * time.Minute},
		{"close deadline keeps the minimum margin", 0, now.Add(5 * time.Minute), 4 * time.Minute},
		{"passed deadline still gets the floor", 0, now.Add(-time.Minute), MinDeadlineBudget},
	}
	for _, c := range cases {
		if got := capToDeadline(c.timeout, c.deadline, now); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// The platform's stall window becomes the inactivity window, clamped so a
// payload can neither make it absurdly short nor unbounded.
func TestRunWatchForBudget(t *testing.T) {
	if w := runWatchFor(nil); w != (RunWatch{}) {
		t.Fatalf("nil budget: %+v", w)
	}
	if w := runWatchFor(&TaskBudget{StallSeconds: 1}); w.Inactivity != MinInactivity {
		t.Fatalf("short stall: %+v", w)
	}
	if w := runWatchFor(&TaskBudget{StallSeconds: 1 << 30}); w.Inactivity != MaxInactivity {
		t.Fatalf("long stall: %+v", w)
	}
	if w := runWatchFor(&TaskBudget{StallSeconds: 900}); w.Inactivity != 15*time.Minute {
		t.Fatalf("stall: %+v", w)
	}
	if e := (RunWatch{FinishGrace: -1}).Effective(); e.FinishGrace != 0 || e.Inactivity != DefaultInactivity {
		t.Fatalf("effective: %+v", e)
	}
}

func TestProcessCPUReadsThisProcess(t *testing.T) {
	var c ProcessCPU
	c.Track(os.Getpid())
	end := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(end) { //nolint:revive // burn CPU
	}
	got, ok := c.Read()
	if runtime.GOOS != "linux" {
		if ok {
			t.Fatal("CPU read where it is not supported")
		}
		return
	}
	if !ok || got <= 0 {
		t.Fatalf("cpu %s ok %v", got, ok)
	}
}
