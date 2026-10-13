package core

import (
	"testing"
	"time"
)

func TestTaskBudgetClamps(t *testing.T) {
	var none *TaskBudget
	if none.Target() != 0 || none.Overrun() != 0 {
		t.Fatal("nil budget must be none")
	}
	cases := []struct {
		b       TaskBudget
		target  time.Duration
		overrun time.Duration
	}{
		{TaskBudget{TargetSeconds: 10, TaskSeconds: 600}, 10 * time.Second, 20 * time.Minute},
		// A hostile or broken payload cannot make the budget absurd.
		{TaskBudget{TargetSeconds: 999999, TaskSeconds: 999999999}, MaxTargetBudget, MaxScanTimeout},
		{TaskBudget{TargetSeconds: -5, TaskSeconds: 1}, 0, MinTaskBudget},
	}
	for _, c := range cases {
		if got := c.b.Target(); got != c.target {
			t.Errorf("%+v Target = %s, want %s", c.b, got, c.target)
		}
		if got := c.b.Overrun(); got != c.overrun {
			t.Errorf("%+v Overrun = %s, want %s", c.b, got, c.overrun)
		}
	}
}

func TestJobTimeoutPrefersTheExplicitTimeout(t *testing.T) {
	b := &TaskBudget{TaskSeconds: 600}
	if got := jobTimeout(300, b); got != 5*time.Minute {
		t.Fatalf("explicit 300s: %s", got)
	}
	if got := jobTimeout(0, b); got != 20*time.Minute {
		t.Fatalf("budget overrun: %s", got)
	}
	if got := jobTimeout(0, nil); got != 0 {
		t.Fatalf("none: %s", got)
	}
	if got := jobTimeout(10*86400, nil); got != MaxScanTimeout {
		t.Fatalf("explicit above the cap: %s", got)
	}
}
