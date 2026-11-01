package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// A job its own time budget ended is classified as a budget time-out, not
// as an unknown tool failure; a deadline that had passed before the job
// started says so; a cancel and other errors keep their own class.
func TestBudgetClassed(t *testing.T) {
	now := time.Now()
	expired := func() (context.Context, context.CancelFunc) {
		return context.WithDeadline(context.Background(), now.Add(-time.Second))
	}

	t.Run("budget ran out", func(t *testing.T) {
		job, cancel := expired()
		defer cancel()
		err := budgetClassed(context.DeadlineExceeded, job, context.Background(), now.Add(time.Hour), now)
		f := ClassifyFailure(FailureInput{Err: fmt.Errorf("scan failed: %w", err)})
		if f.Class != FailureBudgetExceeded || f.Evidence.Reason != "" {
			t.Fatalf("class %q reason %q", f.Class, f.Evidence.Reason)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("the tool's error must stay reachable")
		}
		if f.ErrorCode() != "TIMEOUT" {
			t.Fatalf("error code %q", f.ErrorCode())
		}
	})

	t.Run("deadline passed before the start", func(t *testing.T) {
		job, cancel := expired()
		defer cancel()
		err := budgetClassed(errors.New("signal: killed"), job, context.Background(), now.Add(-10*time.Minute), now)
		f := ClassifyFailure(FailureInput{Err: err})
		if f.Class != FailureBudgetExceeded || f.Evidence.Reason != ReasonDeadlinePassed {
			t.Fatalf("class %q reason %q", f.Class, f.Evidence.Reason)
		}
	})

	t.Run("cancel is not the budget", func(t *testing.T) {
		parent, cancelParent := context.WithCancel(context.Background())
		cancelParent()
		job, cancel := context.WithDeadline(parent, now.Add(-time.Second))
		defer cancel()
		err := budgetClassed(context.Canceled, job, parent, time.Time{}, now)
		if f := ClassifyFailure(FailureInput{Err: err}); f.Class != FailureUnknown {
			t.Fatalf("a canceled job classified %q", f.Class)
		}
	})

	t.Run("live job keeps the error", func(t *testing.T) {
		boom := errors.New("boom")
		if got := budgetClassed(boom, context.Background(), context.Background(), time.Time{}, now); got != boom {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("not wrapped twice", func(t *testing.T) {
		job, cancel := expired()
		defer cancel()
		once := budgetClassed(context.DeadlineExceeded, job, context.Background(), time.Time{}, now)
		if twice := budgetClassed(once, job, context.Background(), time.Time{}, now); twice != once {
			t.Fatal("wrapped twice")
		}
	})
}
