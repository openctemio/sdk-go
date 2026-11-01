package core_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// deadlineScanner records the job context's deadline and run watch.
type deadlineScanner struct {
	fixedScanner
	deadline time.Time
	has      bool
	watch    core.RunWatch
}

func (s *deadlineScanner) Scan(ctx context.Context, _ string, _ *core.ScanOptions) (*core.ScanResult, error) {
	s.deadline, s.has = ctx.Deadline()
	s.watch = core.RunWatchFrom(ctx)
	r := s.res
	return &r, nil
}

// A scan command carrying the platform's deadline runs under a budget that
// ends a margin before it (the results are then delivered in time), and
// its tool runs get the platform's stall window as their inactivity window.
func TestExecuteScan_DeadlineBoundsTheJob(t *testing.T) {
	deadline := time.Now().Add(100 * time.Minute)
	payload, _ := json.Marshal(map[string]any{"scanner": "dl", "target": "http://203.0.113.10",
		"deadline": deadline.Format(time.RFC3339Nano), "budget": map[string]any{"stall_seconds": 900}})
	sc := &deadlineScanner{fixedScanner: fixedScanner{name: "dl", res: core.ScanResult{ScannerName: "dl"}}}
	exec := core.NewDefaultCommandExecutor(nil)
	exec.AddScanner(sc)
	if _, err := exec.Execute(context.Background(), &core.Command{ID: "c-dl", Type: "scan", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	want := deadline.Add(-core.DeadlineMargin(100 * time.Minute))
	if !sc.has || sc.deadline.Before(want.Add(-5*time.Second)) || sc.deadline.After(want.Add(5*time.Second)) {
		t.Fatalf("job deadline %v (set %v), want about %v", sc.deadline, sc.has, want)
	}
	if sc.watch.Inactivity != 15*time.Minute {
		t.Fatalf("run watch %+v", sc.watch)
	}
}

// Without a deadline nothing changes: no budget appears from nowhere.
func TestExecuteScan_NoDeadlineNoBudget(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"scanner": "dl", "target": "http://203.0.113.10"})
	sc := &deadlineScanner{fixedScanner: fixedScanner{name: "dl", res: core.ScanResult{ScannerName: "dl"}}}
	exec := core.NewDefaultCommandExecutor(nil)
	exec.AddScanner(sc)
	if _, err := exec.Execute(context.Background(), &core.Command{ID: "c-dl", Type: "scan", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if sc.has {
		t.Fatalf("a job without deadline or timeout got deadline %v", sc.deadline)
	}
}

// errOnDoneScanner fails with its context's error when the job ends, as a
// tool runner that settled nothing does.
type errOnDoneScanner struct{ fixedScanner }

func (s *errOnDoneScanner) Scan(ctx context.Context, _ string, _ *core.ScanOptions) (*core.ScanResult, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A job its time budget ended with nothing settled fails as a budget
// time-out (infra.budget_exceeded), not as an unknown tool error.
func TestExecuteScan_BudgetFailureIsClassified(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"scanner": "dl", "target": "http://203.0.113.10", "timeout_seconds": 1})
	exec := core.NewDefaultCommandExecutor(nil)
	exec.AddScanner(&errOnDoneScanner{fixedScanner: fixedScanner{name: "dl"}})
	_, err := exec.Execute(context.Background(), &core.Command{ID: "c-budget", Type: "scan", Payload: payload})
	if err == nil {
		t.Fatal("want a failure")
	}
	if f := core.ClassifyFailure(core.FailureInput{Err: err}); f.Class != core.FailureBudgetExceeded {
		t.Fatalf("class %q (%v)", f.Class, err)
	}
}
