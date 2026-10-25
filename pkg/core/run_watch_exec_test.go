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
