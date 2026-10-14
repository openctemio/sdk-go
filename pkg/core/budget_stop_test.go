package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// budgetScanner runs until the job's context ends, then returns what it
// finished, as a tool runner does when the job's time budget stops it
// part-way.
type budgetScanner struct{ fixedScanner }

func (s *budgetScanner) Scan(ctx context.Context, _ string, _ *core.ScanOptions) (*core.ScanResult, error) {
	<-ctx.Done()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, ctx.Err()
	}
	r := s.res
	return &r, nil
}

// ctxPusher records whether the context it pushed under was still live.
type ctxPusher struct {
	pushed  int
	liveCtx bool
}

func (p *ctxPusher) PushFindings(ctx context.Context, _ *ctis.Report) (*core.PushResult, error) {
	p.pushed++
	p.liveCtx = ctx.Err() == nil
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &core.PushResult{}, nil
}

func (p *ctxPusher) PushAssets(context.Context, *ctis.Report) (*core.PushResult, error) {
	return &core.PushResult{}, nil
}

func (p *ctxPusher) SendHeartbeat(context.Context, *core.SensorStatus) error { return nil }

func (p *ctxPusher) TestConnection(context.Context) error { return nil }

func budgetCommand(t *testing.T, scanner string, timeoutSeconds int) *core.Command {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"scanner": scanner, "target": "http://203.0.113.10", "timeout_seconds": timeoutSeconds})
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: "cmd-budget", Type: "scan", Payload: payload}
}

// A run its time budget stopped part-way delivers what it finished: the
// results are pushed under the job's context without the expired budget
// (research note 125 in openctem), never dropped with the budget.
func TestExecuteScan_BudgetStopStillDeliversFinishedResults(t *testing.T) {
	pusher := &ctxPusher{}
	exec := core.NewDefaultCommandExecutor(pusher)
	reg := core.NewParserRegistry()
	reg.Register(&cannedParser{report: *ctis.NewReport()})
	exec.SetParserRegistry(reg)
	exec.AddScanner(&budgetScanner{fixedScanner{name: "slowscan", res: core.ScanResult{ScannerName: "slowscan", RawOutput: []byte("x"),
		Error: "stopped by the job's time budget (results are partial)"}}})
	if _, err := exec.Execute(context.Background(), budgetCommand(t, "slowscan", 1)); err != nil {
		t.Fatalf("a budget-stopped run with results failed: %v", err)
	}
	if pusher.pushed != 1 || !pusher.liveCtx {
		t.Fatalf("pushed %d times, live context %v", pusher.pushed, pusher.liveCtx)
	}
}

// A cancel still ends the job: nothing is pushed for a task the platform
// took back.
func TestExecuteScan_CancelDeliversNothing(t *testing.T) {
	pusher := &ctxPusher{}
	exec := core.NewDefaultCommandExecutor(pusher)
	exec.AddScanner(&budgetScanner{fixedScanner{name: "slowscan", res: core.ScanResult{RawOutput: []byte("x")}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := exec.Execute(ctx, budgetCommand(t, "slowscan", 60)); err == nil {
		t.Fatal("a canceled job succeeded")
	}
	if pusher.pushed != 0 {
		t.Fatalf("pushed %d times after a cancel", pusher.pushed)
	}
}
