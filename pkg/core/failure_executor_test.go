package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/mocks"
)

// failingScanner fails its scan, returning what it saw until then.
type failingScanner struct {
	fixedScanner
	err error
}

func (s *failingScanner) Scan(context.Context, string, *core.ScanOptions) (*core.ScanResult, error) {
	r := s.res
	return &r, s.err
}

// A scan that fails tells which targets it settled first: a host whose
// coverage gap shows an edge answered is on the target's side, the others are
// unfinished (never done), and the error is tagged with the run stage.
func TestExecuteScan_FailureCarriesTargetOutcomes(t *testing.T) {
	exec := core.NewDefaultCommandExecutor(&mocks.MockPusher{})
	gaps := []adapt.Gap{
		{Host: "203.0.113.1", Reason: adapt.GapBlocked, Edge: "blocked"},
		{Host: "203.0.113.2", Reason: adapt.GapProxyUnavailable},
	}
	sc := &failingScanner{fixedScanner: fixedScanner{name: "fakescan", res: core.ScanResult{ScannerName: "fakescan", CoverageGaps: gaps}},
		err: errors.New("tool died")}
	exec.AddScanner(sc)
	payload, _ := json.Marshal(map[string]any{
		"scanner": "fakescan", "outcome_revision": 2,
		"targets": []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"},
	})
	res, err := exec.Execute(context.Background(), &core.Command{ID: "c1", Type: "scan", Payload: payload})
	if err == nil || core.StageOf(err) != core.StageRun {
		t.Fatalf("err %v stage %q", err, core.StageOf(err))
	}
	if res == nil {
		t.Fatal("a failed scan returned no per-target results")
	}
	by := map[string]outcome.Target{}
	for _, o := range res.TargetOutcomes {
		by[o.Target] = o
	}
	if o := by["203.0.113.1"]; o.State != outcome.Failed || o.Class != outcome.EdgeBlocked || o.Side() != outcome.CauseTarget {
		t.Errorf("edge-blocked target: %+v", o)
	}
	if o := by["203.0.113.2"]; o.State != outcome.Failed || o.Class != outcome.SensorNetworkFault || o.Side() != outcome.CauseSensor {
		t.Errorf("proxy-pool target: %+v", o)
	}
	if o := by["203.0.113.3"]; o.State != outcome.Unfinished {
		t.Errorf("unreached target: %+v, want unfinished", o)
	}
	for _, o := range res.TargetOutcomes {
		if o.State == outcome.Done {
			t.Errorf("a failed scan marked %s done", o.Target)
		}
	}
}

func (s *failingScanner) ScanTargets(ctx context.Context, _ []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.Scan(ctx, "", opts)
}
