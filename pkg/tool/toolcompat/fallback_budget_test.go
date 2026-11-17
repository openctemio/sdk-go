package toolcompat

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/core"
)

// A scan or retest whose caller handed it no budget runs under the
// sensor's pacing level when it is below Standard, never above it.
func TestScanWithoutABudgetKeepsToTheSensorLevel(t *testing.T) {
	t.Cleanup(func() { adapt.SetSensorPacing(adapt.DefaultPacing) })
	adapt.SetSensorPacing(adapt.PacingGentle)
	gentle := adapt.ResolveBudget(adapt.PacingGentle, nil, adapt.BudgetCeiling{})
	for name, opts := range map[string]*core.ScanOptions{"no options": nil, "options without a budget": {}} {
		if b := scanBudget(opts); b.RPS != gentle.RPS || b.Inflight != gentle.Inflight {
			t.Fatalf("%s on a Gentle sensor: %+v", name, b)
		}
	}
	adapt.SetSensorPacing(adapt.PacingFast)
	if b, std := scanBudget(nil), adapt.DefaultBudget(); b.RPS != std.RPS || b.Inflight != std.Inflight {
		t.Fatalf("on a Fast sensor: %+v, want Standard", b)
	}
}
