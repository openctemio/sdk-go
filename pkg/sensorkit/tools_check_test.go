package sensorkit

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
)

// "No scanner is available" is a failing check that blocks scans. It is for
// a sensor meant to scan, never for a collector: one that runs its
// collectors on its own schedule with commands off, or one with kit
// collectors only.
func TestToolsAvailableCheckSkipsCollectors(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	for _, tc := range []struct {
		name      string
		commands  bool
		collector bool
		want      string // "" = no check
	}{
		{"scanning sensor without a scanner", true, false, "none"},
		{"collector, commands off", false, false, ""},
		{"collector with kit collectors", true, true, ""},
		{"collector with kit collectors, commands off", false, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, _, _ := baseOptions(t, f)
			opts.DisableCommands = !tc.commands
			k, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			if tc.collector {
				k.AddCollector(nopCollector{})
			}
			k.addScheduledScanners(context.Background(), nil)
			c, ok := findCheck(*k.ConfigReport(), CheckToolsAvailable)
			switch {
			case tc.want == "" && ok:
				t.Fatalf("a collector got the check %s/%s", c.Status, c.Code)
			case tc.want != "" && (!ok || c.Code != tc.want || c.Status != core.CheckFail):
				t.Fatalf("check %+v (present %v), want fail/%s", c, ok, tc.want)
			}
		})
	}
}

type nopCollector struct{}

func (nopCollector) Name() string { return "nop" }
func (nopCollector) Type() string { return "api" }
func (nopCollector) Collect(context.Context, *core.CollectOptions) (*core.CollectResult, error) {
	return &core.CollectResult{}, nil
}
func (nopCollector) TestConnection(context.Context) error { return nil }
