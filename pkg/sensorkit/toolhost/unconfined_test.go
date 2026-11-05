package toolhost

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: where the sandbox is not available (macOS, or a Linux host
// where the launcher does not work) and the operator did not turn it off,
// a tool that contacts its targets (T1 and above) is refused before it
// runs; a passive (T0) tool still runs. SENSOR_SANDBOX=off is the explicit
// acknowledgement; a sandboxed host runs every tier.
func TestUnconfinedSandboxRefusesActiveTools(t *testing.T) {
	unavailable := executor.Status{Backend: "process", Mode: executor.ModeAuto, Missing: []string{"sandbox: available on Linux only"}}
	off := executor.Status{Backend: "process", Mode: executor.ModeOff}
	sandboxed := executor.Status{Backend: "process", Mode: executor.ModeAuto, Sandboxed: true}
	cases := []struct {
		name   string
		st     executor.Status
		tier   tool.Tier
		refuse bool
	}{
		{"unavailable, T0 passive lookup", unavailable, tool.T0, false},
		{"unavailable, T1", unavailable, tool.T1, true},
		{"unavailable, T2", unavailable, tool.T2, true},
		{"unavailable, unknown tier", unavailable, tool.Tier("T9"), true},
		{"acknowledged with off, T1", off, tool.T1, false},
		{"acknowledged with off, T2", off, tool.T2, false},
		{"sandboxed, T2", sandboxed, tool.T2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host{Backend: statusBackend{st: tc.st}}
			e := h.checkUnconfined(tool.Manifest{Name: "scanner", Tier: tc.tier})
			if (e != nil) != tc.refuse {
				t.Fatalf("refusal %+v, want refused %t", e, tc.refuse)
			}
			if e != nil && (e.Class != tool.RefusedByPolicy || !strings.Contains(e.Detail, core.RefusalUnconfinedSandbox) ||
				!strings.Contains(e.Detail, "SENSOR_SANDBOX=off") || !strings.Contains(e.Detail, "Linux only")) {
				t.Fatalf("refusal %+v", e)
			}
		})
	}
}
