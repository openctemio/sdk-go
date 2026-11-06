package toolhost

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: where the host has no sandbox (it is Linux only: macOS,
// Windows) and the operator did not turn it off,
// a tool that contacts its targets (T1 and above) is refused before it
// runs; a passive (T0) tool still runs. SENSOR_SANDBOX=off is the explicit
// acknowledgement; a sandboxed host runs every tier.
func TestUnconfinedSandboxRefusesActiveTools(t *testing.T) {
	unavailable := executor.Status{Backend: "process", Mode: executor.ModeAuto, NoSandboxOnHost: true, Missing: []string{"sandbox: available on Linux only"}}
	off := executor.Status{Backend: "process", Mode: executor.ModeOff}
	sandboxed := executor.Status{Backend: "process", Mode: executor.ModeAuto, Sandboxed: true, Landlock: 4}
	// Linux host, launcher failed: tools would run bare as the sensor's user.
	launcher := executor.Status{Backend: "process", Mode: executor.ModeAuto, Missing: []string{"sandbox: Linux only"}}
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
		{"launcher failed, T0 passive lookup", launcher, tool.T0, false},
		{"launcher failed, T1", launcher, tool.T1, true},
		{"launcher failed, off still runs T1", off, tool.T1, false},
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

// SECURITY (research/452 T1): with a launcher that fails in auto mode, the
// real process backend refuses an active tool and lets a passive one pass;
// off runs both.
func TestBrokenLauncherInAutoRefusesActiveTools(t *testing.T) {
	auto, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeAuto, Launcher: "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	off, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		b       executor.Backend
		tier    tool.Tier
		refused bool
	}{
		{"auto T0", auto, tool.T0, false},
		{"auto T1", auto, tool.T1, true},
		{"auto T2", auto, tool.T2, true},
		{"off T0", off, tool.T0, false},
		{"off T2", off, tool.T2, false},
	} {
		h := &Host{Backend: tc.b}
		e := h.checkUnconfined(tool.Manifest{Name: "scanner", Tier: tc.tier})
		if (e != nil) != tc.refused {
			t.Errorf("%s: refusal %+v, want refused %t", tc.name, e, tc.refused)
		}
	}
	if _, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, Launcher: "/bin/true"}); err == nil {
		t.Error("required mode started with a broken launcher")
	}
}
