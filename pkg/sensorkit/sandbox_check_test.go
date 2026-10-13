package sensorkit

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
)

// The setup checklist says whether tool runs are network-confined and, when
// not, which cause was detected, so the platform can show the exact fix.
func TestSandboxNetworkCheck(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mode, netMode executor.Mode
		st            executor.Status
		code          string
		status        string
	}{
		{"confined", executor.ModeAuto, executor.ModeAuto, executor.Status{NetworkEnforced: true}, "confined", core.CheckPass},
		{"sandbox off", executor.ModeOff, executor.ModeAuto, executor.Status{}, "sandbox_off", core.CheckWarn},
		{"network off", executor.ModeAuto, executor.ModeOff, executor.Status{}, "off", core.CheckWarn},
		{"runtime seccomp", executor.ModeAuto, executor.ModeAuto,
			executor.Status{NetworkMissing: "probe: unshare user namespace: operation not permitted"}, "userns_blocked", core.CheckWarn},
		{"host restriction", executor.ModeAuto, executor.ModeAuto,
			executor.Status{NetworkMissing: "network: write /proc/self/uid_map: permission denied"}, "userns_restricted", core.CheckWarn},
		{"other", executor.ModeAuto, executor.ModeAuto, executor.Status{NetworkMissing: "no ip binary"}, "unavailable", core.CheckWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &Kit{doc: newDoctor(settingsreg.New(), nil)}
			k.sandboxNetworkCheck(tc.mode, tc.netMode, tc.st)
			c, ok := findCheck(*k.ConfigReport(), CheckSandboxNetwork)
			if !ok || c.Code != tc.code || c.Status != tc.status {
				t.Fatalf("check %+v (found %v), want %s/%s", c, ok, tc.code, tc.status)
			}
			if !tc.st.NetworkEnforced && c.Excerpt != tc.st.NetworkMissing {
				t.Fatalf("excerpt %q, want the detected cause", c.Excerpt)
			}
		})
	}
}
