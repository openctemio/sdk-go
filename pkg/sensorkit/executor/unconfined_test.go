package executor

import (
	"strings"
	"testing"
)

func TestStatusUnconfined(t *testing.T) {
	for _, tc := range []struct {
		st      Status
		want    string
		refuses bool
	}{
		{Status{Mode: ModeAuto, Sandboxed: true, Landlock: 4}, "", false},
		{Status{Mode: ModeRequired, Sandboxed: true, Landlock: 4}, "", false},
		{Status{Mode: ModeAuto, NoSandboxOnHost: true}, UnconfinedRefused, true},
		// A Linux host where the sandbox could not start (launcher failure,
		// user namespaces blocked): active tools are refused, not run bare.
		{Status{Mode: ModeAuto, Missing: []string{"launcher: probe failed"}}, UnconfinedRefused, true},
		// Sandboxed but Landlock missing: the key paths are not denied.
		{Status{Mode: ModeAuto, Sandboxed: true, Missing: []string{"landlock: unsupported"}}, UnconfinedRefused, true},
		// Network confinement missing alone: the key is still protected.
		{Status{Mode: ModeAuto, Sandboxed: true, Landlock: 4, NetworkMissing: "userns blocked"}, "", false},
		{Status{Mode: ModeAuto, Sandboxed: true, Landlock: 4}, "", false},
		{Status{Mode: ModeOff}, UnconfinedAcknowledged, false},
		{Status{}, "", false},
	} {
		if got := tc.st.Unconfined(); got != tc.want || tc.st.RefusesActiveTools() != tc.refuses {
			t.Errorf("%+v: %q %t, want %q %t", tc.st, got, tc.st.RefusesActiveTools(), tc.want, tc.refuses)
		}
	}
	// The default backend (nothing installed: tests, one-shot runs) is off,
	// so it refuses nothing.
	if Current().Status().RefusesActiveTools() {
		t.Fatal("the default backend refuses active tools")
	}
}

func TestFailedControls(t *testing.T) {
	for _, tc := range []struct {
		st   Status
		want string
	}{
		{Status{Mode: ModeAuto, Missing: []string{"launcher: x"}}, "launcher"},
		{Status{Mode: ModeAuto, NoSandboxOnHost: true}, "launcher,os"},
		{Status{Mode: ModeAuto, Sandboxed: true}, "landlock"},
		{Status{Mode: ModeOff}, ""},
		{Status{Mode: ModeAuto, Sandboxed: true, Landlock: 3}, ""},
	} {
		if got := strings.Join(tc.st.FailedControls(), ","); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.st, got, tc.want)
		}
	}
}
