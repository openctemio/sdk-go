package sensorkit

import (
	"os"
	"path/filepath"
	"strings"
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
			withProc(t, nil)
			k := &Kit{doc: newDoctor(settingsreg.New(), nil)}
			k.sandboxNetworkCheck(tc.mode, tc.netMode, tc.st)
			c, ok := findCheck(*k.ConfigReport(), CheckSandboxNetwork)
			if !ok || c.Code != tc.code || c.Status != tc.status {
				t.Fatalf("check %+v (found %v), want %s/%s", c, ok, tc.code, tc.status)
			}
			if !tc.st.NetworkEnforced && c.Excerpt != tc.st.NetworkMissing { // no knobs readable: the cause alone
				t.Fatalf("excerpt %q, want the detected cause", c.Excerpt)
			}
		})
	}
}

// The setup checklist says whether tools run unconfined and whether the
// ones that contact their targets are refused for it.
func TestSandboxUnconfinedCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		st     executor.Status
		code   string
		status string
	}{
		{"sandboxed", executor.Status{Mode: executor.ModeAuto, Sandboxed: true, Landlock: 4}, "sandboxed", core.CheckPass},
		{"not available", executor.Status{Mode: executor.ModeAuto, NoSandboxOnHost: true, Missing: []string{"sandbox: available on Linux only"}}, "active_refused", core.CheckFail},
		{"turned off", executor.Status{Mode: executor.ModeOff}, "acknowledged", core.CheckWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &Kit{doc: newDoctor(settingsreg.New(), nil)}
			k.sandboxUnconfinedCheck(tc.st)
			c, ok := findCheck(*k.ConfigReport(), CheckSandboxUnconfined)
			if !ok || c.Code != tc.code || c.Status != tc.status {
				t.Fatalf("check %+v (found %v), want %s/%s", c, ok, tc.code, tc.status)
			}
			if tc.code == "active_refused" && !strings.Contains(c.Excerpt, "sandbox: available on Linux only") {
				t.Fatalf("excerpt %q", c.Excerpt)
			}
		})
	}
}

// withProc points the host-knob reader at a fake /proc holding files.
func withProc(t *testing.T, files map[string]string) {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

// The code names the real cause from the host knobs: a sysctl that disables
// user namespaces is not a seccomp problem even though the error is EPERM.
func TestSandboxNetworkCheckHostKnobs(t *testing.T) {
	const eperm = "fork/exec /proc/self/exe: operation not permitted"
	const clone, maxNS, restrict = "sys/kernel/unprivileged_userns_clone", "sys/user/max_user_namespaces", "sys/kernel/apparmor_restrict_unprivileged_userns"
	const label, status = "self/attr/apparmor/current", "self/status"
	for _, tc := range []struct {
		name    string
		files   map[string]string
		missing string
		code    string
		excerpt []string
	}{
		{"ubuntu host, docker-default, seccomp profile: the sysctl",
			map[string]string{clone: "0\n", maxNS: "63000\n", restrict: "1\n",
				label: "docker-default (enforce)\n", status: "Name:\tx\nSeccomp:\t2\n"},
			eperm, "userns_disabled_host",
			[]string{"kernel.unprivileged_userns_clone=0", "kernel.apparmor_restrict_unprivileged_userns=1",
				"apparmor_label=docker-default (enforce)", "seccomp_mode=2", eperm}},
		{"max_user_namespaces zero", map[string]string{clone: "1\n", maxNS: "0\n"}, eperm, "userns_disabled_host",
			[]string{"user.max_user_namespaces=0"}},
		{"max_user_namespaces zero alone", map[string]string{maxNS: "0\n"}, "permission denied", "userns_disabled_host", nil},
		{"apparmor restriction, unconfined", map[string]string{clone: "1\n", maxNS: "63000\n", restrict: "1\n", label: "unconfined\n"},
			eperm, "userns_restricted", []string{"apparmor_label=unconfined"}},
		{"apparmor restriction, label in the legacy path", map[string]string{restrict: "1\n", "self/attr/current": "unconfined\n"},
			eperm, "userns_restricted", nil},
		{"apparmor restriction but confined by a profile: the error decides", map[string]string{clone: "1\n", restrict: "1\n", label: "docker-default (enforce)\n"},
			eperm, "userns_blocked", nil},
		{"knobs allow, EPERM: seccomp", map[string]string{clone: "1\n", maxNS: "63000\n", restrict: "0\n", status: "Seccomp:\t2\n"},
			eperm, "userns_blocked", []string{"seccomp_mode=2"}},
		{"knobs unreadable, EPERM", nil, eperm, "userns_blocked", nil},
		{"knobs allow, no error text match", map[string]string{clone: "1\n"}, "no ip binary", "unavailable", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withProc(t, tc.files)
			k := &Kit{doc: newDoctor(settingsreg.New(), nil)}
			k.sandboxNetworkCheck(executor.ModeAuto, executor.ModeAuto, executor.Status{NetworkMissing: tc.missing})
			c, ok := findCheck(*k.ConfigReport(), CheckSandboxNetwork)
			if !ok || c.Code != tc.code || c.Status != core.CheckWarn {
				t.Fatalf("check %+v (found %v), want %s", c, ok, tc.code)
			}
			for _, w := range tc.excerpt {
				if !strings.Contains(c.Excerpt, w) {
					t.Errorf("excerpt %q lacks %q", c.Excerpt, w)
				}
			}
			if tc.files == nil && strings.Contains(c.Excerpt, "=") {
				t.Errorf("unknown knobs must not appear: %q", c.Excerpt)
			}
		})
	}
}
