package sensorkit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
)

// withBrokenHost makes every tool backend the kit builds use a launcher that
// cannot run: a host that cannot give the sandbox or its network confinement.
func withBrokenHost(t *testing.T) {
	t.Helper()
	old := newProcessBackend
	newProcessBackend = func(cfg executor.Config) (*executor.ProcessBackend, error) {
		cfg.Launcher = "/nonexistent/openctem-launcher"
		return old(cfg)
	}
	t.Cleanup(func() { newProcessBackend = old; executor.SetCurrent(nil) })
}

func requiredKit() (*Kit, *bytes.Buffer) {
	var errw bytes.Buffer
	return &Kit{out: &bytes.Buffer{}, errw: &errw, doc: newDoctor(settingsreg.New(), nil)}, &errw
}

// research/468 D3: SENSOR_SANDBOX=required or SENSOR_SANDBOX_NETWORK=required
// on a host that cannot give it keeps the sensor online: the installed
// backend refuses every tool that contacts its targets (T1 and above never
// runs unconfined), passive tools still run, and the checklist names the
// classified cause.
func TestRequiredSandboxRefusesActiveWorkInsteadOfExiting(t *testing.T) {
	for _, tc := range []struct{ sandbox, net string }{
		{"required", "auto"},
		{"auto", "required"},
		{"required", "required"},
	} {
		t.Run(tc.sandbox+"/"+tc.net, func(t *testing.T) {
			clearEnv(t)
			withBrokenHost(t)
			withProc(t, map[string]string{"sys/kernel/unprivileged_userns_clone": "0\n"})
			t.Setenv(EnvSandboxNetwork, tc.net)
			if err := validateSandboxNetwork(tc.sandbox, false); err != nil {
				t.Fatalf("pre-pair validation must not refuse the sensor: %v", err)
			}
			k, errw := requiredKit()
			k.opts.Sandbox = tc.sandbox
			if err := k.setupSandbox(); err != nil {
				t.Fatalf("setupSandbox = %v: the sensor must stay online", err)
			}
			st := executor.Current().Status()
			if st.RequiredUnmet == "" || !st.RefusesActiveTools() {
				t.Fatalf("installed backend %+v must refuse active tools", st)
			}
			if _, err := executor.Current().Prepare(executor.TaskSpec{Argv: []string{"true"}, Network: executor.NetworkTargetsOnly}); err == nil {
				t.Fatal("an active task was prepared on a host without the required sandbox")
			}
			if task, err := executor.Current().Prepare(executor.TaskSpec{Argv: []string{"true"}, Network: executor.NetworkAny, Passive: true}); err != nil {
				t.Fatalf("a passive task was refused: %v", err)
			} else {
				_ = task.Cleanup()
			}
			c, ok := findCheck(*k.ConfigReport(), CheckSandboxUnconfined)
			if !ok || c.Status != core.CheckFail || c.Code != "active_refused" || !strings.Contains(c.Excerpt, "required") {
				t.Fatalf("unconfined check %+v (found %v)", c, ok)
			}
			n, ok := findCheck(*k.ConfigReport(), CheckSandboxNetwork)
			if !ok || n.Code != "userns_disabled_host" {
				t.Fatalf("network check %+v (found %v), want the classified cause userns_disabled_host", n, ok)
			}
			if tc.net == "required" && n.Status != core.CheckFail {
				t.Fatalf("network check %+v: required and missing is a failure", n)
			}
			if !strings.Contains(errw.String(), EnvSandboxRequiredExit) {
				t.Fatalf("the log does not say how to exit instead: %s", errw.String())
			}
		})
	}
}

// The cause is classified before anything returns: EPERM with the host's
// kernel.unprivileged_userns_clone=0 is userns_disabled_host, not seccomp.
func TestRequiredNetworkCheckClassifiesHostSysctl(t *testing.T) {
	withProc(t, map[string]string{"sys/kernel/unprivileged_userns_clone": "0\n", "self/status": "Seccomp:\t2\n"})
	k, _ := requiredKit()
	k.sandboxNetworkCheck(executor.ModeRequired, executor.ModeRequired,
		executor.Status{NetworkMissing: "probe: unshare user namespace: operation not permitted"})
	c, ok := findCheck(*k.ConfigReport(), CheckSandboxNetwork)
	if !ok || c.Code != "userns_disabled_host" || c.Status != core.CheckFail || !strings.Contains(c.Excerpt, "kernel.unprivileged_userns_clone=0") {
		t.Fatalf("check %+v (found %v)", c, ok)
	}
}

// SENSOR_SANDBOX_REQUIRED_EXIT=1 keeps the old behavior: the host is
// refused before pairing and at start.
func TestRequiredSandboxExitOptIn(t *testing.T) {
	clearEnv(t)
	withBrokenHost(t)
	t.Setenv(EnvSandboxRequiredExit, "1")
	t.Setenv(EnvSandboxNetwork, "required")
	if err := validateSandboxNetwork("auto", false); err == nil || !strings.Contains(err.Error(), EnvSandboxNetwork+"=required") {
		t.Fatalf("validate = %v, want the start refusal", err)
	}
	k, _ := requiredKit()
	k.opts.Sandbox = "required"
	if err := k.setupSandbox(); err == nil {
		t.Fatal("setupSandbox succeeded with the exit opt-in")
	}
	t.Setenv(EnvSandboxRequiredExit, "maybe")
	if err := validateSandboxNetwork("auto", false); err == nil || !strings.Contains(err.Error(), EnvSandboxRequiredExit) {
		t.Fatalf("an unrecognized value must be refused: %v", err)
	}
}

// A shared sensor still refuses to start on such a host, and network
// confinement required with the sandbox off is a settings error.
func TestRequiredSandboxSharedAndContradiction(t *testing.T) {
	clearEnv(t)
	withBrokenHost(t)
	if err := validateSandboxNetwork("required", true); err == nil {
		t.Fatal("a shared sensor started on a host without network confinement")
	}
	t.Setenv(EnvSandboxNetwork, "required")
	if err := validateSandboxNetwork("off", false); err == nil {
		t.Fatal("network required with the sandbox off must be refused")
	}
}
