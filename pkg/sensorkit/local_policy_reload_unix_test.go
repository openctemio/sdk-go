//go:build unix

package sensorkit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
)

// Owner decision D10: SIGHUP reloads the policy while the kit runs. A file
// that does not load engages the kill switch on the running poller and
// shows on the heartbeat; fixing it and reloading again releases it.
func TestKit_ReloadLocalPolicyOnSIGHUP(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetLocalPolicy(true)
	t.Cleanup(f.Close)

	path := filepath.Join(t.TempDir(), "sensor-policy.yaml")
	good := "apiVersion: openctem.io/sensor-policy/v1\ntools: {allow: [trivy]}\n"
	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, _, errw := baseOptions(t, f)
	opts.LocalPolicy = nil
	opts.LocalPolicyPath = path
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddScanner(&testScanner{name: "trivy", installed: true})
	popts := core.LocalPolicyOptions{Path: path}
	applied := make(chan *core.LocalPolicy, 4)
	stopHUP := k.ReloadLocalPolicyOnSIGHUP(t.Context(), popts, func(lp *core.LocalPolicy) { applied <- lp })
	t.Cleanup(stopHUP)
	stop := runKit(t, k)
	t.Cleanup(func() { _ = stop() })
	waitFor(t, "the poller", func() bool { return k.poller.Load() != nil })

	hup := func() *core.LocalPolicy {
		t.Helper()
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case lp := <-applied:
			return lp
		case <-time.After(5 * time.Second):
			t.Fatal("no reload after SIGHUP")
		}
		return nil
	}

	if err := os.WriteFile(path, []byte("apiVersion: openctem.io/sensor-policy/v1\ntools: {allow: [trivy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lp := hup()
	if !lp.KillSwitchEngaged() || !k.poller.Load().LocalKillSwitch() || k.LocalPolicy() != lp {
		t.Fatalf("invalid file: kill switch %v, poller %v", lp.KillSwitchEngaged(), k.poller.Load().LocalKillSwitch())
	}
	if !strings.Contains(errw.String(), "local policy reload failed") {
		t.Errorf("stderr: %s", errw.String())
	}
	if r := k.LocalPolicy().Report(); !r.KillSwitch || !strings.Contains(strings.Join(r.Warnings, " "), "reload failed") {
		t.Fatalf("report after a failed reload: %+v", r)
	}

	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if lp := hup(); lp.KillSwitchEngaged() || k.poller.Load().LocalKillSwitch() {
		t.Fatal("fixed file did not release the kill switch")
	}
}
