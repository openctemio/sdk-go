package sensorkit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
)

// A kit with a local policy file: a malformed one stops New (fail closed);
// a valid one is reported on the heartbeat (to a platform that reads it),
// and a tool outside tools.allow is neither run nor reported.
func TestKit_LocalPolicy(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetLocalPolicy(true)
	t.Cleanup(f.Close)

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("apiVersion: openctem.io/sensor-policy/v1\nallow_all: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, _, _ := baseOptions(t, f)
	opts.LocalPolicyPath = bad
	if _, err := New(opts); err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "allow_all") {
		t.Fatalf("malformed policy: %v", err)
	}

	good := filepath.Join(dir, "sensor-policy.yaml")
	doc := "apiVersion: openctem.io/sensor-policy/v1\ntargets: {allow: [203.0.113.0/24]}\ntools: {allow: [trivy]}\n"
	if err := os.WriteFile(good, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, out, errw := baseOptions(t, f)
	t.Setenv(core.EnvLocalPolicy, good)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Local policy: enforced from file "+good) {
		t.Errorf("stdout: %s", out.String())
	}
	k.AddScanner(&testScanner{name: "trivy", installed: true})
	k.AddScanner(&testScanner{name: "nuclei", installed: true})
	stop := runKit(t, k)
	waitFor(t, "a heartbeat", func() bool { return len(f.Heartbeats()) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	hb := lastBeat(t, f)
	if len(hb.Tools) != 1 || hb.Tools[0].Name != "trivy" {
		t.Fatalf("tools %+v, want only trivy", hb.Tools)
	}
	if !strings.Contains(errw.String(), "scanner nuclei is not in the local policy's tools.allow") {
		t.Errorf("stderr: %s", errw.String())
	}
	// The first heartbeat (the last one is the shutdown notice).
	beats := f.Heartbeats()
	var body struct {
		LocalPolicy *core.LocalPolicyReport `json:"local_policy"`
	}
	if err := json.Unmarshal(beats[0], &body); err != nil {
		t.Fatal(err)
	}
	if body.LocalPolicy == nil || body.LocalPolicy.State != core.LocalPolicyStateEnforced || body.LocalPolicy.Summary.TargetsAllow != 1 {
		t.Fatalf("heartbeat local_policy %+v: %s", body.LocalPolicy, beats[0])
	}
}

// No policy: the kit starts as before and warns (owner decision Q3 (a)).
func TestKit_NoLocalPolicyWarns(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	opts.LocalPolicy = nil
	if _, err := New(opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Local policy: absent") || !strings.Contains(errw.String(), "Warning: no local policy") {
		t.Fatalf("stdout %s stderr %s", out.String(), errw.String())
	}
}
