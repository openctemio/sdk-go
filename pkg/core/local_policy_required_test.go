package core

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// absentPolicyFor loads the policy of a sensor with no policy file and no
// shorthands, required or not.
func absentPolicyFor(t *testing.T, required bool, vars map[string]string) *LocalPolicy {
	t.Helper()
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"),
		LookupEnv: env(vars), Required: required})
	if err != nil {
		t.Fatal(err)
	}
	if lp.Present() {
		t.Fatal("a policy is loaded")
	}
	return lp
}

func wantNoPolicyRefusal(t *testing.T, what string, err error) {
	t.Helper()
	var pe *LocalPolicyError
	if !errors.As(err, &pe) || pe.Rule != LocalPolicyRuleNoPolicy {
		t.Fatalf("%s: got %v, want a %s refusal", what, err, LocalPolicyRuleNoPolicy)
	}
	if !strings.Contains(pe.Detail, DefaultLocalPolicyPath) || !strings.Contains(pe.Detail, EnvAllowedRanges) {
		t.Fatalf("%s: the detail does not tell the operator what to install: %q", what, pe.Detail)
	}
}

// A sensor that requires a local policy and has none refuses every job with
// a network target before any tool runs, and runs jobs without one.
func TestCommandPoller_RequiredAbsentPolicy(t *testing.T) {
	lp := absentPolicyFor(t, true, nil)
	repo := t.TempDir()
	c := newQueueClient(
		scanCmd("host", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.10"}),
		scanCmd("url", "normal", map[string]any{"scanner": "nuclei", "targets": []string{"https://203.0.113.11/"}}),
		scanCmd("templates", "normal", map[string]any{"scanner": "nuclei", "target": repo + "/x", "custom_templates": []any{map[string]any{"name": "t"}}}),
		scanCmd("repo", "normal", map[string]any{"scanner": "semgrep", "target": repo}),
	)
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 8})
	p.SetLocalPolicy(lp)
	p.SetCommandGate(func(*Command) error { return nil })
	p.pollAndExecute(context.Background())
	select {
	case id := <-e.started:
		if id != "repo" {
			t.Fatalf("ran %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the repository scan did not run")
	}
	close(e.release)
	p.activeCmds.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range []string{"host", "url", "templates"} {
		if c.results[id] != "failed" || !strings.HasPrefix(c.errs[id], "refused by local policy: "+LocalPolicyRuleNoPolicy+": ") {
			t.Errorf("%s: result %q, error %q", id, c.results[id], c.errs[id])
		}
		if r := c.refusals[id]; r == nil || r.Layer != RefusalLayerLocal || r.Rule != LocalPolicyRuleNoPolicy {
			t.Errorf("%s: refusal %+v", id, r)
		}
	}
	if c.results["repo"] != "completed" {
		t.Errorf("repo: %q %q", c.results["repo"], c.errs["repo"])
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.runs) != 1 {
		t.Fatalf("refused commands reached the executor: %v", e.runs)
	}
}

func TestLocalPolicy_RequiredAbsentAdmission(t *testing.T) {
	lp := absentPolicyFor(t, true, nil)
	ctx := context.Background()
	dir := t.TempDir()
	for name, payload := range map[string]map[string]any{
		"ip":         {"scanner": "nuclei", "target": "203.0.113.10"},
		"domain":     {"scanner": "nuclei", "targets": []string{dir, "example.com"}},
		"cidr":       {"scanner": "naabu", "target": "203.0.113.0/24"},
		"image":      {"scanner": "trivy", "target": "registry.example.com/app:1"},
		"validate":   {"executor_kind": "nuclei", "target": map[string]any{"address": "203.0.113.12:443"}},
		"interactsh": {"scanner": "nuclei", "target": dir, "config": map[string]any{"allow_interactsh": true}},
	} {
		raw, _ := json.Marshal(payload)
		typ := "scan"
		if name == "validate" {
			typ = "validate"
		}
		cmd := &Command{ID: name, Type: typ, Payload: raw}
		wantNoPolicyRefusal(t, name, lp.AdmitCommand(ctx, cmd))
		if _, err := lp.AdmitCommandTargets(ctx, cmd); err == nil {
			t.Errorf("%s: AdmitCommandTargets admitted it", name)
		}
	}
	for name, cmd := range map[string]*Command{
		"filesystem": {ID: "fs", Type: "scan", Payload: json.RawMessage(`{"scanner":"trivy","target":"` + dir + `"}`)},
		"health":     {ID: "h", Type: "health_check"},
		"no target":  {ID: "c", Type: "collect", Payload: json.RawMessage(`{"collector":"github"}`)},
	} {
		if err := lp.AdmitCommand(ctx, cmd); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if lp.AllowsCustomTemplates() || lp.AllowsInteractsh() {
		t.Error("a sensor that requires a policy allows custom templates or callbacks without one")
	}
	// The kill switch still applies.
	stop := filepath.Join(t.TempDir(), "STOP")
	ks := absentPolicyFor(t, true, map[string]string{EnvKillSwitchFile: stop})
	if err := os.WriteFile(stop, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var pe *LocalPolicyError
	if err := ks.AdmitCommand(ctx, &Command{ID: "fs", Type: "scan", Payload: json.RawMessage(`{"target":"` + dir + `"}`)}); !errors.As(err, &pe) || pe.Rule != "kill_switch" {
		t.Fatalf("kill switch: %v", err)
	}
	// Every other path that checks a target directly is closed too.
	wantNoPolicyRefusal(t, "CheckTarget", lp.CheckTarget(ctx, "example.com"))
	if err := lp.CheckTarget(ctx, dir); err != nil {
		t.Errorf("CheckTarget(path): %v", err)
	}
	if _, err := lp.CheckDial(ctx, "tcp", "203.0.113.10:443"); err == nil {
		t.Error("CheckDial admitted a dial")
	}
	if _, err := lp.AdmittedAddrs(ctx, "example.com"); err == nil {
		t.Error("AdmittedAddrs admitted a host")
	}
	if _, err := (&ScanTargetPolicy{Local: lp}).Validate(ctx, "https://203.0.113.10/"); err == nil {
		t.Error("ScanTargetPolicy admitted a URL")
	}
	if _, err := (&ScanTargetPolicy{Local: lp}).Validate(ctx, "203.0.113.10"); err == nil {
		t.Error("ScanTargetPolicy admitted an address")
	}
}

// A legacy install (no policy, not required) keeps today's behavior.
func TestLocalPolicy_LegacyAbsentUnchanged(t *testing.T) {
	lp := absentPolicyFor(t, false, nil)
	ctx := context.Background()
	raw := json.RawMessage(`{"scanner":"nuclei","targets":["203.0.113.10","example.com"],"custom_templates":[{"name":"t"}],"config":{"allow_interactsh":true}}`)
	cmd := &Command{ID: "a", Type: "scan", Payload: raw}
	if err := lp.AdmitCommand(ctx, cmd); err != nil {
		t.Fatalf("legacy admission: %v", err)
	}
	if adm, err := lp.AdmitCommandTargets(ctx, cmd); err != nil || adm.Partial() || string(cmd.Payload) != string(raw) {
		t.Fatalf("legacy admission rewrote or refused: %+v %v", adm, err)
	}
	if !lp.AllowsCustomTemplates() || !lp.AllowsInteractsh() || lp.Required() {
		t.Fatal("legacy switches changed")
	}
	if len(lp.CommandWarnings(cmd)) != 2 {
		t.Fatalf("warnings: %v", lp.CommandWarnings(cmd))
	}
	if err := lp.CheckTarget(ctx, "203.0.113.10"); err != nil {
		t.Fatalf("public address: %v", err)
	}
	r := lp.Report()
	if r.State != LocalPolicyStateAbsent || r.Required {
		t.Fatalf("report: %+v", r)
	}
}

// Without a policy CheckTarget still applies the built-in deny list (a
// retest or a tool task checks its targets with it directly).
func TestLocalPolicy_CheckTargetBuiltinWithoutPolicy(t *testing.T) {
	t.Setenv(EnvSensorAllowPrivateTargets, "")
	t.Setenv(EnvAllowPrivateTargets, "")
	ctx := context.Background()
	for _, lp := range []*LocalPolicy{nil, absentPolicyFor(t, false, nil)} {
		for _, target := range []string{"169.254.169.254", "http://169.254.169.254/latest/meta-data/", "127.0.0.1",
			"127.0.0.1:8080", "10.0.0.1", "10.0.0.0/8", "0.0.0.0", "224.0.0.1", "100.64.0.1", "[::1]:443"} {
			err := lp.CheckTarget(ctx, target)
			var pe *LocalPolicyError
			if !errors.As(err, &pe) || (pe.Rule != "builtin" && pe.Rule != "targets.allow_private") {
				t.Errorf("CheckTarget(%q) without a policy (nil %t): %v", target, lp == nil, err)
			}
		}
	}
	// The private-range switch allows private targets, never the metadata
	// address.
	t.Setenv(EnvSensorAllowPrivateTargets, "1")
	lp := absentPolicyFor(t, false, nil)
	if err := lp.CheckTarget(ctx, "10.0.0.1"); err != nil {
		t.Errorf("private switch on: %v", err)
	}
	if err := lp.CheckTarget(ctx, "169.254.169.254"); err == nil {
		t.Error("private switch on: the metadata address is allowed")
	}
}

func TestLocalPolicy_RequireEnvOverride(t *testing.T) {
	for _, tc := range []struct {
		env      string
		required bool
		want     bool
	}{
		{"", true, true},
		{"", false, false},
		{"false", true, false},
		{"0", true, false},
		{"true", false, true},
		{"1", false, true},
	} {
		vars := map[string]string{}
		if tc.env != "" {
			vars[EnvRequireLocalPolicy] = tc.env
		}
		lp := absentPolicyFor(t, tc.required, vars)
		if lp.Required() != tc.want {
			t.Errorf("env %q, option %t: required %t", tc.env, tc.required, lp.Required())
		}
		if lp.AllowsInteractsh() == tc.want {
			t.Errorf("env %q, option %t: interactsh %t", tc.env, tc.required, lp.AllowsInteractsh())
		}
	}
	if _, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"),
		LookupEnv: env(map[string]string{EnvRequireLocalPolicy: "yes please"})}); err == nil ||
		!strings.Contains(err.Error(), EnvRequireLocalPolicy) {
		t.Fatalf("an unreadable %s: %v", EnvRequireLocalPolicy, err)
	}
	// A loaded policy is enforced whatever the requirement; it is reported.
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"),
		LookupEnv: env(map[string]string{EnvAllowedRanges: "203.0.113.0/24"}), Required: true})
	if err != nil {
		t.Fatal(err)
	}
	if r := lp.Report(); r.State != LocalPolicyStateEnforced || !r.Required {
		t.Fatalf("report: %+v", r)
	}
	if err := lp.CheckTarget(context.Background(), "203.0.113.5"); err != nil {
		t.Fatalf("allowed target: %v", err)
	}
	// WithRequired keeps the rest of the policy.
	if c := lp.WithRequired(false); c.Required() || c.Digest() != lp.Digest() || !c.Present() || !lp.Required() {
		t.Fatal("WithRequired changed more than the requirement")
	}
	if c := (*LocalPolicy)(nil).WithRequired(true); c.Present() || !c.Required() || c.AllowsCustomTemplates() {
		t.Fatal("WithRequired on nil")
	}
}

// The report and the slim heartbeat carry "required"; the manifest carries
// the posture with its documented names.
func TestLocalPolicy_PostureSerialized(t *testing.T) {
	lp := absentPolicyFor(t, true, nil)
	raw, err := json.Marshal(lp.Report())
	if err != nil {
		t.Fatal(err)
	}
	var rep map[string]any
	_ = json.Unmarshal(raw, &rep)
	if rep["state"] != "absent" || rep["required"] != true {
		t.Fatalf("report: %s", raw)
	}
	legacy, _ := json.Marshal(absentPolicyFor(t, false, nil).Report())
	if !strings.Contains(string(legacy), `"required":false`) {
		t.Fatalf("legacy report leaves required out: %s", legacy)
	}

	status := &SensorStatus{LocalPolicy: lp.Report()}
	slimHeartbeat(status)
	if !status.LocalPolicy.Required {
		t.Fatal("the slim heartbeat drops required")
	}

	m := BuildManifest(&SensorStatus{LocalPolicy: lp.Report()}, nil, "")
	m.Posture = &SensorPosture{PlatformTLS: &PlatformTLSPosture{Pin: TLSPinFingerprint},
		Sandbox: &SandboxPosture{Mode: "auto", Sandboxed: true, NetworkEnforced: false}}
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"local_policy":{"state":"absent","required":true`, `"posture":{"platform_tls":{"pin":"fingerprint"},"sandbox":{"mode":"auto","sandboxed":true,"network_enforced":false}}`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("manifest %s lacks %s", raw, want)
		}
	}
	if _, err := m.Digest(); err != nil {
		t.Fatal(err)
	}
}

// The platform TLS pin follows what the sensor configured: a pinned CA
// fingerprint, a private CA file, or the system trust store.
func TestPlatformTLSPin(t *testing.T) {
	t.Cleanup(func() { httpsec.SetAPIPinnedCA(nil); httpsec.SetAPIRootCAs(nil) })
	httpsec.SetAPIPinnedCA(nil)
	httpsec.SetAPIRootCAs(nil)
	if got := PlatformTLSPin(); got != TLSPinNone {
		t.Fatalf("no pin: %q", got)
	}
	httpsec.SetAPIRootCAs(x509.NewCertPool())
	if got := PlatformTLSPin(); got != TLSPinCAFile {
		t.Fatalf("CA file: %q", got)
	}
	httpsec.SetAPIPinnedCA(make([]byte, 32))
	if got := PlatformTLSPin(); got != TLSPinFingerprint {
		t.Fatalf("fingerprint: %q", got)
	}
	p := CurrentPosture()
	st := executor.Current().Status()
	if p.PlatformTLS.Pin != TLSPinFingerprint || p.Sandbox.Mode != string(st.Mode) || p.Sandbox.NetworkEnforced != st.NetworkEnforced {
		t.Fatalf("posture %+v %+v, sandbox %+v", p.PlatformTLS, p.Sandbox, st)
	}
}
