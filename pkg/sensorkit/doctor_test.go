package sensorkit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
)

const (
	canaryProxy = "CANARY-proxy-pw-5a4b"
	canaryTool  = "CANARY-trivy-pw-7c6d"
)

func findCheck(r core.ConfigReport, id string) (core.ConfigCheck, bool) {
	for _, c := range r.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return core.ConfigCheck{}, false
}

// A sensor on a platform that takes config reports delivers its preflight
// checks (a broken tool with its reason, a state directory that does not
// persist, an unreadable SSL_CERT_FILE, a legacy name, an unknown setting)
// with the presence of its settings, and every heartbeat carries the
// digest. No secret value appears in any byte the sensor sends: not the
// API key (outside the Authorization header), not a proxy password, not a
// sensor-declared secret echoed in a tool's error output.
func TestRun_ConfigReport_ChecksAndNoSecretOnTheWire(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetConfigReport(true)
	t.Cleanup(f.Close)

	opts, _, errw := baseOptions(t, f)
	t.Setenv("SENSOR_CONTENT_PROXY", "http://svc:"+canaryProxy+"@127.0.0.1:1")
	t.Setenv("TRIVY_PASSWORD", canaryTool)
	t.Setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
	t.Setenv("AGENT_NAME", "legacy-name")
	t.Setenv("SENSOR_MAX_JOB", "4")
	reg := settingsreg.New()
	reg.Register(settingsreg.Setting{Name: "TRIVY_PASSWORD", Type: settingsreg.String, Secret: true, Group: "tools",
		Description: "Registry password for trivy."})
	opts.Settings = reg
	opts.ReportUnknownEnv = true
	opts.UnavailableReason = func(_ context.Context, name string, _ error) string {
		// A tool echoing a secret in its error output.
		return "installed but fails to run: exit status 1: ModuleNotFoundError pkg_resources (password=" + canaryTool + ")"
	}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddScanner(&testScanner{name: "semgrep"})
	k.AddScanner(&testScanner{name: "kit-tool", installed: true})
	k.ReportCheck(core.ConfigCheck{ID: "config.file_unknown_key", Status: core.CheckWarn, Code: "unknown_key",
		Params:  map[string]core.ConfigParam{"key": core.ParamName("max_job"), "suggestion": core.ParamName("max_jobs")},
		Summary: "unknown key max_job "})
	stop := runKit(t, k)
	waitFor(t, "a config report", func() bool { return len(f.ConfigReports()) > 0 })
	waitFor(t, "a heartbeat with the report digest", func() bool {
		for _, b := range f.Heartbeats() {
			if strings.Contains(string(b), `"config_report":{"digest":"sha256:`) {
				return true
			}
		}
		return false
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	var r core.ConfigReport
	if err := json.Unmarshal(f.ConfigReports()[0], &r); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{
		"tool.semgrep.binary":     "broken",
		"tool.kit-tool.binary":    "ok",
		"tools.available":         "ok",
		CheckStatePersistent:      "not_persistent",
		CheckPlatformTLS:          "ca_file_unreadable",
		CheckAliasDeprecated:      "legacy_name",
		CheckEnvUnknown:           "unknown",
		CheckLocalPolicy:          "absent",
		CheckOOMProtect:           "not_requested",
		CheckCommandPoller:        "running",
		"config.file_unknown_key": "unknown_key",
		CheckScanProxyInherit:     "direct",
		CheckKeyRenewal:           "off_not_persistent",
	} {
		c, ok := findCheck(r, id)
		if !ok || c.Code != want {
			t.Errorf("%s: %+v (found %v), want code %s", id, c, ok, want)
		}
	}
	if c, _ := findCheck(r, "tool.semgrep.binary"); c.Status != core.CheckFail || !strings.Contains(c.Excerpt, "pkg_resources") ||
		len(c.Blocks) != 1 || c.Blocks[0] != "tool:semgrep" {
		t.Errorf("broken tool: %+v", c)
	}
	if c, _ := findCheck(r, CheckEnvUnknown); c.Params["suggestion"].Name != EnvMaxJobs {
		t.Errorf("did you mean: %+v", c)
	}
	if r.ConfigHealth != core.ConfigHealthBlocked { // the unreadable trust file blocks everything
		t.Errorf("health %s", r.ConfigHealth)
	}
	sawKey, sawTrivy := false, false
	for _, s := range r.Settings {
		switch s.Name {
		case EnvAPIKey:
			sawKey = s.Set && s.Secret && s.Source == "option"
		case "TRIVY_PASSWORD":
			sawTrivy = s.Set && s.Secret && s.Source == "env"
		}
	}
	if !sawKey || !sawTrivy {
		t.Errorf("settings presence: %+v", r.Settings)
	}
	if !strings.Contains(errw.String(), "SSL_CERT_FILE=/nonexistent/ca.pem cannot be read") {
		t.Errorf("the unreadable trust file must be said at start: %s", errw.String())
	}

	// N1: no secret in any outbound byte.
	for _, req := range f.Requests() {
		blob := req.Method + " " + req.Path + "\n" + string(req.Body)
		for name, vals := range req.Header {
			if name == "Authorization" || name == "X-Api-Key" {
				continue
			}
			blob += "\n" + name + ": " + strings.Join(vals, ",")
		}
		for _, c := range []string{f.APIKey, canaryProxy, canaryTool} {
			if strings.Contains(blob, c) {
				t.Fatalf("secret %q sent in %s %s", c, req.Method, req.Path)
			}
		}
	}
}

// A platform that does not list config_report gets neither the report nor
// the heartbeat member.
func TestRun_ConfigReport_NotSentWithoutTheFeature(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddScanner(&testScanner{name: "kit-tool", installed: true})
	stop := runKit(t, k)
	waitFor(t, "a heartbeat", func() bool { return len(f.Heartbeats()) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	for _, req := range f.Requests() {
		if strings.HasSuffix(req.Path, "/config-report") || strings.Contains(string(req.Body), `"config_report"`) {
			t.Fatalf("config report sent to a platform without the feature: %s %s", req.Method, req.Path)
		}
	}
	if len(k.ConfigReport().Checks) == 0 {
		t.Fatal("the report is still built locally")
	}
}
