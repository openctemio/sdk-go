package core

import (
	"encoding/json"
	"strings"
	"testing"
)

const canary = "CANARY-s3cr3t-9f8e7d"

func TestConfigReportFinalize_ScrubsSecretsEverywhere(t *testing.T) {
	r := &ConfigReport{Checks: []ConfigCheck{
		{ID: "platform.tls", Status: CheckFail, Code: "ca_file_unreadable",
			Summary: "key " + canary + " leaked via https://user:pw@proxy.corp:3128/x",
			Excerpt: "stderr: Authorization: " + canary,
			Params: map[string]ConfigParam{
				"path": ParamPath("/etc/" + canary),
				"name": ParamName(canary),
				"ok":   ParamName("SSL_CERT_FILE"),
			}},
	}}
	r.Finalize([]string{canary}, 0)
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), canary) {
		t.Fatalf("secret in report: %s", raw)
	}
	if strings.Contains(string(raw), "user:pw") {
		t.Fatalf("URL credentials in report: %s", raw)
	}
	c := r.Checks[0]
	if _, ok := c.Params["path"]; ok {
		t.Fatal("a parameter holding a secret must be dropped, not shown")
	}
	if c.Params["ok"].Name != "SSL_CERT_FILE" {
		t.Fatalf("clean param dropped: %+v", c.Params)
	}
}

func TestConfigReportFinalize_DropsHostileAndBounds(t *testing.T) {
	long := strings.Repeat("A", 10_000)
	r := &ConfigReport{Checks: []ConfigCheck{
		{ID: "Bad ID", Status: CheckPass, Code: "ok"},
		{ID: "tool.x.binary", Status: "bogus", Code: "ok"},
		{ID: "tool.x.binary", Status: CheckWarn, Code: "Not-OK"},
		{ID: "tool.semgrep.binary", Status: CheckFail, Code: "broken",
			Summary: "\u202eevil\u202c<script>alert(1)</script>\x00\x1b[31m" + long,
			Excerpt: long,
			Blocks:  []string{"tool:semgrep", "role:god", "tool:SEMGREP"},
			Params: map[string]ConfigParam{
				"two":   {Name: "a", Enum: "b"},
				"rel":   ParamPath("../etc/passwd"),
				"dots":  ParamPath("/var/../etc"),
				"host":  ParamHost("user@evil"),
				"big":   ParamInt(1 << 62),
				"Upper": ParamName("x"),
				"exit":  ParamInt(1),
			}},
	}}
	r.Finalize(nil, 0)
	if len(r.Checks) != 1 {
		t.Fatalf("want only the valid check, got %+v", r.Checks)
	}
	c := r.Checks[0]
	if strings.ContainsRune(c.Summary, '\u202e') || strings.ContainsRune(c.Summary, 0) || strings.ContainsRune(c.Summary, 0x1b) {
		t.Fatalf("control/bidi kept: %q", c.Summary[:40])
	}
	if len(c.Summary) > MaxConfigSummaryLen || len(c.Excerpt) > MaxConfigExcerptLen {
		t.Fatalf("not bounded: %d %d", len(c.Summary), len(c.Excerpt))
	}
	if !strings.Contains(c.Summary, "<script>") {
		t.Fatal("text is data: kept verbatim (the platform renders it as text)")
	}
	if len(c.Blocks) != 1 || c.Blocks[0] != "tool:semgrep" {
		t.Fatalf("blocks %v", c.Blocks)
	}
	if len(c.Params) != 1 || *c.Params["exit"].Int != 1 {
		t.Fatalf("params %+v", c.Params)
	}
	if r.ConfigHealth != ConfigHealthImpaired {
		t.Fatalf("health %s", r.ConfigHealth)
	}
}

func TestConfigReportFinalize_FitsTheLimit(t *testing.T) {
	r := &ConfigReport{}
	for i := 0; i < 500; i++ {
		st := CheckPass
		if i%50 == 0 {
			st = CheckFail
		}
		r.Checks = append(r.Checks, ConfigCheck{ID: "tool.t" + strings.Repeat("x", i%30) + ".binary", Status: st, Code: "ok",
			Summary: strings.Repeat("s", 290), Params: map[string]ConfigParam{"tool": ParamName("t" + string(rune('a'+i%26)))}})
	}
	for i := 0; i < 400; i++ {
		r.Settings = append(r.Settings, ConfigSetting{Name: "SENSOR_X", Source: "env"})
	}
	r.Finalize(nil, 0)
	raw, _ := json.Marshal(r)
	if len(raw) > MaxConfigReportBytes {
		t.Fatalf("report %d bytes > %d", len(raw), MaxConfigReportBytes)
	}
	if !r.Truncated || len(r.Settings) != 0 {
		t.Fatalf("truncated=%v settings=%d", r.Truncated, len(r.Settings))
	}
	if len(r.Checks) == 0 || r.Checks[0].Status != CheckFail {
		t.Fatal("failures must be kept first")
	}
}

func TestConfigReportDigest_IgnoresObservedAt(t *testing.T) {
	a := &ConfigReport{ObservedAt: "2026-10-05T10:00:00Z", Trigger: ConfigTriggerStart,
		Checks: []ConfigCheck{{ID: "policy.local", Status: CheckWarn, Code: "absent"}}}
	a.Finalize(nil, 0)
	b := *a
	b.ObservedAt, b.Trigger = "2026-10-06T10:00:00Z", ConfigTriggerChange
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da != db || !strings.HasPrefix(da, "sha256:") {
		t.Fatalf("%s != %s", da, db)
	}
	b.Checks = []ConfigCheck{{ID: "policy.local", Status: CheckPass, Code: "enforced", Severity: SeverityInfo}}
	if dc, _ := b.Digest(); dc == da {
		t.Fatal("a changed check must change the digest")
	}
}

func TestConfigHealthOf(t *testing.T) {
	for _, tc := range []struct {
		checks []ConfigCheck
		want   string
	}{
		{nil, ConfigHealthOK},
		{[]ConfigCheck{{Status: CheckWarn, Severity: SeverityInfo}}, ConfigHealthOK},
		{[]ConfigCheck{{Status: CheckWarn, Severity: SeverityWarning}}, ConfigHealthAttention},
		{[]ConfigCheck{{Status: CheckFail, Blocks: []string{"tool:x"}}}, ConfigHealthImpaired},
		{[]ConfigCheck{{Status: CheckError}}, ConfigHealthImpaired},
		{[]ConfigCheck{{Status: CheckWarn, Severity: SeverityWarning}, {Status: CheckFail, Blocks: []string{BlockAll}}}, ConfigHealthBlocked},
	} {
		if got := ConfigHealthOf(tc.checks); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.checks, got, tc.want)
		}
	}
}

// The settings entry type has no value member: a value cannot be sent.
func TestConfigSettingHasNoValue(t *testing.T) {
	raw, _ := json.Marshal(ConfigSetting{Name: "API_KEY", Set: true, Source: "env", Secret: true, Valid: true})
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for k := range m {
		switch k {
		case "name", "set", "source", "secret", "valid":
		default:
			t.Fatalf("unexpected member %q", k)
		}
	}
}
