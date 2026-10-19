package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

func TestParseRuleSources(t *testing.T) {
	for in, want := range map[string]RuleSources{
		"": RuleSourcesBoth, "both": RuleSourcesBoth, " Platform ": RuleSourcesPlatform, "TENANT": RuleSourcesTenant,
	} {
		got, err := ParseRuleSources(in)
		if err != nil || got != want {
			t.Errorf("ParseRuleSources(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"all", "none", "custom", "platform,tenant"} {
		if _, err := ParseRuleSources(in); err == nil {
			t.Errorf("ParseRuleSources(%q) accepted an unknown value", in)
		}
	}
	var zero RuleSources
	if !zero.Platform() || !zero.Tenant() {
		t.Error("the zero value must run both rule sources")
	}
	if RuleSourcesPlatform.Tenant() || RuleSourcesTenant.Platform() {
		t.Error("a single source must not run the other")
	}
}

func TestTenantRuleID(t *testing.T) {
	if got := TenantRuleID("CVE-2021-44228"); got != "tenant:CVE-2021-44228" {
		t.Fatalf("TenantRuleID = %q", got)
	}
	if got := TenantRuleID("tenant:x"); got != "tenant:x" {
		t.Fatalf("prefix added twice: %q", got)
	}
	if TenantRuleID("") != "" {
		t.Fatal("an empty id must stay empty")
	}
}

// ruleSourcesJob is a signed nuclei command with tpls and rule sources rs.
func ruleSourcesJob(t *testing.T, s *jobSigner, rs string, tpls []EmbeddedTemplate) *Command {
	t.Helper()
	payload, err := json.Marshal(ScanCommandPayload{Scanner: "nuclei", Target: "https://93.184.215.14", CustomTemplates: tpls, RuleSources: rs})
	if err != nil {
		t.Fatal(err)
	}
	digests, err := jobsig.PayloadTemplateDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	env := s.sign(t, jsCmd, 1, payload, func(st *jobsig.Statement) { st.Templates = digests })
	cmd := &Command{ID: jsCmd, Type: "scan", Payload: payload, LeaseEpoch: 1, SignedJob: env}
	if err := templateGuard(t, s).Check(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestRuleSourcesReachTheScanner(t *testing.T) {
	tpl := encodedTemplate("t1", "probe.yaml", sjTemplateBody)
	cases := []struct {
		rs   string
		tpls []EmbeddedTemplate
		want RuleSources
	}{
		{"", []EmbeddedTemplate{tpl}, RuleSourcesBoth},
		{"both", []EmbeddedTemplate{tpl}, RuleSourcesBoth},
		{"tenant", []EmbeddedTemplate{tpl}, RuleSourcesTenant},
		{"platform", nil, RuleSourcesPlatform},
		{"", nil, RuleSourcesBoth},
	}
	for _, c := range cases {
		t.Run(c.rs+"/"+string(c.want), func(t *testing.T) {
			sc, err := runTemplateCommand(t, NewDefaultCommandExecutor(nil), ruleSourcesJob(t, newJobSigner(), c.rs, c.tpls))
			if err != nil || sc.calls != 1 {
				t.Fatalf("err = %v, scans = %d; want one scan", err, sc.calls)
			}
			if sc.opts.RuleSources != c.want {
				t.Fatalf("RuleSources = %q, want %q", sc.opts.RuleSources, c.want)
			}
			if (len(c.tpls) > 0) != (sc.opts.CustomTemplateDir != "") {
				t.Fatalf("CustomTemplateDir = %q with %d templates", sc.opts.CustomTemplateDir, len(c.tpls))
			}
		})
	}
}

// A job whose rule sources contradict its templates is never run.
func TestRuleSourcesContradictionsAreRefused(t *testing.T) {
	tpl := encodedTemplate("t1", "probe.yaml", sjTemplateBody)
	cases := map[string]struct {
		rs   string
		tpls []EmbeddedTemplate
		want string
	}{
		"platform with templates":  {"platform", []EmbeddedTemplate{tpl}, "only platform rules"},
		"tenant without templates": {"tenant", nil, "no custom template"},
		"unknown value":            {"everything", []EmbeddedTemplate{tpl}, "unknown rule_sources"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sc, err := runTemplateCommand(t, NewDefaultCommandExecutor(nil), ruleSourcesJob(t, newJobSigner(), c.rs, c.tpls))
			if err == nil || sc.calls != 0 || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, scans = %d; want refused with %q", err, sc.calls, c.want)
			}
		})
	}
}

// A signed custom template that could run code on the sensor is refused
// before anything is written, whatever the platform signed: this is what
// lets a scanner run custom templates together with its own in one run.
func TestDangerousCustomTemplatesAreRefusedAtVerify(t *testing.T) {
	base := "id: x\ninfo:\n  name: x\n  severity: info\n"
	for name, body := range map[string]string{
		"code":            base + "code:\n  - engine: [sh]\n    source: id\n",
		"javascript":      base + "javascript:\n  - code: 'x'\n",
		"flow":            base + "flow: http(1)\nhttp:\n  - path: ['{{BaseURL}}']\n",
		"flow upper case": base + "Flow: http(1)\n",
		"file":            base + "file:\n  - extensions: [all]\n",
		"headless":        base + "headless:\n  - steps: []\n",
		"self-contained":  base + "self-contained: true\nhttp:\n  - path: ['{{BaseURL}}']\n",
		"workflows":       base + "workflows:\n  - template: http/x.yaml\n",
		"payload file":    base + "http:\n  - payloads:\n      p: /etc/passwd\n    path: ['{{BaseURL}}/{{p}}']\n",
		"two documents":   base + "---\ncode: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			tpl := encodedTemplate("t1", "bad.yaml", body)
			sc, err := runTemplateCommand(t, NewDefaultCommandExecutor(nil), ruleSourcesJob(t, newJobSigner(), "both", []EmbeddedTemplate{tpl}))
			if err == nil || sc.calls != 0 || !strings.Contains(err.Error(), "refused") {
				t.Fatalf("err = %v, scans = %d; want the template refused", err, sc.calls)
			}
		})
	}
}

func TestCheckCustomTemplateAcceptsPlainTemplatesAndOtherTypes(t *testing.T) {
	if err := CheckCustomTemplate("nuclei", []byte(sjTemplateBody)); err != nil {
		t.Fatalf("plain http template refused: %v", err)
	}
	inline := "id: x\ninfo:\n  name: x\n  severity: info\nhttp:\n  - payloads:\n      p: [a, b]\n    path: ['{{BaseURL}}/{{p}}']\n"
	if err := CheckCustomTemplate("nuclei", []byte(inline)); err != nil {
		t.Fatalf("inline payloads refused: %v", err)
	}
	if err := CheckCustomTemplate("semgrep", []byte("rules: []\n")); err != nil {
		t.Fatalf("semgrep rules inspected as nuclei: %v", err)
	}
	if err := CheckCustomTemplate("nuclei", []byte("{not yaml")); err == nil {
		t.Fatal("a template that is not YAML was accepted")
	}
}
