package playbook

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/harness"
	"github.com/openctemio/sdk-go/pkg/harness/contract"
)

const samplePath = "../../../examples/playbooks/web-vuln-triage/playbook.yaml"

func sample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSamplePlaybookLoadsAndRenders(t *testing.T) {
	p, err := Parse(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "web-vuln-triage@1.0.0" || !strings.HasPrefix(p.Digest(), "sha256:") {
		t.Fatalf("%s %s", p.ID(), p.Digest())
	}
	in := p.Render()
	if in.ID != p.ID() || in.Digest != p.Digest() || len(in.Tools) != 1 || in.Budgets.ToolCalls != 3 {
		t.Fatalf("%+v", in)
	}
	for _, want := range []string{"1. read:", "(tools: http.probe)", "Always read and cite: bundle:finding.evidence", "Rules:"} {
		if !strings.Contains(in.Text, want) {
			t.Errorf("rendered text lacks %q", want)
		}
	}
	if !p.Matches("dast", "web") || p.Matches("dast", "cloud") {
		t.Fatal("match")
	}
}

func TestParseRefusesBadPlaybooks(t *testing.T) {
	good := string(sample(t))
	cases := map[string]string{
		"unknown key":          good + "\nauto_apply: true\n",
		"wrong apiVersion":     strings.Replace(good, "openctem.io/playbook/v1", "openctem.io/playbook/v9", 1),
		"not semver":           strings.Replace(good, "version: 1.0.0", "version: latest", 1),
		"unknown output":       strings.Replace(good, "output: openctem.ai.triage/v1", "output: openctem.ai.anything/v1", 1),
		"bad tier":             strings.Replace(good, "model_tier: small", "model_tier: huge", 1),
		"step tool not listed": strings.Replace(good, "    tools: [http.probe]", "    tools: [port.scan]", 1),
		"budget too large":     strings.Replace(good, "steps: 6", "steps: 999", 1),
		"evidence not bundle":  strings.Replace(good, "[bundle:finding.evidence]", "[tool:1]", 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestDigestChangesWithAnyByte(t *testing.T) {
	a, _ := Parse(sample(t))
	b, _ := Parse(append(sample(t), '\n'))
	if a.Digest() == b.Digest() {
		t.Fatal("digest ignores content")
	}
}

// The playbook can only narrow the grant: a tool the grant has but the
// playbook does not list is never offered.
func TestPlaybookNarrowsTheGrantInARun(t *testing.T) {
	p, _ := Parse(sample(t))
	in := p.Render()
	reg, err := harness.NewRegistry(harness.Grant{Tools: []string{"http.probe", "port.scan"}, TierCeiling: harness.TierSafe}, in.Tools,
		stub("http.probe"), stub("port.scan"))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("offered %d tools", reg.Len())
	}
}

func TestRequiredEvidenceVerifier(t *testing.T) {
	p, _ := Parse(sample(t))
	v := p.RequireEvidence()
	refs := map[string]bool{"bundle:finding.evidence": true, "bundle:finding.title": true}
	missing := &contract.Output{Suggestions: []contract.Suggestion{{Kind: "verdict", Evidence: []contract.Evidence{{Ref: "bundle:finding.title"}}}}}
	var ve *harness.VerifyError
	if err := v(context.Background(), harness.Job{}, missing, refs); !errors.As(err, &ve) || ve.Code != CodeMissingEvidence {
		t.Fatalf("got %v", err)
	}
	ok := &contract.Output{Suggestions: []contract.Suggestion{{Kind: "verdict", Evidence: []contract.Evidence{{Ref: "bundle:finding.evidence"}}}}}
	if err := v(context.Background(), harness.Job{}, ok, refs); err != nil {
		t.Fatal(err)
	}
	// A withheld field is not required.
	if err := v(context.Background(), harness.Job{}, missing, map[string]bool{"bundle:finding.title": true}); err != nil {
		t.Fatal(err)
	}
}

type stubTool struct{ name string }

func stub(n string) stubTool { return stubTool{name: n} }

func (s stubTool) Def() harness.ToolDef {
	return harness.ToolDef{Spec: harness.ToolSpec{Name: s.name}, Class: harness.ClassSensorJob, Tier: harness.TierSafe}
}

func (s stubTool) Call(context.Context, json.RawMessage) (string, error) { return "", nil }
