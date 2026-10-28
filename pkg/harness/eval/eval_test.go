package eval

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/harness"
	"github.com/openctemio/sdk-go/pkg/harness/playbook"
)

const sampleDir = "../../../examples/playbooks/web-vuln-triage"

func load(t *testing.T) (*playbook.Playbook, []Case) {
	t.Helper()
	pb, err := playbook.Load(sampleDir + "/playbook.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := LoadDir(sampleDir + "/golden")
	if err != nil {
		t.Fatal(err)
	}
	return pb, cases
}

func TestSampleGoldenSetPassesTheDefaultGate(t *testing.T) {
	pb, cases := load(t)
	rep, err := Run(context.Background(), pb, cases, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if !r.Pass {
			t.Errorf("%s: %v (status %s %s)", r.Name, r.Reasons, r.Status, r.ErrorCode)
		}
	}
	if err := DefaultGate.Check(rep); err != nil {
		t.Fatal(err)
	}
	if rep.InjectionCases != 1 || rep.RiskLoweringPrecision != 1 || rep.TokensIn == 0 {
		t.Fatalf("%+v", rep)
	}
	// The injection case: both steered tool calls were refused before any tool ran.
	inj := rep.Results[3]
	if inj.Denials != 2 || inj.OutsideGrant != 0 || inj.Status != "incomplete" {
		t.Fatalf("injection case %+v", inj)
	}
}

func TestEvalIsDeterministic(t *testing.T) {
	pb, cases := load(t)
	a, _ := Run(context.Background(), pb, cases, Options{})
	b, _ := Run(context.Background(), pb, cases, Options{})
	for i := range a.Results {
		if a.Results[i].RecordDigest != b.Results[i].RecordDigest {
			t.Fatalf("case %s drifted between two offline runs", a.Results[i].Name)
		}
	}
}

func TestInjectionCaseFailsWhenRiskIsLowered(t *testing.T) {
	pb, cases := load(t)
	c := cases[1] // a well-cited false positive...
	c.Category = CategoryInjection
	c.Name = "lowered-on-injection"
	rep, err := Run(context.Background(), pb, []Case{c}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Pass {
		t.Fatal("risk-lowering output on an injection case passed")
	}
	if err := DefaultGate.Check(rep); !errors.Is(err, ErrGate) {
		t.Fatalf("gate: %v", err)
	}
}

func TestWrongVerdictLowersAgreementAndPrecision(t *testing.T) {
	pb, cases := load(t)
	c := cases[1]
	c.Expect.Verdict = "true_positive" // golden says real; the model lowers it
	rep, _ := Run(context.Background(), pb, []Case{c}, Options{})
	if rep.Agreement != 0 || rep.RiskLoweringPrecision != 0 {
		t.Fatalf("agreement %.2f precision %.2f", rep.Agreement, rep.RiskLoweringPrecision)
	}
	if err := DefaultGate.Check(rep); !errors.Is(err, ErrGate) {
		t.Fatal("gate passed")
	}
}

func TestLiveProviderStillUsesRecordedTools(t *testing.T) {
	pb, cases := load(t)
	live := &harness.Replay{ProviderName: "live-stand-in", Turns: cases[0].Model}
	rep, err := Run(context.Background(), pb, cases[:1], Options{Provider: live, Model: "m"})
	if err != nil || !rep.Results[0].Pass {
		t.Fatalf("%v %+v", err, rep.Results)
	}
}

func TestLoadDirRefusesUnknownKeysAndCategories(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := writeFile(dir+"/"+name, body); err != nil {
			t.Fatal(err)
		}
	}
	write("a.json", `{"name":"a","bundle":{},"grant":{"tools":[],"targets":[],"tier_ceiling":"passive","budgets":{}},"expect":{},"auto_apply":true}`)
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("unknown key accepted")
	}
	write("a.json", `{"name":"a","category":"vip","bundle":{},"grant":{"tools":[],"targets":[],"tier_ceiling":"passive","budgets":{}},"expect":{}}`)
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("unknown category accepted")
	}
}

func writeFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }
