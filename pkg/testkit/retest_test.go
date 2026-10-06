package testkit_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

var checkManifest = tool.Manifest{
	Name: "check", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"domain"}, Produces: []string{"finding:vulnerability"},
	Permissions: tool.Permissions{Network: tool.NetNone,
		Credentials: []tool.CredentialReq{{Name: "api_token", Kind: "token"}}},
}

// checker retests by rule id: "present" is still there, "gone" is fixed,
// "flaky" fails its target, "silent" gets no verdict.
var checker = tool.WithRetest(tool.New(checkManifest, func(tool.Context, tool.Task, tool.NoConfig) error { return nil }),
	func(ctx tool.RetestContext, task tool.Task) error {
		if err := ctx.Emit().Finding(task.Targets[0], ctis.Finding{Type: "vulnerability", Title: "x", Severity: "low"}); !errors.Is(err, tool.ErrRetestRecord) {
			return tool.Failed(errors.New("a record was accepted in a retest task"))
		}
		secret, _ := ctx.Secret("api_token")
		byTarget := map[string]tool.Target{}
		for _, t := range task.Targets {
			byTarget[t.Ref] = t
		}
		failed := map[string]bool{}
		for _, it := range task.Retest {
			switch it.RuleID {
			case "present":
				ctx.Verdict(it, tool.StillPresent, "matched again with "+secret.Reveal())
			case "gone":
				ctx.Verdict(it, tool.Fixed, "no match")
				ctx.Verdict(it, tool.StillPresent, "a second verdict does not count")
			case "flaky":
				ctx.Verdict(it, tool.Fixed, "claims fixed on a target it did not reach")
				failed[it.Target] = true
			}
		}
		ctx.Verdict(tool.RetestItem{Ref: "not-in-task"}, tool.Fixed, "")
		for ref, t := range byTarget {
			if failed[ref] {
				ctx.TargetError(t, tool.Unreachable(errors.New("no answer")))
				continue
			}
			ctx.TargetDone(t)
		}
		return nil
	})

func retestTask() tool.Task {
	return tool.Task{
		Targets: []tool.Target{{Ref: "t1", Type: "domain", Value: "a.example"}, {Ref: "t2", Type: "domain", Value: "b.example"}},
		Retest: []tool.RetestItem{
			{Ref: "f-present", Target: "t1", Kind: tool.RetestFinding, RuleID: "present"},
			{Ref: "f-gone", Target: "t1", Kind: tool.RetestFinding, RuleID: "gone"},
			{Ref: "f-flaky", Target: "t2", Kind: tool.RetestFinding, RuleID: "flaky"},
			{Ref: "f-silent", Target: "t1", Kind: tool.RetestFinding, RuleID: "silent"},
		},
	}
}

func TestRetestVerdicts(t *testing.T) {
	if !checker.Manifest().Retest {
		t.Fatal("WithRetest must declare retest in the manifest")
	}
	res := testkit.Run(t, checker, retestTask(), testkit.Options{Secrets: map[string]string{"api_token": "s3cr3t-value"}})
	if res.Err != nil {
		t.Fatalf("run error: %v", res.Err)
	}
	want := map[string]tool.Verdict{
		"f-present": tool.StillPresent, "f-gone": tool.Fixed, "f-flaky": tool.Unverifiable, "f-silent": tool.Unverifiable,
	}
	if len(res.Verdicts) != len(want) {
		t.Fatalf("verdicts %+v", res.Verdicts)
	}
	for i, v := range res.Verdicts {
		if v.Verdict != want[v.Ref] {
			t.Errorf("%s: %s (%s), want %s", v.Ref, v.Verdict, v.Detail, want[v.Ref])
		}
		if v.Ref != retestTask().Retest[i].Ref {
			t.Errorf("verdict %d is %s: not in task order", i, v.Ref)
		}
		if v.Ref == "f-present" && v.Detail != "matched again with "+tool.Redacted {
			t.Errorf("detail not redacted: %q", v.Detail)
		}
	}
	if len(res.Report.Findings) != 0 {
		t.Fatalf("a retest delivered records: %+v", res.Report.Findings)
	}
}

func TestRetestFixedNeedsAFinishedTask(t *testing.T) {
	tl := tool.WithRetest(tool.New(checkManifest, func(tool.Context, tool.Task, tool.NoConfig) error { return nil }),
		func(ctx tool.RetestContext, task tool.Task) error {
			ctx.Verdict(task.Retest[0], tool.Fixed, "")
			ctx.TargetDone(task.Targets[0])
			return tool.Failed(errors.New("crashed after the verdict"))
		})
	task := retestTask()
	task.Retest = task.Retest[:1]
	res := testkit.Run(t, tl, task)
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != tool.Unverifiable {
		t.Fatalf("verdicts %+v", res.Verdicts)
	}
}

func TestRetestRefusals(t *testing.T) {
	plain := tool.New(checkManifest, func(tool.Context, tool.Task, tool.NoConfig) error { return nil })
	res := testkit.Run(t, plain, retestTask())
	if res.Err == nil || res.Err.Class != tool.InvalidInput {
		t.Fatalf("a retest task for a tool without retest: %v", res.Err)
	}

	for name, mutate := range map[string]func(*tool.Task){
		"target not in task": func(task *tool.Task) { task.Retest[0].Target = "t9" },
		"duplicate ref":      func(task *tool.Task) { task.Retest[1].Ref = task.Retest[0].Ref },
		"empty ref":          func(task *tool.Task) { task.Retest[0].Ref = "" },
		"unknown kind":       func(task *tool.Task) { task.Retest[0].Kind = "host" },
		"too many items": func(task *tool.Task) {
			for i := range tool.MaxRetestItems {
				task.Retest = append(task.Retest, tool.RetestItem{Ref: fmt.Sprintf("x%d", i), Target: "t1", Kind: tool.RetestAsset})
			}
		},
	} {
		task := retestTask()
		mutate(&task)
		res := testkit.Run(t, checker, task)
		if res.Err == nil || res.Err.Class != tool.InvalidInput {
			t.Errorf("%s: %v", name, res.Err)
		}
		for _, v := range res.Verdicts {
			if v.Verdict != tool.Unverifiable {
				t.Errorf("%s: a refused task produced %s for %s", name, v.Verdict, v.Ref)
			}
		}
	}
}

func TestRetestManifestRules(t *testing.T) {
	m := checkManifest
	m.Retest = true
	if err := m.Validate(); err != nil {
		t.Fatalf("target-scan with retest: %v", err)
	}
	m.Class, m.Consumes, m.Permissions = tool.Parser, []string{"file:application/json"}, tool.Permissions{}
	if err := m.Validate(); err == nil {
		t.Fatal("a parser declaring retest must be refused")
	}
	if checkManifest.Digest() == checker.Manifest().Digest() {
		t.Fatal("declaring retest must change the manifest digest")
	}
	if _, err := tool.LoadManifest([]byte("apiVersion: openctem.io/tool/v1\nname: check\nversion: 1.0.0\nclass: target-scan\ntier: T1\nconsumes: [domain]\nproduces: [finding:vulnerability]\nretest: true\nrun:\n  argv: [./check]\n")); err != nil {
		t.Fatalf("tool.yaml with retest: %v", err)
	}
}
