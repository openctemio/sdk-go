package toolhost

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// retestTool retests by rule id: "present" is still there, "gone" is
// fixed. It reports every target done.
var retestTool = tool.WithRetest(tool.New(tool.Manifest{
	Name: "retest-tool", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"domain"}, Produces: []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetTargets},
}, func(tool.Context, tool.Task, tool.NoConfig) error { return nil }),
	func(ctx tool.RetestContext, task tool.Task) error {
		for _, it := range task.Retest {
			switch it.RuleID {
			case "present":
				ctx.Verdict(it, tool.StillPresent, "matched")
			case "gone":
				// A networked tool shows the attempt that did not match.
				u, _ := url.Parse("https://" + targetValue(task, it.Target) + "/check")
				ex, _ := tool.HTTPExchange(&http.Request{Method: "GET", URL: u}, nil, &http.Response{StatusCode: 404}, []byte("not found"))
				ctx.Report(it, tool.VerdictReport{Verdict: tool.Fixed, Detail: "no match on a reachable target", Evidence: []ctis.EvidenceItem{ex}})
			}
		}
		for _, t := range task.Targets {
			ctx.TargetDone(t)
		}
		return nil
	})

func targetValue(task tool.Task, ref string) string {
	for _, t := range task.Targets {
		if t.Ref == ref {
			return t.Value
		}
	}
	return ""
}

func retestTask() tool.Task {
	return tool.Task{
		Targets: []tool.Target{{Ref: "t1", Type: "domain", Value: "a.example"}, {Ref: "t2", Type: "domain", Value: "b.example"}},
		Retest: []tool.RetestItem{
			{Ref: "f1", Target: "t1", Kind: tool.RetestFinding, RuleID: "present"},
			{Ref: "f2", Target: "t1", Kind: tool.RetestFinding, RuleID: "gone"},
			{Ref: "f3", Target: "t2", Kind: tool.RetestFinding, RuleID: "gone"},
		},
	}
}

func verdictsOf(out *Outcome) map[string]tool.Verdict {
	m := map[string]tool.Verdict{}
	for _, v := range out.Verdicts {
		m[v.Ref] = v.Verdict
	}
	return m
}

// A retest runs out of process like any task; an item on a target the
// local policy refuses never reaches the tool and ends unverifiable.
func TestRetestBuiltinWithPolicy(t *testing.T) {
	h := testHost(t)
	h.Policy = &fakePolicy{deny: map[string]bool{"b.example": true}}
	out, err := h.RunBuiltin(context.Background(), retestTool, retestTask(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := verdictsOf(out)
	want := map[string]tool.Verdict{"f1": tool.StillPresent, "f2": tool.Fixed, "f3": tool.Unverifiable}
	for ref, v := range want {
		if got[ref] != v {
			t.Errorf("%s: %s, want %s (outcome %+v, stderr %s)", ref, got[ref], v, out.Verdicts, out.Stderr)
		}
	}
	if len(out.Verdicts) != 3 || out.Verdicts[0].Ref != "f1" || out.Verdicts[2].Ref != "f3" {
		t.Fatalf("verdicts not in task order: %+v", out.Verdicts)
	}
	if len(out.Report.Findings) != 0 {
		t.Fatalf("a retest delivered findings: %+v", out.Report.Findings)
	}
}

// A hostile adapter cannot add records to a retest, judge an item it was
// not given, or call fixed an item whose target it never reported done.
func TestRetestHostileAdapter(t *testing.T) {
	m := hostileManifest
	m.Retest = true
	task := retestTask()
	task.Targets, task.Retest = oneTarget, task.Retest[:1]
	out := hostileRun(t, "retest-liar", m, task)
	if out.Err != nil {
		t.Fatalf("the adapter did not run: %v", out.Err)
	}
	if v := verdictsOf(out)["f1"]; v != tool.Unverifiable {
		t.Fatalf("f1: %s, want unverifiable (verdicts %+v)", v, out.Verdicts)
	}
	if out.Stats.Invalid < 2 || len(out.Report.Findings) != 0 {
		t.Fatalf("refused output: invalid %d, findings %d", out.Stats.Invalid, len(out.Report.Findings))
	}
}

// SECURITY: an adapter's verdict evidence is checked again on the host: too
// many or invalid items make the verdict unverifiable, an unmarked
// credential is marked, the evidence and digest of a good verdict travel.
func TestRetestEvidenceFromAHostileAdapter(t *testing.T) {
	m := hostileManifest
	m.Retest = true
	task := tool.Task{Targets: oneTarget, Retest: []tool.RetestItem{
		{Ref: "f1", Target: "t1", Kind: tool.RetestFinding}, {Ref: "f2", Target: "t1", Kind: tool.RetestFinding},
		{Ref: "f3", Target: "t1", Kind: tool.RetestFinding}}}
	out := hostileRun(t, "retest-evidence", m, task)
	if out.Err != nil {
		t.Fatalf("the adapter did not run: %v", out.Err)
	}
	got := map[string]tool.RetestVerdict{}
	for _, v := range out.Verdicts {
		got[v.Ref] = v
	}
	if got["f1"].Verdict != tool.Unverifiable || got["f2"].Verdict != tool.Unverifiable {
		t.Fatalf("bad evidence accepted: %+v", out.Verdicts)
	}
	f3 := got["f3"]
	if f3.Verdict != tool.Fixed || f3.TemplateDigest != "sha256:t" || len(f3.Evidence) != 1 || len(f3.Evidence[0].Sensitive) == 0 {
		t.Fatalf("f3: %+v", f3)
	}
}

func TestRetestRefusedBeforeStart(t *testing.T) {
	h := testHost(t)
	// A tool that does not declare retest.
	out, err := h.RunBuiltin(context.Background(), echoTool, retestTask(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err == nil || out.Err.Class != tool.InvalidInput || out.ExitCode != -1 {
		t.Fatalf("outcome %+v", out.Err)
	}
	for _, v := range out.Verdicts {
		if v.Verdict != tool.Unverifiable {
			t.Fatalf("a refused retest produced %+v", v)
		}
	}
	if len(out.Verdicts) != 3 {
		t.Fatalf("verdicts %+v", out.Verdicts)
	}
	// An item on a target that is not in the task.
	task := retestTask()
	task.Retest[0].Target = "t9"
	if out, _ := h.RunBuiltin(context.Background(), retestTool, task, RunOptions{}); out.Err == nil || out.Err.Class != tool.InvalidInput {
		t.Fatalf("item on an unknown target: %+v", out.Err)
	}
	// The exec profile has no verdict channel.
	m := retestTool.Manifest()
	m.Run = &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{"/bin/true"}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}}
	if err := m.Validate(); err == nil {
		t.Fatal("an exec-profile manifest declaring retest must be refused")
	}
	m.Retest = false
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exe, _ := os.Executable()
	m.Run.Argv = []string{exe}
	if out, err := h.RunManifest(ctx, m, retestTask(), RunOptions{Trusted: true}); err != nil || out.Err == nil || out.Err.Class != tool.InvalidInput {
		t.Fatalf("exec profile retest: %v %+v", err, out)
	}
}
