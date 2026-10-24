package toolrt

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

func retestAsm(t *testing.T) *Assembler {
	t.Helper()
	m := testManifest
	m.Retest = true
	task := tool.Task{ID: "r", Targets: []tool.Target{{Ref: "t0", Value: "https://a.example"}, {Ref: "t1", Value: "https://b.example"}},
		Retest: []tool.RetestItem{
			{Ref: "i0", Target: "t0", Kind: tool.RetestFinding, RuleID: "x"},
			{Ref: "i1", Target: "t1", Kind: tool.RetestFinding, RuleID: "x"},
		}}
	return NewAssembler(m.Normalized(), task, NewChecker(m.Normalized()))
}

// An item the tool never judged says why: the item's target failed, was
// skipped, or the run stopped. It is never a bare "no verdict".
func TestMissingVerdictSaysWhy(t *testing.T) {
	a := retestAsm(t)
	_ = a.Target("t0", tool.StateFailed, tool.Unreachable(errString("dial tcp: no route")).(*tool.Error))
	_ = a.Target("t1", tool.StateSkipped, &tool.Error{Class: tool.InvalidInput})
	vs := a.Verdicts(nil)
	if vs[0].Code != tool.CodeTargetUnreachable || !strings.Contains(vs[0].Detail, "could not connect") {
		t.Errorf("unreachable target: %+v", vs[0])
	}
	if vs[1].Code != tool.CodeNoVerdict || !strings.Contains(vs[1].Detail, "skipped") {
		t.Errorf("skipped target: %+v", vs[1])
	}
	b := retestAsm(t)
	vs = b.Verdicts(&tool.Error{Class: tool.ToolCrashed})
	if vs[0].Code != tool.CodeNoVerdict || !strings.Contains(vs[0].Detail, "tool_crashed") {
		t.Errorf("stopped run: %+v", vs[0])
	}
}

// A tool's own code is kept on an unverifiable verdict only when it is one
// of the known codes; anything else is dropped.
func TestVerdictCodeIsClosedSet(t *testing.T) {
	a := retestAsm(t)
	_ = a.Verdict("i0", tool.VerdictReport{Verdict: tool.Unverifiable, Detail: "x", Code: tool.CodeTemplateNotFound})
	_ = a.Verdict("i1", tool.VerdictReport{Verdict: tool.Unverifiable, Detail: "x", Code: "made_up"})
	_ = a.Target("t0", tool.StateDone, nil)
	_ = a.Target("t1", tool.StateDone, nil)
	vs := a.Verdicts(nil)
	if vs[0].Code != tool.CodeTemplateNotFound || vs[1].Code != "" {
		t.Fatalf("%+v", vs)
	}
	// The tool cannot see the sensor's confinement: its egress_refused
	// claim is dropped.
	e := retestAsm(t)
	_ = e.Verdict("i0", tool.VerdictReport{Verdict: tool.Unverifiable, Code: tool.CodeEgressRefused})
	_ = e.Target("t0", tool.StateDone, nil)
	if got := e.Verdicts(nil)[0].Code; got != "" {
		t.Fatalf("a tool's egress_refused kept: %q", got)
	}
	c := retestAsm(t)
	_ = c.Verdict("i0", tool.VerdictReport{Verdict: tool.StillPresent, Code: tool.CodeNoVerdict})
	if c.Verdicts(nil)[0].Code != "" {
		t.Fatal("a code on a conclusive verdict must be dropped")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
