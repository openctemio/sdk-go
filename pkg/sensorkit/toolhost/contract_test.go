package toolhost

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// contractTool implements vuln.templates@1: the workflow's severity and
// rate reach it as its own keys sev and rate. It reports what it received in
// the finding title; with bad set it emits a finding without a rule id.
var contractTool = tool.Define("contract-tool", "1.0.0").
	ImplementsWith(tool.Implementation{Capability: "vuln.templates@1", Params: map[string]tool.ParamMapping{
		"severity": {Key: "sev", Values: []string{"high", "critical"}},
		"rate":     {Max: intPtr(500)},
	}}).
	Targets("domain").
	Produces("finding:vulnerability").
	Params(tool.ListParam("sev"), tool.IntParam("rate").Default(100).Range(1, 1000), tool.BoolParam("bad")).
	Manifest(func(m *tool.Manifest) {
		m.Safety = &tool.Safety{RateParam: "rate"}
		m.Permissions.Network = tool.NetNone
	}).
	Handle(func(ctx tool.Context, job *tool.Job, emit tool.Emit) error {
		for _, t := range job.Targets() {
			title := fmt.Sprintf("sev=%s rate=%d", strings.Join(job.Param("sev").Strings(), "+"), job.Param("rate").Int())
			f := ctis.Finding{Type: ctis.FindingTypeVulnerability, RuleID: "r1", Title: title, Severity: ctis.SeverityHigh}
			if job.Param("bad").Bool() {
				f.RuleID = ""
			}
			if err := emit.CTIS().Finding(t, f); err != nil {
				return err
			}
			ctx.TargetDone(t)
		}
		return nil
	}).MustBuild()

func intPtr(n int) *int { return &n }

// ratePolicy admits everything and caps the rate.
type ratePolicy struct {
	fakePolicy
	max int
}

func (r *ratePolicy) CapRate(requested int) int {
	if requested <= 0 || requested > r.max {
		return r.max
	}
	return requested
}

func runContract(t *testing.T, h *Host, task tool.Task) *Outcome {
	t.Helper()
	if task.Targets == nil {
		task.Targets = oneTarget
	}
	out, err := h.RunBuiltin(context.Background(), contractTool, task, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func params(kv ...string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = json.RawMessage(kv[i+1])
	}
	return out
}

func TestStandardParamsReachTheToolAsItsKeys(t *testing.T) {
	out := runContract(t, testHost(t), tool.Task{Capability: "vuln.templates@1", Params: params("severity", `["high"]`, "rate", `50`)})
	if out.Status != tool.StatusOK || len(out.Report.Findings) != 1 {
		t.Fatalf("status %s err %v stderr %s", out.Status, out.Err, out.Stderr)
	}
	if got := out.Report.Findings[0].Title; got != "sev=high rate=50" {
		t.Fatalf("the tool received %q", got)
	}
	prov, _ := json.Marshal(out.Report.Metadata.Properties["provenance"])
	if !strings.Contains(string(prov), `"capability":"vuln.templates@1"`) {
		t.Fatalf("provenance lacks the capability: %s", prov)
	}
}

// SECURITY: the local policy caps the rate whatever the workflow asked,
// and sets it when the workflow left it to the tool's default.
func TestLocalPolicyCapsTheRate(t *testing.T) {
	h := testHost(t)
	h.Policy = &ratePolicy{max: 10}
	out := runContract(t, h, tool.Task{Capability: "vuln.templates@1", Params: params("rate", `400`)})
	if out.Status != tool.StatusOK || out.Report.Findings[0].Title != "sev= rate=10" {
		t.Fatalf("status %s title %q err %v", out.Status, out.Report.Findings[0].Title, out.Err)
	}
	if !strings.Contains(fmt.Sprint(out.Logs), "set rate to 10 (asked 400)") {
		t.Fatalf("the cap is not logged: %+v", out.Logs)
	}
	out = runContract(t, h, tool.Task{})
	if out.Report.Findings[0].Title != "sev= rate=10" {
		t.Fatalf("default rate not capped: %q", out.Report.Findings[0].Title)
	}
}

func TestContractRefusalsBeforeStart(t *testing.T) {
	cases := map[string]struct {
		task  tool.Task
		class tool.ErrorClass
		want  string
	}{
		"param the tool does not take":    {tool.Task{Capability: "vuln.templates@1", Params: params("exclude_tags", `["dos"]`)}, tool.InvalidInput, "does not take"},
		"value the tool does not support": {tool.Task{Capability: "vuln.templates@1", Params: params("severity", `["low"]`)}, tool.InvalidInput, "not supported by this tool"},
		"value outside the capability":    {tool.Task{Capability: "vuln.templates@1", Params: params("severity", `["urgent"]`)}, tool.InvalidInput, "not one of"},
		"rate above the tool's maximum":   {tool.Task{Capability: "vuln.templates@1", Params: params("rate", `900`)}, tool.InvalidInput, "maximum 500 of this tool"},
		"params without capability":       {tool.Task{Params: params("rate", `5`)}, tool.InvalidInput, "need the task's capability"},
		"capability not implemented":      {tool.Task{Capability: "scan.ports@1"}, tool.InvalidInput, "does not implement"},
		"config conflicts with the param": {tool.Task{Capability: "vuln.templates@1", Params: params("rate", `50`), Config: json.RawMessage(`{"rate":60}`)}, tool.InvalidInput, "another value"},
		"tier above the job's ceiling":    {tool.Task{Capability: "vuln.templates@1", MaxTier: tool.T0}, tool.RefusedByPolicy, "allows at most T0"},
		"invalid web scope":               {tool.Task{WebScope: &webscope.Scope{Methods: []string{"TRACE"}}}, tool.RefusedByPolicy, "web scope"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := runContract(t, testHost(t), tc.task)
			if out.Status != tool.StatusFailed || out.Err == nil || out.Err.Class != tc.class || !strings.Contains(out.Err.Detail, tc.want) {
				t.Fatalf("status %s err %+v", out.Status, out.Err)
			}
			if len(out.Report.Findings) != 0 {
				t.Fatal("the tool ran")
			}
		})
	}
}

func TestContractViolationsMakeTheTaskPartial(t *testing.T) {
	out := runContract(t, testHost(t), tool.Task{Capability: "vuln.templates@1", Config: json.RawMessage(`{"bad":true}`)})
	if out.Status != tool.StatusPartial || out.Stats.ContractViolations != 1 {
		t.Fatalf("status %s stats %+v", out.Status, out.Stats)
	}
	if !strings.Contains(fmt.Sprint(out.Logs), "miss the contract of vuln.templates@1") {
		t.Fatalf("not logged: %+v", out.Logs)
	}
	// Records are still delivered: the platform decides (warn or quarantine).
	if len(out.Report.Findings) != 1 {
		t.Fatal("records dropped")
	}
	// Without a capability there is no contract to check.
	out = runContract(t, testHost(t), tool.Task{Config: json.RawMessage(`{"bad":true}`)})
	if out.Status != tool.StatusOK || out.Stats.ContractViolations != 0 {
		t.Fatalf("status %s stats %+v", out.Status, out.Stats)
	}
}
