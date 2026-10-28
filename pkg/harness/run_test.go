package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/harness/contract"
)

type fakeTool struct {
	def   ToolDef
	out   string
	err   error
	calls atomic.Int32
	delay time.Duration
	live  *atomic.Int32
	peak  *atomic.Int32
}

func (f *fakeTool) Def() ToolDef { return f.def }

func (f *fakeTool) Call(_ context.Context, _ json.RawMessage) (string, error) {
	f.calls.Add(1)
	if f.live != nil {
		n := f.live.Add(1)
		for {
			p := f.peak.Load()
			if n <= p || f.peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer f.live.Add(-1)
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.out, f.err
}

const probeSchema = `{"type":"object","additionalProperties":false,"required":["target"],
 "properties":{"target":{"type":"string"},"path":{"type":"string","maxLength":200}}}`

func probe(name string, tier Tier) *fakeTool {
	return &fakeTool{
		def: ToolDef{Spec: ToolSpec{Name: name, Description: "probe", InputSchema: json.RawMessage(probeSchema)},
			Class: ClassSensorJob, Tier: tier, Targets: []string{"target"}},
		out: "HTTP/1.1 200 OK\nbody contains marker-7731",
	}
}

var t0 = time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)

func baseJob() Job {
	return Job{
		ID: "01a18087-4972-7af5-8ce4-36833fe53fc4", TenantID: "tenant-a", Kind: "triage.v1",
		OutputSchema: contract.OutputTriageV1,
		Bundle: map[string]string{
			"finding.title":    "Reflected input on HOST_K3F9QA",
			"finding.evidence": "GET /search?q=marker-7731 echoed",
		},
		Grant: Grant{
			Tools:       []string{"http.probe", "port.scan", "heavy.tool"},
			Targets:     []TargetBinding{{Token: "HOST_K3F9QA", Value: "app.example.com"}},
			TierCeiling: TierSafe,
			Budgets:     Budgets{Steps: 6, ToolCalls: 4, Tokens: 50000, Seconds: 60},
		},
		Deadline: t0.Add(time.Hour),
	}
}

func instr() Instructions {
	return Instructions{ID: "web-vuln-triage@1.0.0", Digest: "sha256:" + strings.Repeat("a", 64), Text: "Confirm or refute the finding."}
}

func call(id, name, args string) ToolCall {
	return ToolCall{ID: id, Name: name, Args: json.RawMessage(args)}
}

func toolTurn(calls ...ToolCall) Response {
	return Response{Message: Message{Role: RoleAssistant, ToolCalls: calls}, Stop: StopToolUse, Usage: Usage{InputTokens: 1000, OutputTokens: 50}}
}

func answer(text string) Response {
	return Response{Message: Message{Role: RoleAssistant, Text: text}, Stop: StopEnd, Usage: Usage{InputTokens: 1200, OutputTokens: 200}}
}

const tpAnswer = `{"suggestions":[{"kind":"verdict","payload":{"verdict":"true_positive","reason":"The marker is echoed back."},"confidence":0.9,"evidence":[{"ref":"tool:1","quote":"marker-7731"},{"ref":"bundle:finding.evidence"}]}]}`

const tpBundleOnly = `{"suggestions":[{"kind":"verdict","payload":{"verdict":"true_positive","reason":"Echoed."},"confidence":0.7,"evidence":[{"ref":"bundle:finding.evidence"}]}]}`

func newRun(p Provider, tools ...Tool) *Run {
	return &Run{Job: baseJob(), Instructions: instr(), Provider: p, Model: "small-model", Tools: tools,
		Now: func() time.Time { return t0 }}
}

func TestRunCallsAGrantedToolAndCompletes(t *testing.T) {
	tool := probe("http.probe", TierSafe)
	p := &Replay{Turns: []Response{
		toolTurn(call("c1", "http.probe", `{"target":"HOST_K3F9QA","path":"/search"}`)),
		answer(tpAnswer),
	}}
	var rec bytes.Buffer
	run := newRun(p, tool)
	run.Recorder = NewJSONLRecorder(&rec)
	res, err := run.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusCompleted || res.ErrorCode != "" {
		t.Fatalf("status %s %s", res.Status, res.ErrorCode)
	}
	if tool.calls.Load() != 1 || res.Usage.ToolCalls != 1 || res.Usage.Steps != 2 {
		t.Fatalf("tool calls %d usage %+v", tool.calls.Load(), res.Usage)
	}
	if !strings.HasPrefix(res.RecordDigest, "sha256:") || res.ToolOutputs["tool:1"] == "" {
		t.Fatalf("record %q outputs %v", res.RecordDigest, res.ToolOutputs)
	}
	reqs := p.Requests()
	if len(reqs) != 2 || len(reqs[0].Tools) != 1 || reqs[0].Tools[0].Name != "http.probe" {
		t.Fatalf("requests %+v", reqs)
	}
	if strings.Contains(reqs[0].System, "Reflected input") {
		t.Fatal("bundle text reached the system prompt")
	}
	last := reqs[1].Messages[len(reqs[1].Messages)-1]
	if last.Role != RoleTool || !strings.Contains(last.ToolResults[0].Content, `<untrusted ref="tool:1"`) {
		t.Fatalf("tool result not fenced: %+v", last)
	}
	doc, err := res.ContractResult(run.Job.ID, run.Instructions, false)
	if err != nil {
		t.Fatalf("result/v1 refused: %v", err)
	}
	if !bytes.Contains(doc, []byte(`"status":"completed"`)) {
		t.Fatalf("%s", doc)
	}
	if n := bytes.Count(rec.Bytes(), []byte("\n")); n < 6 {
		t.Fatalf("record has %d events", n)
	}
}

func TestRunPolicyRefusesCallsOutsideTheGrant(t *testing.T) {
	granted := probe("http.probe", TierSafe)
	notGranted := probe("dns.lookup", TierPassive)
	t2 := probe("heavy.tool", TierIntrusive)
	p := &Replay{Turns: []Response{
		toolTurn(
			call("a", "dns.lookup", `{"target":"HOST_K3F9QA"}`),             // not in the grant
			call("b", "http.probe", `{"target":"other.example.net"}`),       // raw target, not a bound placeholder
			call("c", "http.probe", `{"target":"HOST_ZZZZZZ"}`),             // placeholder of no binding
			call("d", "http.probe", `{"target":"HOST_K3F9QA","extra":"x"}`), // outside the input schema
			call("e", "heavy.tool", `{"target":"HOST_K3F9QA"}`),             // intrusive: withheld
			call("f", "http.probe", `not json`),
		),
		answer(tpBundleOnly),
	}}
	res, err := newRun(p, granted, notGranted, t2).Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if granted.calls.Load()+notGranted.calls.Load()+t2.calls.Load() != 0 {
		t.Fatal("a refused call reached a tool")
	}
	want := []string{CodeOutsideGrant, CodeTargetNotBound, CodeTargetNotBound, CodeInvalidArgs, CodeOutsideGrant, CodeInvalidArgs}
	if len(res.Denials) != len(want) {
		t.Fatalf("denials %+v", res.Denials)
	}
	for i, d := range res.Denials {
		if d.Code != want[i] {
			t.Errorf("denial %d: %s, want %s", i, d.Code, want[i])
		}
	}
	if res.Status != StatusCompleted || res.Usage.ToolCalls != 0 {
		t.Fatalf("%s tool calls %d", res.Status, res.Usage.ToolCalls)
	}
}

func TestGrantPolicyIntrusiveNeedsAPerson(t *testing.T) {
	pol := NewGrantPolicy(baseJob().Grant)
	def := probe("heavy.tool", TierIntrusive).Def()
	if d := pol.Decide(context.Background(), call("x", "heavy.tool", `{"target":"HOST_K3F9QA"}`), def); d.Code != CodeNeedsApproval {
		t.Fatalf("got %+v", d)
	}
}

func TestRunEvidenceMustResolveAndOneRepairIsAllowed(t *testing.T) {
	bad := `{"suggestions":[{"kind":"verdict","payload":{"verdict":"true_positive","reason":"r"},"confidence":0.9,"evidence":[{"ref":"tool:9"}]}]}`
	p := &Replay{Turns: []Response{answer(bad), answer(tpBundleOnly)}}
	res, _ := newRun(p).Execute(context.Background())
	if res.Status != StatusCompleted || res.Repairs != 1 {
		t.Fatalf("%s repairs %d", res.Status, res.Repairs)
	}
	p2 := &Replay{Turns: []Response{answer(bad), answer(bad)}}
	res2, _ := newRun(p2).Execute(context.Background())
	if res2.Status != StatusIncomplete || res2.ErrorCode != ErrCodeUnresolvedEvid || res2.Output != nil {
		t.Fatalf("%s %s", res2.Status, res2.ErrorCode)
	}
}

func TestRunRiskLoweringVerdictMustCiteEvidence(t *testing.T) {
	uncited := `{"suggestions":[{"kind":"verdict","payload":{"verdict":"likely_false_positive","reason":"r"},"confidence":0.9,"evidence":[]}]}`
	p := &Replay{Turns: []Response{answer(uncited), answer(uncited)}}
	res, _ := newRun(p).Execute(context.Background())
	if res.Status != StatusIncomplete || res.ErrorCode != ErrCodeUncitedLowering {
		t.Fatalf("%s %s", res.Status, res.ErrorCode)
	}
}

func TestRunProseOrExtraKeysAreRefused(t *testing.T) {
	p := &Replay{Turns: []Response{answer("Looks fine to me."), answer(`{"suggestions":[],"approve":true}`)}}
	res, _ := newRun(p).Execute(context.Background())
	if res.Status != StatusIncomplete || res.ErrorCode != ErrCodeInvalidOutput {
		t.Fatalf("%s %s", res.Status, res.ErrorCode)
	}
}

func TestRunToolBudgetStopsToolsAndAsksForAFinalAnswer(t *testing.T) {
	tool := probe("http.probe", TierSafe)
	p := &Replay{Turns: []Response{
		toolTurn(call("1", "http.probe", `{"target":"HOST_K3F9QA"}`), call("2", "http.probe", `{"target":"HOST_K3F9QA"}`)),
		answer(tpAnswer),
	}}
	run := newRun(p, tool)
	run.Job.Grant.Budgets.ToolCalls = 1
	res, _ := run.Execute(context.Background())
	if tool.calls.Load() != 1 || len(res.Denials) != 1 || res.Denials[0].Code != CodeBudgetExhausted {
		t.Fatalf("calls %d denials %+v", tool.calls.Load(), res.Denials)
	}
	if res.Status != StatusCompleted || !res.BudgetStopped {
		t.Fatalf("%s stopped %v", res.Status, res.BudgetStopped)
	}
	if reqs := p.Requests(); len(reqs[1].Tools) != 0 {
		t.Fatal("tools offered after the budget stop")
	}
}

func TestRunAModelThatNeverStopsIsBounded(t *testing.T) {
	tool := probe("http.probe", TierSafe)
	turns := make([]Response, 20)
	for i := range turns {
		turns[i] = toolTurn(call("x", "http.probe", `{"target":"HOST_K3F9QA"}`))
	}
	p := &Replay{Turns: turns}
	run := newRun(p, tool)
	run.Job.Grant.Budgets = Budgets{Steps: 3, ToolCalls: 10, Tokens: 50000, Seconds: 60}
	res, _ := run.Execute(context.Background())
	if res.Status != StatusIncomplete || res.ErrorCode != ErrCodeBudget {
		t.Fatalf("%s %s", res.Status, res.ErrorCode)
	}
	if n := len(p.Requests()); n > 5 {
		t.Fatalf("%d model calls for a 3-step budget", n)
	}
}

func TestRunProviderErrorTextNeverReachesTheResult(t *testing.T) {
	res, _ := newRun(failing{}).Execute(context.Background())
	if res.Status != StatusFailed || res.ErrorCode != ErrCodeProvider {
		t.Fatalf("%s %s", res.Status, res.ErrorCode)
	}
}

type failing struct{}

func (failing) Name() string { return "failing" }
func (failing) Complete(context.Context, Request) (Response, error) {
	return Response{}, errors.New("upstream said: key sk-live-123 invalid")
}

func TestRunPastDeadlineIsRefusedBeforeAnyModelCall(t *testing.T) {
	p := &Replay{Turns: []Response{answer(tpAnswer)}}
	run := newRun(p)
	run.Job.Deadline = t0.Add(-time.Second)
	res, _ := run.Execute(context.Background())
	if res.Status != StatusRefused || len(p.Requests()) != 0 {
		t.Fatalf("%s %d", res.Status, len(p.Requests()))
	}
}

func TestRunParallelToolCallsKeepOrderAndRespectTheLimit(t *testing.T) {
	var live, peak atomic.Int32
	tool := probe("http.probe", TierSafe)
	tool.delay, tool.live, tool.peak = 20*time.Millisecond, &live, &peak
	calls := make([]ToolCall, 4)
	for i := range calls {
		calls[i] = call(string(rune('a'+i)), "http.probe", `{"target":"HOST_K3F9QA"}`)
	}
	p := &Replay{Turns: []Response{toolTurn(calls...), answer(tpAnswer)}}
	run := newRun(p, tool)
	run.MaxParallelTools = 2
	res, _ := run.Execute(context.Background())
	if res.Status != StatusCompleted || peak.Load() > 2 || peak.Load() < 2 {
		t.Fatalf("%s peak %d", res.Status, peak.Load())
	}
	results := p.Requests()[1].Messages[2].ToolResults
	for i, r := range results {
		if r.CallID != calls[i].ID || !strings.Contains(r.Content, `ref="tool:`+string(rune('1'+i))+`"`) {
			t.Fatalf("result %d out of order: %+v", i, r)
		}
	}
}

func TestRunCacheKeyIsPerOrganization(t *testing.T) {
	pa := &Replay{Turns: []Response{answer(tpBundleOnly)}}
	pb := &Replay{Turns: []Response{answer(tpBundleOnly)}}
	ra, rb := newRun(pa), newRun(pb)
	rb.Job.TenantID = "tenant-b"
	_, _ = ra.Execute(context.Background())
	_, _ = rb.Execute(context.Background())
	if pa.Requests()[0].CacheKey == pb.Requests()[0].CacheKey {
		t.Fatal("two organizations share a prompt cache key")
	}
}

func TestReplayWithTheRecordedNonceIsDeterministic(t *testing.T) {
	digest := func() string {
		p := &Replay{Turns: []Response{toolTurn(call("c1", "http.probe", `{"target":"HOST_K3F9QA"}`)), answer(tpAnswer)}}
		run := newRun(p, probe("http.probe", TierSafe))
		run.Fence = FenceWithNonce("0011223344556677")
		run.Recorder = NewJSONLRecorder(&bytes.Buffer{})
		res, _ := run.Execute(context.Background())
		return res.RecordDigest
	}
	if a, b := digest(), digest(); a != b || a == "" {
		t.Fatalf("replay drifted: %s vs %s", a, b)
	}
}
