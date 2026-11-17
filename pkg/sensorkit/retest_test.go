package sensorkit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// retestContract retests by rule id: "present" is still there, "gone" is
// fixed.
var retestContract = tool.WithRetest(tool.New(tool.Manifest{
	Name: "kit-retest", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces: []string{"finding:misconfiguration"}, Permissions: tool.Permissions{Network: tool.NetTargets},
}, func(tool.Context, tool.Task, tool.NoConfig) error { return nil }),
	func(ctx tool.RetestContext, task tool.Task) error {
		for _, it := range task.Retest {
			switch it.RuleID {
			case "present":
				ctx.Verdict(it, tool.StillPresent, "matched")
			case "gone":
				// A networked tool shows the attempt that did not match.
				u, _ := url.Parse("https://a.example/check")
				ex, _ := tool.HTTPExchange(&http.Request{Method: "GET", URL: u}, nil, &http.Response{StatusCode: 404}, nil)
				ctx.Report(it, tool.VerdictReport{Verdict: tool.Fixed, Detail: "no match", Evidence: []ctis.EvidenceItem{ex}})
			}
		}
		for _, t := range task.Targets {
			ctx.TargetDone(t)
		}
		return nil
	})

// TestKit_RetestCommand: a tool that declares retest is reported with
// capability retest:<tool>, and a retest command runs it out of process and
// completes with one verdict per item; a command whose item is not on one
// of its targets, or that names a tool without retest, fails.
func TestKit_RetestCommand(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddTool(retestContract)
	k.AddTool(contractTool)
	// A sensor that runs a tool itself serves its retests with HandleRetest.
	var handled, budgeted atomic.Int32
	k.HandleRetest("ext-scanner", func(ctx context.Context, task tool.Task) (*toolhost.Outcome, error) {
		handled.Add(1)
		// The retest command's per-host budget travels on the context.
		b, ok := adapt.HostBudgetFrom(ctx)
		if ok && b.RPS == adapt.DefaultBudget().RPS && b.Inflight == adapt.DefaultBudget().Inflight {
			budgeted.Add(1)
		}
		return k.toolHost().RunBuiltin(ctx, retestContract, task, toolhost.RunOptions{HostBudget: &b})
	})

	// A tool whose retest also runs delivered templates reports both.
	k.HandleRetestTemplates("ext-tpl", func(ctx context.Context, task tool.Task) (*toolhost.Outcome, error) {
		return k.toolHost().RunBuiltin(ctx, retestContract, task, toolhost.RunOptions{HostBudget: testBudget()})
	})

	good, offTarget, noRetest := "0192a3b4-0000-7000-8000-0000000000e1", "0192a3b4-0000-7000-8000-0000000000e2", "0192a3b4-0000-7000-8000-0000000000e3"
	f.QueueCommandPayload(good, RetestCommandType, json.RawMessage(`{"scanner":"kit-retest","retest_id":"r1","timeout_seconds":60,
		"targets":["1.1.1.1","8.8.8.8"],
		"items":[{"ref":"f1","target":"1.1.1.1","kind":"finding","rule_id":"present"},
		         {"ref":"f2","target":"8.8.8.8","kind":"finding","rule_id":"gone"},
		         {"ref":"f3","target":"8.8.8.8","kind":"finding","rule_id":"other"}]}`))
	f.QueueCommandPayload(offTarget, RetestCommandType, json.RawMessage(`{"scanner":"kit-retest","targets":["1.1.1.1"],
		"items":[{"ref":"f1","target":"9.9.9.9","kind":"finding","rule_id":"present"}]}`))
	f.QueueCommandPayload(noRetest, RetestCommandType, json.RawMessage(`{"scanner":"kit-contract","targets":["1.1.1.1"],
		"items":[{"ref":"f1","target":"1.1.1.1","kind":"finding","rule_id":"present"}]}`))
	ext := "0192a3b4-0000-7000-8000-0000000000e4"
	f.QueueCommandPayload(ext, RetestCommandType, json.RawMessage(`{"scanner":"ext-scanner","targets":["1.1.1.1"],
		"items":[{"ref":"x1","target":"1.1.1.1","kind":"finding","rule_id":"gone"}]}`))
	stop := runKit(t, k)
	waitCompleted(t, f, good, out, errw)
	waitCompleted(t, f, ext, out, errw)
	waitFor(t, "refused retests", func() bool {
		a, _ := f.CommandState(offTarget)
		b, _ := f.CommandState(noRetest)
		return a == "failed" && b == "failed"
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var res struct {
		Metadata struct {
			Retest RetestResult `json:"retest"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(f.CommandResult(good), &res); err != nil {
		t.Fatalf("result %s: %v", f.CommandResult(good), err)
	}
	got := map[string]tool.Verdict{}
	for _, v := range res.Metadata.Retest.Verdicts {
		got[v.Ref] = v.Verdict
	}
	want := map[string]tool.Verdict{"f1": tool.StillPresent, "f2": tool.Fixed, "f3": tool.Unverifiable}
	for ref, v := range want {
		if got[ref] != v {
			t.Errorf("%s: %s, want %s (result %s)", ref, got[ref], v, f.CommandResult(good))
		}
	}
	if res.Metadata.Retest.Tool != "kit-retest" {
		t.Errorf("tool %q", res.Metadata.Retest.Tool)
	}
	if _, msg := f.CommandState(offTarget); !strings.Contains(msg, "not a target of the command") {
		t.Errorf("off-target retest: %s", msg)
	}
	if _, msg := f.CommandState(noRetest); !strings.Contains(msg, "no tool \"kit-contract\" that retests") {
		t.Errorf("retest of a tool without retest: %s", msg)
	}
	if n := len(acceptedTitles(f)); n != 0 {
		t.Errorf("a retest delivered %d findings", n)
	}
	if budgeted.Load() != 1 {
		t.Errorf("the retest ran without its command's per-host budget on the context")
	}
	if handled.Load() != 1 || !strings.Contains(string(f.CommandResult(ext)), `"ref":"x1","verdict":"fixed"`) {
		t.Errorf("HandleRetest: %d calls, result %s", handled.Load(), f.CommandResult(ext))
	}
	hb := lastBeat(t, f)
	if !slices.Contains(hb.Capabilities, "retest:kit-retest") || !slices.Contains(hb.Capabilities, "retest:ext-scanner") ||
		slices.Contains(hb.Capabilities, "retest:kit-contract") ||
		!slices.Contains(hb.Capabilities, "retest:ext-tpl") || !slices.Contains(hb.Capabilities, "retest-templates:ext-tpl") ||
		slices.Contains(hb.Capabilities, "retest-templates:ext-scanner") || slices.Contains(hb.Capabilities, "retest-templates:kit-retest") {
		t.Errorf("capabilities %v", hb.Capabilities)
	}
}

// budgetedEgress is the command executor as the retest executor sees it,
// with a fixed per-host budget for every command.
type budgetedEgress struct{ b adapt.HostBudget }

func (budgetedEgress) PrepareEgress(context.Context, string, *upstream.Config) (*upstream.Pool, error) {
	return nil, errors.New("no pool in this test")
}

func (e budgetedEgress) HostBudget(*core.Command) adapt.HostBudget { return e.b }

// A retest runs under its command's per-host budget, as a scan does: the
// budget the executor resolves for the command (the lowest of the sensor's
// level, the command's signed budget and the operator's ceiling) is on the
// context the retest's tool is started with.
func TestRetestRunsUnderItsCommandsBudget(t *testing.T) {
	gentle := adapt.ResolveBudget(adapt.DefaultPacing, &adapt.JobBudget{Level: "gentle"}, adapt.BudgetCeiling{})
	var got adapt.HostBudget
	var ok bool
	run := func(ctx context.Context, _ tool.Task) (*toolhost.Outcome, error) {
		got, ok = adapt.HostBudgetFrom(ctx)
		return &toolhost.Outcome{Status: tool.StatusOK}, nil
	}
	rx := newRetestExecutor(nil, map[string]RetestFunc{"ext-scanner": run}, nil, nil, nil, budgetedEgress{b: gentle})
	cmd := &core.Command{ID: "0192a3b4-0000-7000-8000-0000000000f1", Type: RetestCommandType,
		Payload: json.RawMessage(`{"scanner":"ext-scanner","targets":["192.0.2.1"],"items":[{"ref":"x1","target":"192.0.2.1","kind":"finding","rule_id":"r"}]}`)}
	if _, err := rx.Execute(t.Context(), cmd); err != nil {
		t.Fatal(err)
	}
	if !ok || got.Level != "gentle" || got.RPS != 5 || got.Inflight != 2 {
		t.Fatalf("the retest's budget: %+v (%t), want the command's gentle budget", got, ok)
	}
}
