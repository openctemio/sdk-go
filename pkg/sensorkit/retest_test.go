package sensorkit

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
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
				ctx.Verdict(it, tool.Fixed, "no match")
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
	var handled atomic.Int32
	k.HandleRetest("ext-scanner", func(ctx context.Context, task tool.Task) (*toolhost.Outcome, error) {
		handled.Add(1)
		return k.toolHost().RunBuiltin(ctx, retestContract, task, toolhost.RunOptions{})
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
	if handled.Load() != 1 || !strings.Contains(string(f.CommandResult(ext)), `"ref":"x1","verdict":"fixed"`) {
		t.Errorf("HandleRetest: %d calls, result %s", handled.Load(), f.CommandResult(ext))
	}
	hb := lastBeat(t, f)
	if !slices.Contains(hb.Capabilities, "retest:kit-retest") || !slices.Contains(hb.Capabilities, "retest:ext-scanner") ||
		slices.Contains(hb.Capabilities, "retest:kit-contract") {
		t.Errorf("capabilities %v", hb.Capabilities)
	}
}
