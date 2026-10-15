package sensorkit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: a retest command's web scope reaches the task, as a scan
// command's does: the tool host enforces it and refuses a tool that does
// not declare features.web_scope. An invalid scope fails the command before
// anything runs; it is never run unrestricted.
func TestRetestTaskCarriesTheWebScope(t *testing.T) {
	var p retestPayload
	if err := json.Unmarshal([]byte(`{"scanner":"x","targets":["https://app.example/"],
		"web_scope":{"deny_paths":["/admin"]},
		"items":[{"ref":"f1","target":"https://app.example/","kind":"finding","rule_id":"r"}]}`), &p); err != nil {
		t.Fatal(err)
	}
	task, err := retestTask("c1", p)
	if err != nil {
		t.Fatal(err)
	}
	if task.WebScope == nil || len(task.WebScope.DenyPaths) != 1 || task.WebScope.DenyPaths[0] != "/admin" {
		t.Fatalf("task web scope %+v", task.WebScope)
	}
	if err := json.Unmarshal([]byte(`{"scanner":"x","targets":["https://app.example/"],
		"web_scope":{"deny_paths":["no-slash"]},
		"items":[{"ref":"f1","target":"https://app.example/","kind":"finding","rule_id":"r"}]}`), &p); err != nil {
		t.Fatal(err)
	}
	if _, err := retestTask("c2", p); err == nil || !strings.Contains(err.Error(), "web scope") {
		t.Fatalf("an invalid web scope must fail the retest: %v", err)
	}
}

func TestKit_RetestWebScope(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddTool(retestContract) // no features.web_scope
	var seen *tool.Task
	k.HandleRetest("ext-scanner", func(_ context.Context, task tool.Task) (*toolhost.Outcome, error) {
		seen = &task
		return &toolhost.Outcome{Status: tool.StatusOK}, nil
	})
	scoped, refused := "0192a3b4-0000-7000-8000-0000000000f1", "0192a3b4-0000-7000-8000-0000000000f2"
	f.QueueCommandPayload(scoped, RetestCommandType, json.RawMessage(`{"scanner":"ext-scanner","targets":["1.1.1.1"],
		"web_scope":{"deny_paths":["/admin"]},
		"items":[{"ref":"x1","target":"1.1.1.1","kind":"finding","rule_id":"gone"}]}`))
	f.QueueCommandPayload(refused, RetestCommandType, json.RawMessage(`{"scanner":"kit-retest","targets":["1.1.1.1"],
		"web_scope":{"deny_paths":["/admin"]},
		"items":[{"ref":"f1","target":"1.1.1.1","kind":"finding","rule_id":"present"}]}`))
	stop := runKit(t, k)
	waitCompleted(t, f, scoped, out, errw)
	waitFor(t, "the unscoped tool's retest", func() bool {
		st, _ := f.CommandState(refused)
		return st == "completed" || st == "failed"
	})
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if seen == nil || seen.WebScope == nil || seen.WebScope.DenyPaths[0] != "/admin" {
		t.Fatalf("the retest handler got web scope %+v", seen)
	}
	// The tool does not declare features.web_scope: it never runs the
	// items, whatever the command's state.
	if r := string(f.CommandResult(refused)); strings.Contains(r, `"verdict":"still_present"`) || !strings.Contains(r+stateMsg(f, refused), "web_scope") {
		t.Fatalf("a tool without features.web_scope ran a web-scoped retest: %s %s", r, stateMsg(f, refused))
	}
}

func stateMsg(f *conformance.FakePlatform, id string) string {
	_, msg := f.CommandState(id)
	return msg
}

// SECURITY: a retest command's identification (a bug-bounty program's
// User-Agent and headers) reaches the task, as a scan command's does, so the
// tool host puts it on every request or refuses the tool; an invalid one
// fails the command before anything runs.
func TestRetestTaskCarriesTheIdentification(t *testing.T) {
	var p retestPayload
	if err := json.Unmarshal([]byte(`{"scanner":"x","targets":["https://app.example/"],
		"http_policy":{"user_agent":"jdoe-research","headers":{"X-Bug-Bounty":"jdoe"}},
		"items":[{"ref":"f1","target":"https://app.example/","kind":"finding","rule_id":"r"}]}`), &p); err != nil {
		t.Fatal(err)
	}
	task, err := retestTask("c1", p)
	if err != nil {
		t.Fatal(err)
	}
	if task.OrgHTTP == nil || task.OrgHTTP.UserAgent != "jdoe-research" || task.OrgHTTP.Headers["X-Bug-Bounty"] != "jdoe" {
		t.Fatalf("task http policy %+v", task.OrgHTTP)
	}
	if err := json.Unmarshal([]byte(`{"scanner":"x","targets":["https://app.example/"],
		"http_policy":{"headers":{"Authorization":"Bearer x"}},
		"items":[{"ref":"f1","target":"https://app.example/","kind":"finding","rule_id":"r"}]}`), &p); err != nil {
		t.Fatal(err)
	}
	if _, err := retestTask("c2", p); err == nil || !strings.Contains(err.Error(), "http policy") {
		t.Fatalf("an invalid http policy must fail the retest: %v", err)
	}
}
