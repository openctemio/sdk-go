package core

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/openctemio/ctis/outcome"
)

type failingExecutor struct {
	res *CommandExecutionResult
	err error
}

func (e *failingExecutor) Execute(context.Context, *Command) (*CommandExecutionResult, error) {
	return e.res, e.err
}

func runFailed(t *testing.T, e CommandExecutor, id string) *CommandResult {
	t.Helper()
	c := newQueueClient(scanCmd(id, "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.10"}))
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 2})
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.full[id]
	if r == nil {
		t.Fatal("no result reported")
	}
	return r
}

// A job that fails reports its class and bounded evidence, the error code,
// a redacted message and the targets settled before the failure.
func TestCommandPoller_FailureIsClassified(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	crash := exec.Command("sh", "-c", "kill -SEGV $$").Run()
	partial := &CommandExecutionResult{TargetOutcomes: []outcome.Target{
		{Target: "203.0.113.10", State: outcome.Unfinished},
	}}
	e := &failingExecutor{res: partial, err: atStage(StageRun, fmt.Errorf("scan failed: via http://u:hunter2@10.0.0.1:3128: %w", crash))}
	r := runFailed(t, e, "crash")
	if r.Status != "failed" || r.Refusal != nil {
		t.Fatalf("%+v", r)
	}
	if r.Failure == nil || r.Failure.Class != FailureToolCrashed || r.Failure.Evidence.Signal != "SIGSEGV" ||
		r.Failure.Evidence.Stage != StageRun || r.Failure.Evidence.Tool != "nuclei" {
		t.Fatalf("failure %+v", r.Failure)
	}
	if r.ErrorCode != "TOOL_EXIT" {
		t.Fatalf("error code %q", r.ErrorCode)
	}
	if strings.Contains(r.Error, "hunter2") || !strings.Contains(r.Error, "scan failed") {
		t.Fatalf("message %q", r.Error)
	}
	if len(r.TargetOutcomes) != 1 || r.TargetOutcomes[0].State != outcome.Unfinished {
		t.Fatalf("outcomes %+v", r.TargetOutcomes)
	}
}

// A failure the sensor cannot place is "unknown", never a guess.
func TestCommandPoller_UnknownFailure(t *testing.T) {
	r := runFailed(t, &failingExecutor{err: errors.New("scan failed: odd")}, "odd")
	if r.Failure == nil || r.Failure.Class != FailureUnknown || r.ErrorCode != "" {
		t.Fatalf("%+v code %q", r.Failure, r.ErrorCode)
	}
}

// A policy refusal is a refusal: no failure class goes with it.
func TestCommandPoller_RefusalHasNoFailureClass(t *testing.T) {
	r := runFailed(t, &failingExecutor{err: &LocalPolicyError{Rule: "allow_interactsh", Detail: "x"}}, "ref")
	if r.Refusal == nil || r.Failure != nil || r.ErrorCode != "" || r.TargetOutcomes != nil {
		t.Fatalf("%+v", r)
	}
}

// A completed command carries neither.
func TestCommandPoller_CompletedHasNoFailure(t *testing.T) {
	c := newQueueClient(scanCmd("ok", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.10"}))
	p := NewCommandPoller(c, &failingExecutor{res: &CommandExecutionResult{}}, &CommandPollerConfig{MaxConcurrent: 2})
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if r := c.full["ok"]; r == nil || r.Status != "completed" || r.Failure != nil || r.ErrorCode != "" {
		t.Fatalf("%+v", r)
	}
}
