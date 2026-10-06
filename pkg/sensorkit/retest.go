package sensorkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/toolcompat"
)

// RetestCommandType is the platform's command that asks a tool to check
// again what it reported (tool.Retester). The kit serves it for every tool
// whose manifest declares retest, and reports capability "retest:<tool>"
// for each, which the platform routes the command by.
const RetestCommandType = "retest"

// Retest limits.
const (
	defaultRetestTimeout = 2 * time.Minute
	maxRetestTimeout     = 30 * time.Minute
)

// retestPayload is the payload of a retest command. targets are addresses,
// as in a scan command (the local policy admits each one before anything
// runs); each item names the address it is on.
type retestPayload struct {
	Scanner        string   `json:"scanner"`
	RetestID       string   `json:"retest_id"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Targets        []string `json:"targets"`
	Items          []struct {
		Ref         string `json:"ref"`
		Target      string `json:"target"`
		Kind        string `json:"kind"`
		RuleID      string `json:"rule_id"`
		Fingerprint string `json:"fingerprint"`
	} `json:"items"`
}

// RetestResult is what a retest command completes with, under the result's
// metadata as "retest".
type RetestResult struct {
	Tool     string               `json:"tool"`
	Status   tool.Status          `json:"status"`
	Verdicts []tool.RetestVerdict `json:"verdicts"`
	// Error is the task's error class and detail, when it failed.
	Error string `json:"error,omitempty"`
}

// RetestFunc runs one retest task (tool.Task.Retest set) of a tool and
// returns the host's outcome (toolhost.Host.RunBuiltin or RunManifest): a
// sensor that runs its tools itself serves retests with it (HandleRetest).
type RetestFunc func(ctx context.Context, task tool.Task) (*toolhost.Outcome, error)

// HandleRetest makes the kit serve the platform's retest commands for tool
// name with run, and report capability "retest:<name>" (the platform
// routes retests of the tool's findings by it). For a sensor that runs its
// tools itself; a contract tool added with AddTool that declares retest is
// served without it. The command is admitted like a scan before run is
// called (the platform's tool gate, the local policy's checks.allow,
// tools.allow and every target); run must run the task through a toolhost
// Host, which admits it again and enforces the retest rules. Call before
// Run.
func (k *Kit) HandleRetest(name string, run RetestFunc) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || run == nil {
		return
	}
	if k.retests == nil {
		k.retests = map[string]RetestFunc{}
	}
	k.retests[name] = run
	k.Tools().AddCapabilities(toolcompat.RetestCapability(name))
}

// retestExecutor runs retest commands with the tools that declare retest.
type retestExecutor struct {
	tools map[string]RetestFunc
}

// newRetestExecutor returns the executor of the scanners that can retest
// and of the tools given to HandleRetest (nil when there is none).
func newRetestExecutor(scanners []scannerEntry, handled map[string]RetestFunc) *retestExecutor {
	rx := &retestExecutor{tools: map[string]RetestFunc{}}
	for _, e := range scanners {
		r, ok := e.s.(toolcompat.Retester)
		if !ok || !r.Retests() {
			continue
		}
		rx.tools[strings.ToLower(e.s.Name())] = r.RunRetest
		if e.as != "" {
			rx.tools[strings.ToLower(e.as)] = r.RunRetest
		}
	}
	for name, run := range handled {
		rx.tools[name] = run
	}
	if len(rx.tools) == 0 {
		return nil
	}
	return rx
}

// Execute runs one retest command: the payload becomes a retest task (one
// target per address, each item on its address), the tool runs it out of
// process, and the command completes with one verdict per item. A payload
// that names a tool without retest, or an item on an address that is not a
// target, fails the command before anything runs.
func (x *retestExecutor) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	start := time.Now()
	var p retestPayload
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		return nil, fmt.Errorf("retest: unreadable payload: %w", err)
	}
	name := strings.ToLower(strings.TrimSpace(core.CanonicalScannerName(p.Scanner)))
	r, ok := x.tools[name]
	if !ok {
		return nil, fmt.Errorf("retest: this sensor has no tool %q that retests", p.Scanner)
	}
	task, err := retestTask(cmd.ID, p)
	if err != nil {
		return nil, err
	}
	timeout := defaultRetestTimeout
	if p.TimeoutSeconds > 0 {
		timeout = min(time.Duration(p.TimeoutSeconds)*time.Second, maxRetestTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	task.Deadline = time.Now().Add(timeout)
	out, err := r(ctx, task)
	if err != nil {
		return nil, fmt.Errorf("retest: %w", err)
	}
	res := RetestResult{Tool: name, Status: out.Status, Verdicts: out.Verdicts}
	if out.Err != nil {
		res.Error = string(out.Err.Class)
		if out.Err.Detail != "" {
			res.Error += ": " + out.Err.Detail
		}
	}
	return &core.CommandExecutionResult{
		DurationMs: time.Since(start).Milliseconds(),
		Metadata:   map[string]any{"retest": res},
	}, nil
}

// retestTask builds the task of a retest command.
func retestTask(id string, p retestPayload) (tool.Task, error) {
	task := tool.Task{ID: id}
	if len(p.Items) == 0 {
		return task, errors.New("retest: the command has no items")
	}
	if len(p.Items) > tool.MaxRetestItems {
		return task, fmt.Errorf("retest: %d items, more than %d", len(p.Items), tool.MaxRetestItems)
	}
	refs := map[string]string{}
	for _, v := range p.Targets {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, dup := refs[v]; dup {
			continue
		}
		ref := fmt.Sprintf("t%d", len(task.Targets))
		refs[v] = ref
		task.Targets = append(task.Targets, tool.Target{Ref: ref, Value: v})
	}
	for _, it := range p.Items {
		ref, ok := refs[strings.TrimSpace(it.Target)]
		if !ok {
			return task, fmt.Errorf("retest: item %q is on %q, which is not a target of the command", it.Ref, it.Target)
		}
		task.Retest = append(task.Retest, tool.RetestItem{Ref: it.Ref, Target: ref, Kind: it.Kind,
			RuleID: it.RuleID, Fingerprint: it.Fingerprint})
	}
	return task, nil
}
