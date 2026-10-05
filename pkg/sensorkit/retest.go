package sensorkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
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

// retestExecutor runs retest commands with the tools that declare retest.
type retestExecutor struct {
	tools map[string]toolcompat.Retester
}

// newRetestExecutor returns the executor of the scanners that can retest
// (nil when none can).
func newRetestExecutor(scanners []scannerEntry) *retestExecutor {
	rx := &retestExecutor{tools: map[string]toolcompat.Retester{}}
	for _, e := range scanners {
		r, ok := e.s.(toolcompat.Retester)
		if !ok || !r.Retests() {
			continue
		}
		rx.tools[strings.ToLower(e.s.Name())] = r
		if e.as != "" {
			rx.tools[strings.ToLower(e.as)] = r
		}
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
	out, err := r.RunRetest(ctx, task)
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
