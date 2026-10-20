package sensorkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/toolcompat"
	"github.com/openctemio/sdk-go/pkg/webscope"
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
	// WebScope is the job's web scope, as on a scan command: the paths
	// and methods the tool may request. The tool host enforces it (the
	// task forwarder, on a sandbox that confines the network), and a tool
	// that does not declare features.web_scope is refused.
	WebScope *webscope.Scope `json:"web_scope,omitempty"`
	// HTTPPolicy is the job's identification (a bug-bounty program's
	// User-Agent and headers), as on a scan command: the tool host puts it
	// on every request of the retest or refuses a tool that cannot.
	HTTPPolicy *core.OrgHTTPPolicy `json:"http_policy,omitempty"`
	// CustomTemplates and CustomTemplatesEnvelope are the custom templates
	// the platform delivers with the retest, as on a scan command (signed
	// for this command; see core.DefaultCommandExecutor.VerifyCustomTemplates).
	core.CommandTemplates
	Items []struct {
		Ref         string `json:"ref"`
		Target      string `json:"target"`
		Kind        string `json:"kind"`
		RuleID      string `json:"rule_id"`
		Fingerprint string `json:"fingerprint"`
		// Template is the id of one of CustomTemplates: the item is
		// checked with that template instead of the tool's own rule.
		Template string `json:"template"`
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

// HandleRetestTemplates is HandleRetest for a tool whose run also checks
// items with the custom templates the platform delivers with the retest
// command, and reports capability "retest-templates:<name>" too (the
// platform sends such a command only to a sensor that reports it). Before
// run is called, the kit refuses the command unless the local policy
// allows custom templates, verifies the templates exactly as a scan's
// (the signed job's template digests, else the per-tenant template
// manifest bound to this sensor and command), runs the sensor's content
// check on each, writes them to a private temporary directory and sets
// each templated item's tool.RetestItem.TemplatePath; the files are
// removed when run returns. run must check a templated item with exactly
// that file and report its digest; a templated item whose fixed or still
// present verdict names another digest becomes unverifiable.
func (k *Kit) HandleRetestTemplates(name string, run RetestFunc) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || run == nil {
		return
	}
	k.HandleRetest(name, run)
	if k.retestTemplates == nil {
		k.retestTemplates = map[string]bool{}
	}
	k.retestTemplates[name] = true
	k.Tools().AddCapabilities(toolcompat.RetestTemplatesCapability(name))
}

// TemplateVerifier verifies the custom templates a command carries (the
// kit's command executor: core.DefaultCommandExecutor.VerifyCustomTemplates).
type TemplateVerifier interface {
	VerifyCustomTemplates(cmd *core.Command, t core.CommandTemplates) ([][]byte, error)
}

// retestExecutor runs retest commands with the tools that declare retest.
type retestExecutor struct {
	tools map[string]RetestFunc
	// templated are the tools whose run takes delivered templates.
	templated map[string]bool
	// verifier checks delivered templates; nil refuses them.
	verifier TemplateVerifier
	// policy is the local policy in force (allow_custom_templates).
	policy func() *core.LocalPolicy
}

// newRetestExecutor returns the executor of the scanners that can retest
// and of the tools given to HandleRetest (nil when there is none).
func newRetestExecutor(scanners []scannerEntry, handled map[string]RetestFunc, templated map[string]bool,
	verifier TemplateVerifier, policy func() *core.LocalPolicy) *retestExecutor {
	rx := &retestExecutor{tools: map[string]RetestFunc{}, templated: templated, verifier: verifier, policy: policy}
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
	digests, cleanup, err := x.prepareTemplates(cmd, name, p, &task)
	if err != nil {
		return nil, err
	}
	defer cleanup()
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
	res := RetestResult{Tool: name, Status: out.Status, Verdicts: templatedVerdicts(out.Verdicts, digests)}
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
	task := tool.Task{ID: id, WebScope: p.WebScope, OrgHTTP: p.HTTPPolicy}
	if err := p.WebScope.Validate(); err != nil {
		return task, fmt.Errorf("retest: web scope: %w", err)
	}
	if err := p.HTTPPolicy.Validate(); err != nil {
		return task, fmt.Errorf("retest: http policy: %w", err)
	}
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

// prepareTemplates admits, verifies and writes the custom templates a
// retest command delivers, and points each templated item of task at its
// file (tool.RetestItem.TemplatePath). It returns the digest each templated
// item's verdict must name (by item ref) and the cleanup of the files. A
// command without templates returns nothing to do.
//
// SECURITY: a template reaches a tool only when the tool opted in
// (HandleRetestTemplates), the local policy allows custom templates, the
// platform signed exactly these templates for this command (the same
// verification as a scan's) and the sensor's content check passes; every
// templated item must name a delivered template of this tool's type.
// Nothing is written before all of that holds.
func (x *retestExecutor) prepareTemplates(cmd *core.Command, name string, p retestPayload, task *tool.Task) (map[string]string, func(), error) {
	none := func() {}
	templated := false
	for _, it := range p.Items {
		if strings.TrimSpace(it.Template) != "" {
			templated = true
		}
	}
	if !templated && len(p.CustomTemplates) == 0 {
		return nil, none, nil
	}
	if !x.templated[name] {
		return nil, none, fmt.Errorf("retest: this sensor's %s retest does not run delivered templates", name)
	}
	if lp := x.policy; lp != nil && !lp().AllowsCustomTemplates() {
		return nil, none, &core.LocalPolicyError{Rule: "allow_custom_templates",
			Detail: fmt.Sprintf("the retest carries %d custom template(s); this sensor's policy does not allow platform-supplied templates", len(p.CustomTemplates))}
	}
	if len(p.CustomTemplates) == 0 {
		return nil, none, errors.New("retest: an item names a template, and the command carries none")
	}
	if len(p.CustomTemplates) > core.MaxTemplatesPerCommand {
		return nil, none, fmt.Errorf("retest: %d custom templates, more than %d", len(p.CustomTemplates), core.MaxTemplatesPerCommand)
	}
	index := make(map[string]int, len(p.CustomTemplates))
	for i, t := range p.CustomTemplates {
		id := strings.TrimSpace(t.ID)
		if _, dup := index[id]; id == "" || dup {
			return nil, none, fmt.Errorf("retest: custom template %d needs a unique id", i)
		}
		if core.CanonicalScannerName(t.TemplateType) != core.CanonicalScannerName(name) {
			return nil, none, fmt.Errorf("retest: custom template %s is a %q template, not one for %s", t.Name, t.TemplateType, name)
		}
		index[id] = i
	}
	for _, it := range p.Items {
		if id := strings.TrimSpace(it.Template); id != "" {
			if _, ok := index[id]; !ok {
				return nil, none, fmt.Errorf("retest: item %q names template %q, which the command does not carry", it.Ref, id)
			}
		}
	}
	if x.verifier == nil {
		return nil, none, core.ErrNoTemplateKeys
	}
	contents, err := x.verifier.VerifyCustomTemplates(cmd, p.CommandTemplates)
	if err != nil {
		return nil, none, fmt.Errorf("retest: %w", err)
	}
	_, files, cleanup, err := core.WriteCustomTemplates(name, p.CustomTemplates)
	if err != nil {
		return nil, none, fmt.Errorf("retest: write custom templates: %w", err)
	}
	digests := map[string]string{}
	for i, it := range p.Items {
		id := strings.TrimSpace(it.Template)
		if id == "" {
			continue
		}
		n := index[id]
		task.Retest[i].TemplatePath = files[n]
		digests[it.Ref] = jobsig.TemplateDigest(contents[n])
	}
	return digests, cleanup, nil
}

// templatedVerdicts holds templated items to the template delivered: a
// verdict that concludes (fixed, still present) under another digest than
// the delivered template's did not run that template and becomes
// unverifiable; an unverifiable verdict without a digest gets the
// delivered one, so the platform can tell which check could not run.
func templatedVerdicts(vs []tool.RetestVerdict, digests map[string]string) []tool.RetestVerdict {
	if len(digests) == 0 {
		return vs
	}
	for i := range vs {
		want, ok := digests[vs[i].Ref]
		if !ok {
			continue
		}
		switch {
		case vs[i].TemplateDigest == want:
		case vs[i].Verdict == tool.Unverifiable && vs[i].TemplateDigest == "":
			vs[i].TemplateDigest = want
		default:
			vs[i] = tool.RetestVerdict{Ref: vs[i].Ref, Verdict: tool.Unverifiable, TemplateDigest: want,
				Detail: "the check that ran is not the template the platform delivered"}
		}
	}
	return vs
}
