package tool

import (
	"context"
	"errors"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// A retest asks a tool to check again what it reported before: the platform
// sends known findings (or assets) with the targets they are on, and the
// tool answers one verdict per item. The platform settles each item from
// its verdict (a fixed finding is closed, a regression reopened), so the
// rules are strict:
//
//   - a retest never widens scope: its targets are admitted like any task's
//     targets, and every item must be on one of them;
//   - a retest task reports verdicts, not records (an emitted record is
//     refused with ErrRetestRecord);
//   - Fixed means the tool reached the target, ran the check and did not see
//     the issue. The runtime turns Fixed into Unverifiable when the item's
//     target was not reported done (TargetDone) or the task did not finish;
//   - an item without a verdict is Unverifiable;
//   - a networked tool's Fixed on a finding stands only with an
//     http_exchange evidence item whose response arrived (the attempt that
//     did not see the issue); otherwise it is Unverifiable.
//
// A tool declares that it can retest with Manifest.Retest and implements
// Retester (WithRetest adds one to any tool).

// MaxRetestItems bounds the items of one retest task.
const MaxRetestItems = 1000

// Retest item kinds.
const (
	RetestFinding = "finding"
	RetestAsset   = "asset"
)

// RetestItem is one thing the platform asks the tool to check again.
type RetestItem struct {
	// Ref is the platform's opaque id of the item, echoed in its verdict.
	Ref string `json:"ref"`
	// Target is the ref of the task target the item is on.
	Target string `json:"target"`
	// Kind is RetestFinding or RetestAsset.
	Kind string `json:"kind"`
	// RuleID is the check that reported the finding (a template id, a rule
	// id).
	RuleID string `json:"rule_id,omitempty"`
	// Fingerprint is the finding's fingerprint as the platform keeps it.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Attrs are typed hints from the platform.
	Attrs map[string]string `json:"attrs,omitempty"`
	// TemplatePath is the file of the check to run for this item instead
	// of the tool's own rule RuleID: a custom template the platform
	// delivered with the retest command, which the sensor verified (signed
	// for this command, the sensor's content check) and wrote to a private
	// file the tool reads. Only the sensor sets it, for a tool that opted
	// in to delivered templates (capability "retest-templates:<tool>");
	// never the platform. The tool runs exactly this file and reports its
	// digest (TemplateDigest of the file's bytes) in the item's verdict.
	// Empty: the tool's own check, as before.
	TemplatePath string `json:"template_path,omitempty"`
}

// Verdict is what a retest concluded about one item.
type Verdict string

// Verdicts.
const (
	// StillPresent: the issue (or asset) was observed again.
	StillPresent Verdict = "still_present"
	// Fixed: the check ran against the reached target and the issue is
	// gone (an asset: it no longer exists).
	Fixed Verdict = "fixed"
	// Unverifiable: the tool could not tell (unreachable, check not
	// available, error).
	Unverifiable Verdict = "unverifiable"
)

// Valid reports whether v is a known verdict.
func (v Verdict) Valid() bool { return v == StillPresent || v == Fixed || v == Unverifiable }

// VerdictCode says why an item is Unverifiable, in a closed set the
// platform maps to text and a suggested action. Free text in Detail is for
// people only; nothing decides on it. An unknown code is dropped by the
// runtime (the tool's output is hostile until checked).
type VerdictCode string

// Verdict codes of an Unverifiable item.
const (
	// CodeTemplateNotFound: the check is not installed on this sensor
	// (its template set does not hold the id).
	CodeTemplateNotFound VerdictCode = "template_not_found"
	// CodeExcludedByPolicy: the check is installed but the sensor's safety
	// policy never runs it (a destructive, intrusive or code class).
	CodeExcludedByPolicy VerdictCode = "excluded_by_policy"
	// CodeTargetUnreachable: the sensor could not connect to the target.
	CodeTargetUnreachable VerdictCode = "target_unreachable"
	// CodeEgressRefused: the sensor's network confinement refused the target.
	// Set by the runtime (it watches the confinement) or a built-in tool
	// (tool.Dial's ErrEgressRefused); the host drops it from a tool that runs
	// out of process.
	CodeEgressRefused VerdictCode = "egress_refused"
	// CodeNoVerdict: the tool ended without a verdict for the item (it
	// stopped early or never reached the target); Detail says what the
	// runtime knows.
	CodeNoVerdict VerdictCode = "no_verdict"
)

// Valid reports whether c is a known code.
func (c VerdictCode) Valid() bool {
	switch c {
	case CodeTemplateNotFound, CodeExcludedByPolicy, CodeTargetUnreachable, CodeEgressRefused, CodeNoVerdict:
		return true
	}
	return false
}

// RuntimeOnly reports whether c is a code an out-of-process tool may not
// set: the claim is about the sensor's network confinement, which such a
// tool's word cannot prove.
func (c VerdictCode) RuntimeOnly() bool { return c == CodeEgressRefused }

// RetestVerdict is an item's final verdict, as the runtime reports it.
type RetestVerdict struct {
	Ref     string  `json:"ref"`
	Verdict Verdict `json:"verdict"`
	Detail  string  `json:"detail,omitempty"`
	// Code says why an Unverifiable item has no conclusion ("" when the
	// tool gave none, or for another verdict).
	Code VerdictCode `json:"code,omitempty"`
	// Evidence is what the attempt saw (at most MaxVerdictEvidence items),
	// sensitive values marked (ctis.MarkSensitive), never masked.
	Evidence []ctis.EvidenceItem `json:"evidence,omitempty"`
	// TemplateDigest identifies the exact check that ran (a template's
	// digest), so the platform can tell a fix from a changed check.
	TemplateDigest string `json:"template_digest,omitempty"`
	// Requests is one line per request the check made (at most
	// MaxVerdictRequests), so the platform can judge the finding's own
	// endpoint when the check probes several. Empty from a tool that does not
	// report it (the platform then reads the evidence as before).
	Requests []RequestResult `json:"requests,omitempty"`
}

// MaxVerdictEvidence bounds the evidence items of one verdict.
const MaxVerdictEvidence = 5

// MaxVerdictRequests bounds the request results of one verdict.
const MaxVerdictRequests = 64

// MaxRequestURL bounds the URL of one request result.
const MaxRequestURL = 2048

// RequestResult is what one request of a check saw. The URL carries no
// userinfo, query values or fragment (the runtime strips them whatever the
// tool sends); nothing here is a
// response body. The platform decides on the finding's own endpoint from
// these lines and treats them as untrusted.
type RequestResult struct {
	// URL is the request URL.
	URL string `json:"url"`
	// Status is the HTTP status (0: no response).
	Status int `json:"status,omitempty"`
	// Matched: the check's matchers matched this request's response.
	Matched bool `json:"matched,omitempty"`
	// Error is a short class of a failed request ("timeout"); empty when
	// the request was answered.
	Error string `json:"error,omitempty"`
	// EdgeVendor and EdgeState are the CDN or WAF markers the answer
	// carried (edgeprotect vendor and state); empty when none. The runtime
	// drops a state ValidEdgeState refuses, and the vendor with it.
	EdgeVendor string `json:"edge_vendor,omitempty"`
	EdgeState  string `json:"edge_state,omitempty"`
}

// ValidEdgeState reports whether s is an edge state a request result may
// carry: the edgeprotect states direct, fronted, challenged, blocked and
// rate_limited.
func ValidEdgeState(s string) bool {
	switch s {
	case "direct", "fronted", "challenged", "blocked", "rate_limited":
		return true
	}
	return false
}

// VerdictReport is a verdict with what supports it (RetestContext.Report).
type VerdictReport struct {
	Verdict Verdict
	Detail  string
	// Code is the reason of an Unverifiable verdict (optional).
	Code           VerdictCode
	Evidence       []ctis.EvidenceItem
	TemplateDigest string
	// Requests is one line per request the check made (optional).
	Requests []RequestResult
}

// ErrRetestRecord is the error of a record emitted in a retest task.
var ErrRetestRecord = errors.New("tool: a retest task reports verdicts, not records")

// IsRetest reports whether the task is a retest.
func (t Task) IsRetest() bool { return len(t.Retest) > 0 }

// RetestContext is the Context of a retest task.
type RetestContext interface {
	Context
	// Verdict reports the verdict on item. The first verdict of an item
	// counts; a verdict on an item not in the task is ignored. detail is
	// cut to MaxErrorDetail and redacted.
	Verdict(item RetestItem, v Verdict, detail string)
	// Report is Verdict with the attempt's evidence and the digest of the
	// check that ran. Evidence over MaxVerdictEvidence items or invalid
	// makes the verdict Unverifiable.
	Report(item RetestItem, r VerdictReport)
}

// Retester is implemented by a tool that can retest (Manifest.Retest).
// The runtime calls Retest instead of Run for a retest task.
type Retester interface {
	Retest(ctx RetestContext, task Task) error
}

// WithRetest returns t with a retest handler: the manifest declares Retest,
// Run is t's, Retest is fn.
// It panics without a tool or a handler, like New on an invalid manifest.
func WithRetest(t Tool, fn func(ctx RetestContext, task Task) error) Tool {
	if t == nil || fn == nil {
		panic("tool: WithRetest needs a tool and a retest handler")
	}
	return &retestTool{Tool: t, fn: fn}
}

type retestTool struct {
	Tool
	fn func(RetestContext, Task) error
}

func (r *retestTool) Manifest() Manifest {
	m := r.Tool.Manifest()
	if !m.RetestFeature() {
		m.Retest = true
	}
	return m
}

func (r *retestTool) Retest(ctx RetestContext, task Task) error { return r.fn(ctx, task) }

// Validate keeps the wrapped tool's semantic checks.
func (r *retestTool) Validate(ctx context.Context, task Task) error {
	if v, ok := r.Tool.(Validator); ok {
		return v.Validate(ctx, task)
	}
	return nil
}
