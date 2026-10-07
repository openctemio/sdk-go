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

// RetestVerdict is an item's final verdict, as the runtime reports it.
type RetestVerdict struct {
	Ref     string  `json:"ref"`
	Verdict Verdict `json:"verdict"`
	Detail  string  `json:"detail,omitempty"`
	// Evidence is what the attempt saw (at most MaxVerdictEvidence items),
	// sensitive values marked (ctis.MarkSensitive), never masked.
	Evidence []ctis.EvidenceItem `json:"evidence,omitempty"`
	// TemplateDigest identifies the exact check that ran (a template's
	// digest), so the platform can tell a fix from a changed check.
	TemplateDigest string `json:"template_digest,omitempty"`
}

// MaxVerdictEvidence bounds the evidence items of one verdict.
const MaxVerdictEvidence = 5

// VerdictReport is a verdict with what supports it (RetestContext.Report).
type VerdictReport struct {
	Verdict        Verdict
	Detail         string
	Evidence       []ctis.EvidenceItem
	TemplateDigest string
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
