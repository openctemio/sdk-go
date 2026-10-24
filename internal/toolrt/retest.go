package toolrt

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/openctemio/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// CheckRetest checks a retest task's items before it runs: the manifest
// declares retest, at most tool.MaxRetestItems items with unique refs, a
// known kind, and each on one of the task's targets (a retest never adds a
// target). It returns nil for a task that is not a retest.
func CheckRetest(m tool.Manifest, task tool.Task) *tool.Error {
	if !task.IsRetest() {
		return nil
	}
	if !m.RetestFeature() {
		return tool.AsError(tool.Invalid("%s does not declare retest", m.Name))
	}
	if len(task.Retest) > tool.MaxRetestItems {
		return tool.AsError(tool.Invalid("%d retest items, more than %d", len(task.Retest), tool.MaxRetestItems))
	}
	targets := map[string]bool{}
	for _, t := range task.Targets {
		targets[t.Ref] = true
	}
	seen := map[string]bool{}
	for i, it := range task.Retest {
		switch {
		case it.Ref == "" || len(it.Ref) > 256 || strings.IndexFunc(it.Ref, unicode.IsControl) >= 0 || seen[it.Ref]:
			return tool.AsError(tool.Invalid("retest item %d: a unique ref (at most 256 characters) is required", i))
		case it.Kind != tool.RetestFinding && it.Kind != tool.RetestAsset:
			return tool.AsError(tool.Invalid("retest item %q: kind must be finding or asset", it.Ref))
		case !targets[it.Target]:
			return tool.AsError(tool.Invalid("retest item %q: target %q is not in the task", it.Ref, it.Target))
		case len(it.RuleID) > 512 || len(it.Fingerprint) > 512 || len(it.Attrs) > 32:
			return tool.AsError(tool.Invalid("retest item %q: rule id, fingerprint or attributes too large", it.Ref))
		case it.TemplatePath != "" && !validTemplatePath(it.TemplatePath):
			return tool.AsError(tool.Invalid("retest item %q: the template path must be a clean absolute file path", it.Ref))
		}
		seen[it.Ref] = true
	}
	return nil
}

// Verdict records the verdict on item ref (the first one counts). A ref not
// in the task or an unknown verdict is an error. Evidence the runtime
// cannot accept (too many items, an invalid item, an unreadable template
// digest) makes the verdict Unverifiable rather than failing the task: the
// tool's output is hostile until checked.
func (a *Assembler) Verdict(ref string, r tool.VerdictReport) error {
	if !r.Verdict.Valid() {
		return fmt.Errorf("unknown verdict %q", r.Verdict)
	}
	if _, ok := a.items[ref]; !ok {
		return fmt.Errorf("retest item %q is not in the task", ref)
	}
	v := tool.RetestVerdict{Ref: ref, Verdict: r.Verdict, Detail: tool.CapDetail(CleanString(r.Detail))}
	if r.Verdict == tool.Unverifiable && r.Code.Valid() {
		v.Code = r.Code
	}
	if err := checkVerdictEvidence(r); err != nil {
		v = tool.RetestVerdict{Ref: ref, Verdict: tool.Unverifiable, Detail: tool.CapDetail("evidence refused: " + err.Error())}
	} else {
		v.TemplateDigest = r.TemplateDigest
		if len(r.Evidence) > 0 {
			v.Evidence = append([]ctis.EvidenceItem(nil), r.Evidence...)
			ptrs := make([]*ctis.EvidenceItem, len(v.Evidence))
			for i := range v.Evidence {
				ptrs[i] = &v.Evidence[i]
			}
			// Marks only (never masks): a value the tool did not mark is
			// marked here, so the platform masks it.
			ctis.MarkSensitive(ptrs...)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, done := a.verdicts[ref]; done {
		return nil
	}
	a.verdicts[ref] = v
	return nil
}

// Verdicts returns one final verdict per retest item, in task order (nil
// for a task that is not a retest). The runtime, not the tool, decides what
// a verdict may claim:
//   - an item without a verdict is Unverifiable;
//   - Fixed stands only when the task finished (runErr nil) and the item's
//     target was reported done: a tool that never reached the target, or
//     stopped, cannot call anything fixed.
func (a *Assembler) Verdicts(runErr *tool.Error) []tool.RetestVerdict {
	if len(a.itemOrder) == 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]tool.RetestVerdict, 0, len(a.itemOrder))
	for _, ref := range a.itemOrder {
		v, ok := a.verdicts[ref]
		switch {
		case !ok:
			v = a.missingVerdict(ref, runErr)
		case v.Verdict == tool.Fixed && runErr != nil:
			v = tool.RetestVerdict{Ref: ref, Verdict: tool.Unverifiable, Detail: "the retest did not finish: " + string(runErr.Class)}
		case v.Verdict == tool.Fixed:
			if r, done := a.results[a.items[ref].Target]; !done || r.State != tool.StateDone {
				v = tool.RetestVerdict{Ref: ref, Verdict: tool.Unverifiable, Detail: "the target was not reached"}
			} else if a.items[ref].Kind == tool.RetestFinding && a.m.Normalized().Permissions.Network != tool.NetNone &&
				!hasAnsweredExchange(v.Evidence) {
				// A networked check that did not show the attempt it made
				// cannot call a finding fixed.
				v = tool.RetestVerdict{Ref: ref, Verdict: tool.Unverifiable, TemplateDigest: v.TemplateDigest,
					Evidence: v.Evidence, Detail: "fixed without the attempt's HTTP exchange"}
			}
		}
		out = append(out, v)
	}
	return out
}

// Invoke runs one task of t: Retest for a retest task (t must implement
// tool.Retester, ctx tool.RetestContext), Run otherwise.
func Invoke(t tool.Tool, ctx tool.Context, task tool.Task) error {
	if !task.IsRetest() {
		return t.Run(ctx, task)
	}
	r, ok := t.(tool.Retester)
	rc, ok2 := ctx.(tool.RetestContext)
	if !ok || !ok2 {
		return tool.Invalid("%s has no retest handler", t.Manifest().Name)
	}
	return r.Retest(rc, task)
}

// maxTemplatePath bounds a retest item's template path.
const maxTemplatePath = 4096

// validTemplatePath reports whether p is a clean absolute path without
// control characters, at most maxTemplatePath long.
func validTemplatePath(p string) bool {
	return len(p) <= maxTemplatePath && filepath.IsAbs(p) && filepath.Clean(p) == p &&
		strings.IndexFunc(p, unicode.IsControl) < 0
}

// missingVerdict is the verdict of an item the tool never judged: it says
// what the runtime knows (the item's target failed, was skipped or was
// never reached; the run failed) so the platform shows a reason, not a bare
// "no verdict". A target that failed because it did not answer or was
// refused by the network confinement keeps those codes.
func (a *Assembler) missingVerdict(ref string, runErr *tool.Error) tool.RetestVerdict {
	v := tool.RetestVerdict{Ref: ref, Verdict: tool.Unverifiable, Code: tool.CodeNoVerdict}
	r, ok := a.results[a.items[ref].Target]
	switch {
	case ok && r.State == tool.StateFailed && r.Error != nil && (r.Error.Class == tool.TargetUnreachable || r.Error.Class == tool.NotFound):
		v.Code = tool.CodeTargetUnreachable
		v.Detail = "the sensor could not connect to the target"
	case ok && r.State == tool.StateFailed && r.Error != nil && r.Error.Class == tool.EgressRefused:
		v.Code = tool.CodeEgressRefused
		v.Detail = "the sensor's network confinement refused the target"
	case ok && r.State != tool.StateDone:
		v.Detail = "the check ended without a verdict: the target was " + string(r.State)
		if r.Error != nil {
			v.Detail += " (" + string(r.Error.Class) + ")"
		}
	case runErr != nil:
		v.Detail = "the check ended without a verdict: the tool stopped (" + string(runErr.Class) + ")"
	default:
		v.Detail = "the check ended without a verdict: the tool finished without judging this item"
	}
	return v
}
