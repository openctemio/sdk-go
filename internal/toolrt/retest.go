package toolrt

import (
	"fmt"
	"strings"
	"unicode"

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
	if !m.Retest {
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
		}
		seen[it.Ref] = true
	}
	return nil
}

// Verdict records the verdict on item ref (the first one counts). A ref not
// in the task or an unknown verdict is an error.
func (a *Assembler) Verdict(ref string, v tool.Verdict, detail string) error {
	if !v.Valid() {
		return fmt.Errorf("unknown verdict %q", v)
	}
	if _, ok := a.items[ref]; !ok {
		return fmt.Errorf("retest item %q is not in the task", ref)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, done := a.verdicts[ref]; done {
		return nil
	}
	a.verdicts[ref] = tool.RetestVerdict{Ref: ref, Verdict: v, Detail: tool.CapDetail(CleanString(detail))}
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
			v = tool.RetestVerdict{Ref: ref, Verdict: tool.Unverifiable, Detail: "the tool reported no verdict"}
		case v.Verdict == tool.Fixed && runErr != nil:
			v = tool.RetestVerdict{Ref: ref, Verdict: tool.Unverifiable, Detail: "the retest did not finish: " + string(runErr.Class)}
		case v.Verdict == tool.Fixed:
			if r, done := a.results[a.items[ref].Target]; !done || r.State != tool.StateDone {
				v = tool.RetestVerdict{Ref: ref, Verdict: tool.Unverifiable, Detail: "the target was not reached"}
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
