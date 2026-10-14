package core

// Per-target outcomes of a scan command (ctis outcome): the result says how
// each of the job's targets ended, so the platform settles every target with
// an outcome and hands only the unfinished ones out again. The ledger is
// built from what the run already reports: the targets refused before the
// run, the per-target outcomes the tool host writes into
// the report (target_outcomes), the targets a run that stopped part-way
// never reached (unfinished_targets) and the targets a scanner says it could
// not scan (failed_targets).

import (
	"github.com/openctemio/ctis/outcome"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// TargetOutcomes returns one outcome per target the scanner ran over, in
// order, from a completed scan's report (nil: the run reported nothing on
// its targets). A target nothing marks is done: the scan ran over it.
// Values of the report are the tool's, read as hints and bounded by the
// targets.
func TargetOutcomes(targets []string, report *ctis.Report) []outcome.Target {
	if len(targets) == 0 {
		return nil
	}
	var marked []outcome.Target
	if report != nil {
		marked = reportOutcomes(report)
	}
	for _, t := range targets {
		marked = append(marked, outcome.Target{Target: t, State: outcome.Done})
	}
	// Normalize keeps the first valid entry per target: the report's, then
	// done.
	return outcome.Normalize(marked, targets)
}

// skippedOutcomes are the outcomes of targets a policy refused before the
// scanner saw them.
func skippedOutcomes(refused []RefusedTarget) []outcome.Target {
	out := make([]outcome.Target, 0, len(refused))
	for _, r := range refused {
		out = append(out, outcome.Target{Target: r.Target, State: outcome.Skipped, Class: outcome.Refused})
	}
	return out
}

// outcomes names the outcomes by the payload's own target values (a target
// the policy rewrote gets its payload value back) and adds the targets the
// executor's policy refused.
func (p *ScanCommandPayload) outcomes(ran []outcome.Target, refused []RefusedTarget) []outcome.Target {
	out := skippedOutcomes(refused)
	for _, o := range ran {
		if raw, ok := p.aliases[o.Target]; ok {
			o.Target = raw
		}
		out = append(out, o)
	}
	return out
}

// reportOutcomes reads the per-target marks of a report: the tool host's
// explicit outcomes first, then the targets a run that stopped part-way
// never reached, then failed targets.
func reportOutcomes(report *ctis.Report) []outcome.Target {
	out := explicitOutcomes(report.Properties[outcome.ResultKey])
	for _, t := range stringList(report.Properties[unfinishedTargetsKey]) {
		out = append(out, outcome.Target{Target: t, State: outcome.Unfinished})
	}
	for _, t := range failedTargetList(report.Properties["failed_targets"]) {
		out = append(out, outcome.Target{Target: t, State: outcome.Failed, Class: outcome.ToolError})
	}
	return out
}

// unfinishedTargetsKey is the report property a run that stopped part-way
// lists its unreached targets in (toolhost.UnfinishedTargetsKey).
const unfinishedTargetsKey = "unfinished_targets"

// explicitOutcomes reads a report's target_outcomes property, as decoded
// from JSON ([]any of objects) or set in process ([]outcome.Target).
func explicitOutcomes(v any) []outcome.Target {
	switch list := v.(type) {
	case []outcome.Target:
		return list
	case []any:
		out := make([]outcome.Target, 0, min(len(list), outcome.MaxTargets))
		for i, e := range list {
			if i == outcome.MaxTargets {
				break
			}
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			t, _ := m["target"].(string)
			s, _ := m["state"].(string)
			c, _ := m["class"].(string)
			out = append(out, outcome.Target{Target: t, State: outcome.State(s), Class: outcome.Class(c)})
		}
		return out
	}
	return nil
}

// stringList reads a property holding a list of strings.
func stringList(v any) []string {
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, min(len(list), outcome.MaxTargets))
		for i, e := range list {
			if i == outcome.MaxTargets {
				break
			}
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// failedTargetList reads the targets of a failed_targets property: a list
// of target strings or of objects with a "target" member.
func failedTargetList(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return stringList(v)
	}
	out := make([]string, 0, min(len(list), outcome.MaxTargets))
	for i, e := range list {
		if i == outcome.MaxTargets {
			break
		}
		switch t := e.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			if s, ok := t["target"].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
