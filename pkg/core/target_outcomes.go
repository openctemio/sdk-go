package core

// Per-target outcomes of a scan command (contract outcome): the result says
// how each of the job's targets ended, so the platform settles every target
// with an outcome and hands only the unfinished ones out again. The ledger is
// built from what the run already reports: the targets refused before the
// run and the per-target outcomes of the report (CTIS metadata.targets: the
// tool host writes done, failed, skipped and unfinished; a scanner states
// the targets it could not scan).
//
// A target is done only when the run covered it. The run's own evidence of the
// targets it did not cover counts too: a host the rate controller gave up on
// (a coverage gap: blocked by an edge protection, pushing back at the lowest
// rate, stopped answering), and a target every attempt to reach failed (the
// reach recorder). Those outcomes say why (a name that is gone, a resolver
// that failed, an edge that challenged or blocked, the sensor's own network)
// so the platform can tell a fact about the target from a fault of the scan.

import (
	"context"
	"encoding/json"

	"github.com/openctemio/contract/outcome"
	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// OutcomeEvidence is what a run saw of its targets, beside the report's own
// marks.
type OutcomeEvidence struct {
	// Report is the parsed report (nil: the run reported nothing on its
	// targets).
	Report *ctis.Report
	// Gaps are the hosts the run could not fully cover (ScanResult.CoverageGaps).
	Gaps []adapt.Gap
	// Reach is the job's reach recorder (nil: none).
	Reach *reach.Recorder
	// Control is the sensor's network-path self-check (nil: none). It runs
	// only when a target was not reached, and charges an unreached target to
	// the sensor when it fails.
	Control *reach.Control
	// Revision is the highest outcome revision the platform accepts
	// (ScanCommandPayload.OutcomeRevision); below 2 the classes added in
	// revision 2 are sent as the closest class revision 1 knows.
	Revision int
}

// OutcomeRevisionNewClasses is the outcome revision that adds the classes
// that say why a target was not covered (contract outcome.Revision).
const OutcomeRevisionNewClasses = 2

// TargetOutcomes returns one outcome per target the scanner ran over, in
// order, from a completed scan's report alone (nil: the run reported nothing
// on its targets). Without other evidence a target nothing marks is done: the
// scan ran over it. Callers that have the run's gaps and reach evidence use
// TargetOutcomesFor. Values of the report are the tool's, read as hints and
// bounded by the targets.
func TargetOutcomes(targets []string, report *ctis.Report) []outcome.Target {
	return TargetOutcomesFor(context.Background(), targets, OutcomeEvidence{Report: report, Revision: 1})
}

// TargetOutcomesFor returns one outcome per target, in order: the report's own
// mark first, then the run's coverage gaps, then what the reach recorder saw,
// and done only for a target none of them marks. Normalize keeps the first
// valid entry per target.
func TargetOutcomesFor(ctx context.Context, targets []string, ev OutcomeEvidence) []outcome.Target {
	if len(targets) == 0 {
		return nil
	}
	var marked []outcome.Target
	if ev.Report != nil {
		marked = reportOutcomes(ev.Report)
	}
	marked = append(marked, evidenceOutcomes(ctx, targets, ev)...)
	for _, t := range targets {
		marked = append(marked, outcome.Target{Target: t, State: outcome.Done})
	}
	return downgradeOutcomes(outcome.Normalize(marked, targets), ev.Revision)
}

// downgradeOutcomes gives a platform that accepts revision 1 only the classes
// it knows.
func downgradeOutcomes(out []outcome.Target, revision int) []outcome.Target {
	if revision >= OutcomeRevisionNewClasses {
		return out
	}
	for i := range out {
		out[i] = out[i].Legacy()
	}
	return out
}

// evidenceOutcomes marks the targets the run did not cover from its gaps and
// its reach recorder.
func evidenceOutcomes(ctx context.Context, targets []string, ev OutcomeEvidence) []outcome.Target {
	var gapByHost map[string]adapt.Gap
	if len(ev.Gaps) > 0 {
		gapByHost = make(map[string]adapt.Gap, len(ev.Gaps))
		for _, g := range ev.Gaps {
			gapByHost[reach.HostOf(g.Host)] = g
		}
	}
	var ctl reach.ControlResult
	ctlRan := false
	var out []outcome.Target
	for _, t := range targets {
		if g, ok := gapByHost[reach.HostOf(t)]; ok {
			if o, ok := gapOutcome(t, g); ok {
				out = append(out, o)
				continue
			}
		}
		class, reason, ok := ev.Reach.Lookup(t)
		if !ok || !class.Unreached() {
			continue
		}
		if !ctlRan {
			ctl, ctlRan = ev.Control.Check(ctx), true
		}
		out = append(out, unreachedOutcome(t, class, reason, ctl))
	}
	return out
}

// gapOutcome is the outcome of a target whose host is a coverage gap.
func gapOutcome(target string, g adapt.Gap) (outcome.Target, bool) {
	switch g.Reason {
	case adapt.GapBlocked:
		// An edge protection answered in place of the service (or the host
		// refused us after answering): the service was not scanned.
		o := outcome.Target{Target: target, State: outcome.Failed, Class: outcome.EdgeBlocked, Cause: outcome.CauseTarget}
		if g.Edge == string(edgeChallenged) {
			o.Class = outcome.EdgeChallenged
		}
		if validVendor(g.Vendor) {
			o.Vendor = g.Vendor
		}
		return o, true
	case adapt.GapRateFloor:
		return outcome.Target{Target: target, State: outcome.Failed, Class: outcome.RateLimited, Cause: outcome.CauseTarget}, true
	case adapt.GapBreakerOpen:
		return outcome.Target{Target: target, State: outcome.Failed, Class: outcome.Unreachable, Cause: outcome.CauseTarget, Reason: "stopped_answering"}, true
	case adapt.GapProxyUnavailable:
		// The job's proxy pool did not carry the connections: the sensor's
		// path failed, nothing is known about the target.
		return outcome.Target{Target: target, State: outcome.Failed, Class: outcome.SensorNetworkFault, Cause: outcome.CauseSensor, Reason: adapt.GapProxyUnavailable}, true
	}
	return outcome.Target{}, false
}

// edgeChallenged is the Gap.Edge text of a challenge (edgeprotect.Challenged).
const edgeChallenged = "challenged"

// validVendor reports whether a vendor from a gap is a short token an outcome
// may carry.
func validVendor(v string) bool {
	return outcome.Target{Target: "x", State: outcome.Failed, Class: outcome.EdgeBlocked, Vendor: v}.Valid()
}

// unreachedOutcome is the outcome of a target every attempt to reach failed.
func unreachedOutcome(target string, class reach.Class, reason string, ctl reach.ControlResult) outcome.Target {
	if ctl.SensorFault(class) {
		return outcome.Target{Target: target, State: outcome.Failed, Class: outcome.SensorNetworkFault, Cause: outcome.CauseSensor}
	}
	o := outcome.Target{Target: target, State: outcome.Failed, Class: outcome.Unreachable, Cause: outcome.CauseTarget}
	switch class {
	case reach.DNSFailure:
		if reach.DNSKind(reason) == reach.NameGone {
			o.Class = outcome.NameGone
		} else {
			o.Class = outcome.ResolverFailed
		}
	case reach.Timeout:
		o.Reason = "no_answer"
	case reach.NoRoute:
		o.Reason = "no_route"
	case reach.FirewallRefused:
		o.Reason = "firewall_refused"
	}
	return o
}

// skippedOutcomes are the outcomes of targets a policy refused before the
// scanner saw them.
// A name that does not resolve is, for a platform that accepts the classes of
// revision 2, a failed target that says whether the name is gone or the lookup
// failed; otherwise it is skipped as refused, as before.
func skippedOutcomes(refused []RefusedTarget, revision int) []outcome.Target {
	out := make([]outcome.Target, 0, len(refused))
	for _, r := range refused {
		o := outcome.Target{Target: r.Target, State: outcome.Skipped, Class: outcome.Refused}
		if revision >= OutcomeRevisionNewClasses && r.Reason == RefusedTargetUnresolvable {
			switch reach.DNSKind(r.DNS) {
			case reach.NameGone:
				o = outcome.Target{Target: r.Target, State: outcome.Failed, Class: outcome.NameGone, Cause: outcome.CauseTarget}
			case reach.ResolverFailed:
				o = outcome.Target{Target: r.Target, State: outcome.Failed, Class: outcome.ResolverFailed, Cause: outcome.CauseTarget}
			}
		}
		out = append(out, o)
	}
	return out
}

// outcomes names the outcomes by the payload's own target values (a target
// the policy rewrote gets its payload value back) and adds the targets the
// executor's policy refused.
func (p *ScanCommandPayload) outcomes(ran []outcome.Target, refused []RefusedTarget) []outcome.Target {
	out := skippedOutcomes(refused, p.OutcomeRevision)
	for _, o := range ran {
		if raw, ok := p.aliases[o.Target]; ok {
			o.Target = raw
		}
		out = append(out, o)
	}
	return out
}

// reportOutcomes reads the per-target marks of a report: its CTIS
// metadata.targets (the tool host writes them for every target; a tool may
// state its own), bounded by outcome.MaxTargets.
func reportOutcomes(report *ctis.Report) []outcome.Target {
	n := min(len(report.Metadata.Targets), outcome.MaxTargets)
	out := make([]outcome.Target, 0, n)
	for _, t := range report.Metadata.Targets[:n] {
		o := outcome.Target{Target: t.Target, State: outcome.State(t.State), Class: outcome.Class(t.Class)}
		// A tool's report is not evidence about the sensor: only the
		// sensor's own reach control may charge it, so a claimed sensor
		// fault is downgraded, and the side is the sensor's to decide.
		if o.Class == outcome.SensorNetworkFault {
			o.Class = outcome.Unreachable
		}
		out = append(out, o)
	}
	return out
}

// evidence is what the run saw of its targets: its report, its coverage gaps,
// the job's reach recorder and the sensor's control check, at the revision the
// platform accepts.
func (p *ScanCommandPayload) evidence(ctx context.Context, report *ctis.Report, scanResult *ScanResult) OutcomeEvidence {
	ev := OutcomeEvidence{
		Report:   report,
		Reach:    reach.FromContext(ctx),
		Control:  reach.ControlFromContext(ctx),
		Revision: p.OutcomeRevision,
	}
	if scanResult != nil {
		ev.Gaps = scanResult.CoverageGaps
	}
	return ev
}

// outcomeRevisionOf reads the outcome revision a command payload names (1
// when it names none or cannot be read).
func outcomeRevisionOf(payload []byte) int {
	var p struct {
		OutcomeRevision int `json:"outcome_revision"`
	}
	if json.Unmarshal(payload, &p) != nil || p.OutcomeRevision < 1 {
		return 1
	}
	return p.OutcomeRevision
}
