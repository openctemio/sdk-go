package core

// Per-target refusals (api RFC-040 §5.7, docs/rfcs/RFC-040-platform-sensor-
// mutual-distrust.md in openctemio/openctem). A scan job's target that the
// sensor cannot check (it does not resolve, it is a wildcard pattern, it
// cannot be parsed) or that a policy denies is removed from the job before
// any tool sees it, and the job runs on the rest. The command then
// completes as partial: its result metadata lists every refused target
// with a reason (MetaRefusedTargets), so the platform can show what was
// skipped and why. When every target is refused the command fails, with
// the same list.
//
// Fail-closed stays per target: an address the policy cannot check is
// never handed to a tool, and the tool never learns a refused target, so a
// result cannot carry data for it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Refused-target reasons (the closed set the platform shows).
const (
	// RefusedTargetUnresolvable: a host name that does not resolve
	// (NXDOMAIN, a resolver failure). Its addresses cannot be checked.
	RefusedTargetUnresolvable = "unresolvable"
	// RefusedTargetWildcard: a pattern such as "*.example.com", not a host
	// a policy can check or a tool can reach.
	RefusedTargetWildcard = "wildcard_pattern"
	// RefusedTargetDenied: the target (or an address it resolves to) is
	// outside the local policy's targets or ports, or in the built-in deny
	// list.
	RefusedTargetDenied = "denied_by_policy"
	// RefusedTargetInvalid: the target cannot be read as a URL, host,
	// address, range or path, or it is unsafe to hand to a tool.
	RefusedTargetInvalid = "invalid_target"
)

// Result metadata keys of a command with refused targets.
const (
	// MetaRefusedTargets is the list of refused targets ([]RefusedTarget,
	// at most MaxRefusedTargetsReported entries).
	MetaRefusedTargets = "refused_targets"
	// MetaRefusedTargetsTotal is how many targets were refused (also those
	// the list leaves out).
	MetaRefusedTargetsTotal = "refused_targets_total"
	// MetaPartial is true when the command ran on some of its targets only.
	MetaPartial = "partial"
)

// MaxRefusedTargetsReported bounds the refused targets one result lists.
const MaxRefusedTargetsReported = 100

// maxRefusedTargetValue bounds a refused target's value in a result.
const maxRefusedTargetValue = 512

// RefusedTarget is one target a policy removed from a command.
type RefusedTarget struct {
	Target string `json:"target"`
	// Reason is one of RefusedTarget*.
	Reason string `json:"reason"`
	// Rule is the policy rule that refused it ("targets.deny",
	// "ports.allow", "builtin"…), when a policy rule did.
	Rule string `json:"rule,omitempty"`
	// Detail is a short, bounded explanation.
	Detail string `json:"detail,omitempty"`
}

// targetRefusalError marks a target check error with its reason. Its text
// is the wrapped error's, so existing messages stay as they are.
type targetRefusalError struct {
	reason string
	err    error
}

func (e *targetRefusalError) Error() string { return e.err.Error() }
func (e *targetRefusalError) Unwrap() error { return e.err }

// markTarget gives err the refusal reason (nil stays nil).
func markTarget(reason string, err error) error {
	if err == nil {
		return nil
	}
	return &targetRefusalError{reason: reason, err: err}
}

// refusedTargetOf describes why target was refused with err.
func refusedTargetOf(target string, err error) RefusedTarget {
	rt := RefusedTarget{Target: cleanRefusalDetail(truncateBytes(target, maxRefusedTargetValue)), Reason: RefusedTargetInvalid}
	var te *targetRefusalError
	var pe *LocalPolicyError
	switch {
	case errors.As(err, &te):
		rt.Reason = te.reason
	case errors.As(err, &pe):
		rt.Reason = RefusedTargetDenied
	}
	if errors.As(err, &pe) {
		rt.Rule = pe.Rule
		rt.Detail = cleanRefusalDetail(pe.Detail)
	} else if err != nil {
		rt.Detail = cleanRefusalDetail(err.Error())
	}
	return rt
}

func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// isWildcardHost reports whether host is a pattern rather than a host.
func isWildcardHost(host string) bool {
	return strings.ContainsAny(host, "*?")
}

// RefusedTargetsMetadata returns the result metadata for refused (nil when
// none): the bounded list, the total and the partial flag.
func RefusedTargetsMetadata(refused []RefusedTarget) map[string]any {
	if len(refused) == 0 {
		return nil
	}
	listed := refused
	if len(listed) > MaxRefusedTargetsReported {
		listed = listed[:MaxRefusedTargetsReported]
	}
	return map[string]any{
		MetaRefusedTargets:      append([]RefusedTarget(nil), listed...),
		MetaRefusedTargetsTotal: len(refused),
		MetaPartial:             true,
	}
}

// refusedTargetsFrom reads the refused targets an executor put in its
// result metadata (a []RefusedTarget, or the same shape decoded from JSON).
func refusedTargetsFrom(meta map[string]any) []RefusedTarget {
	v, ok := meta[MetaRefusedTargets]
	if !ok || v == nil {
		return nil
	}
	if list, ok := v.([]RefusedTarget); ok {
		return list
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var list []RefusedTarget
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	return list
}

// refusedSummary is a short text of refused for an error or log line:
// "2 targets refused: "a" (unresolvable), "b" (denied_by_policy)".
func refusedSummary(refused []RefusedTarget) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d target(s) refused: ", len(refused))
	for i, r := range refused {
		if i == maxRefusedListed {
			fmt.Fprintf(&b, ", and %d more", len(refused)-i)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q (%s)", r.Target, r.Reason)
	}
	return b.String()
}
