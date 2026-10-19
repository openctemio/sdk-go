package core

// Rule sources (api docs/architecture/rule-sources.md): a scan runs the
// platform's detection rules (the sensor's managed template or rule pack),
// the organization's own rules (the job's custom templates), or both
// together in one tool run. The platform says which in the job
// (ScanCommandPayload.RuleSources); a scanner that honors it reports
// CapabilityRuleSources, and the platform sends a job that runs only the
// organization's rules to such a sensor only. A sensor without it keeps
// the older behavior: its own rules, plus the custom templates in a
// separate run when the job carries any.

import (
	"fmt"
	"strings"
)

// RuleSources is which detection rules a scan runs.
type RuleSources string

const (
	// RuleSourcesBoth runs the platform's rules and the organization's
	// rules together (the default).
	RuleSourcesBoth RuleSources = "both"
	// RuleSourcesPlatform runs only the platform's rules.
	RuleSourcesPlatform RuleSources = "platform"
	// RuleSourcesTenant runs only the organization's own rules.
	RuleSourcesTenant RuleSources = "tenant"
)

// CapabilityRuleSources is the capability of a sensor whose scanners honor
// a job's rule sources (ScanOptions.RuleSources): platform-only and
// tenant-only runs, and one tool run for both. Report it with
// ToolRegistry.AddCapabilities only when every template-driven scanner the
// sensor runs honors the option.
const CapabilityRuleSources = "rule.sources@1"

// TenantRulePrefix prefixes the rule id of every finding an organization's
// own rule produced, so it never collides with a platform rule of the same
// id (and an organization rule can never stand in for a platform rule).
const TenantRulePrefix = "tenant:"

// ParseRuleSources reads a job's rule sources: "" is RuleSourcesBoth; any
// other unknown value is an error (a job is never run with rules it did
// not ask for).
func ParseRuleSources(s string) (RuleSources, error) {
	switch v := RuleSources(strings.ToLower(strings.TrimSpace(s))); v {
	case "":
		return RuleSourcesBoth, nil
	case RuleSourcesBoth, RuleSourcesPlatform, RuleSourcesTenant:
		return v, nil
	default:
		return "", fmt.Errorf("unknown rule_sources %q (want both, platform or tenant)", s)
	}
}

// Platform reports whether the platform's rules run. The zero value is
// RuleSourcesBoth.
func (r RuleSources) Platform() bool { return r != RuleSourcesTenant }

// Tenant reports whether the organization's own rules run. The zero value
// is RuleSourcesBoth.
func (r RuleSources) Tenant() bool { return r != RuleSourcesPlatform }

// TenantRuleID returns id with TenantRulePrefix, added once.
func TenantRuleID(id string) string {
	if id == "" || IsTenantRuleID(id) {
		return id
	}
	return TenantRulePrefix + id
}

// IsTenantRuleID reports whether id carries TenantRulePrefix.
func IsTenantRuleID(id string) bool { return strings.HasPrefix(id, TenantRulePrefix) }

// checkRuleSources checks a scan job's rule sources against the custom
// templates it carries: a platform-only job carries none, a tenant-only
// job at least one. A job that contradicts itself is refused, never run
// with a guess.
func checkRuleSources(raw string, customTemplates int) (RuleSources, error) {
	rs, err := ParseRuleSources(raw)
	if err != nil {
		return "", err
	}
	switch {
	case rs == RuleSourcesPlatform && customTemplates > 0:
		return "", fmt.Errorf("the job runs only platform rules but carries %d custom template(s)", customTemplates)
	case rs == RuleSourcesTenant && customTemplates == 0:
		return "", fmt.Errorf("the job runs only the organization's rules but carries no custom template")
	}
	return rs, nil
}
