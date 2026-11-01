package toolhost

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Policy is the sensor-side policy a task is admitted against before the
// tool starts: the sensor-local policy the network owner wrote at install
// time (*core.LocalPolicy implements it). Nothing the platform sends
// widens it.
type Policy interface {
	// AllowsTool reports whether the policy lets the tool run at all.
	AllowsTool(name string) bool
	// CheckTarget checks one target (URL, host, host:port, IP, CIDR);
	// host names are resolved and every address must pass.
	CheckTarget(ctx context.Context, target string) error
	// CapTimeout caps how long a task may run.
	CapTimeout(requested time.Duration) time.Duration
	// KillSwitchEngaged reports whether the owner stopped every job.
	KillSwitchEngaged() bool
}

// Admission is what Admit decided for one task.
type Admission struct {
	// Task is the task the tool receives: only the admitted targets.
	Task tool.Task
	// Refused are the targets the policy refused; the tool never sees
	// them. Each is skipped with class refused_by_policy.
	Refused []TargetOutcome
	// Timeout is the task's run time: the manifest's, capped by the
	// policy.
	Timeout time.Duration
}

// Admit applies the effective permission of one task: the manifest's
// permissions intersected with the sensor policy (and the mode the sensor
// runs in, when known). It runs before any task directory, credential or
// process exists. A refused task returns a refused_by_policy error;
// refused targets are removed from the task, so the tool can neither reach
// nor even learn them.
//
//   - The policy's tools allow-list and kill switch.
//   - The manifest's modes (mode "" skips the check).
//   - Linux capabilities: the runtime grants none, so a tool that declares
//     any is refused instead of running degraded.
//   - Every target of a tool whose network is "targets" passes the
//     policy's target guard (allow/deny lists, private ranges, ports, the
//     resolved addresses of a host name). When none is left the task is
//     refused.
//   - The task's run time is capped by the policy.
func Admit(ctx context.Context, m tool.Manifest, task tool.Task, pol Policy, mode tool.Mode) (*Admission, *tool.Error) {
	m = m.Normalized()
	timeout, _, _, _ := m.Resources.Limits()
	a := &Admission{Task: task, Timeout: timeout}
	if mode != "" && len(m.Modes) > 0 && !slices.Contains(m.Modes, mode) {
		return nil, refusedErr("%s does not run in %s mode", m.Name, mode)
	}
	if len(m.Permissions.LinuxCaps) > 0 {
		return nil, refusedErr("%s needs Linux capabilities (%s); this sensor grants none to tools",
			m.Name, strings.Join(m.Permissions.LinuxCaps, ", "))
	}
	if pol == nil {
		return a, nil
	}
	if pol.KillSwitchEngaged() {
		return nil, refusedErr("the local policy's kill switch is engaged")
	}
	if !pol.AllowsTool(m.Name) {
		return nil, refusedErr("the local policy's tools.allow does not list %s", m.Name)
	}
	if t := pol.CapTimeout(timeout); t > 0 {
		a.Timeout = t
	}
	if (m.Permissions.Network != tool.NetTargets && m.Permissions.Network != tool.NetResolver) || len(task.Targets) == 0 {
		return a, nil
	}
	admitted := make([]tool.Target, 0, len(task.Targets))
	for _, t := range task.Targets {
		if err := ctx.Err(); err != nil {
			return nil, tool.AsError(err)
		}
		if err := pol.CheckTarget(ctx, t.Value); err != nil {
			a.Refused = append(a.Refused, TargetOutcome{Ref: t.Ref, Value: t.Value, State: tool.StateSkipped,
				Class: tool.RefusedByPolicy, Detail: tool.CapDetail(err.Error())})
			continue
		}
		admitted = append(admitted, t)
	}
	if len(admitted) == 0 {
		return nil, refusedErr("the local policy refused every target (%s)", a.Refused[0].Detail)
	}
	a.Task.Targets = admitted
	return a, nil
}

// CapabilityHTTPIdentity is the capability a sensor advertises when every
// HTTP request its tools send to their targets carries the job's
// identification: the organization's User-Agent and headers
// (core.OrgHTTPPolicy, for example the headers a bug-bounty program
// requires). The tool host enforces it per task (Task.Identity,
// checkIdentity): Context.HTTP sets it on every request, an exec tool gets
// it on its argv, and a tool that can do neither is refused. So a sensor
// whose tools all run through the tool host advertises it
// (ToolRegistry.AddCapabilities), and the platform gives jobs that carry an
// identification only to a sensor that reports it.
const CapabilityHTTPIdentity = "http.identity@1"

// CapabilityHTTPIdentityV2 is what a sensor advertises when, besides
// http.identity@1, it honors the job's locked_headers and user_agent_locked,
// merges the owner's local http.headers (schema v4), carries the job's query
// parameter in tools that declare features.http_query, and reports the
// identification it applied (Outcome.Identity, core.MetaHTTPIdentity).
const CapabilityHTTPIdentityV2 = "http.identity@2"

// HTTPPolicy is a policy that decides about the tools' requests
// (*core.LocalPolicy, schema v3): a User-Agent that replaces every tool's,
// and whether a tool may skip TLS verification.
type HTTPPolicy interface {
	HTTPPolicy() (userAgent string, allowInsecureTLS bool)
}

// HTTPHeaderPolicy is a policy that adds identification headers of the
// sensor owner to every task that sends HTTP to its targets
// (*core.LocalPolicy, schema v4).
type HTTPHeaderPolicy interface {
	HTTPHeaders() []core.LocalHTTPHeader
}

// httpMerge is the result of merging the job's identification with the
// sensor owner's: the task's http settings, the identification every
// request carries, and the report of what was applied.
type httpMerge struct {
	eff      *tool.HTTPSpec
	identity *tool.Identity
	applied  *tool.AppliedIdentity
}

// effectiveHTTP is the task's http settings: the manifest's, with the
// policy's User-Agent; a tool that skips TLS verification is refused
// where the policy forbids it. The identification (the job's headers and
// query parameter, then the sensor owner's headers when sendsHTTP) is
// merged by name, case-insensitively, one value per name:
//
//   - a job name in LockedHeaders (platform-enforced or program-set) is
//     never changed by the sensor owner's layer;
//   - any other job name is replaced by the sensor owner's header of that
//     name; every other name is kept (union);
//   - the sensor owner's User-Agent wins over the job's unless the job locks
//     it (UserAgentLocked).
//
// More than maxOrgHTTPHeaders names in all refuse the task, naming the
// cap; nothing is dropped. nil eff when nothing is set.
func effectiveHTTP(m tool.Manifest, pol Policy, org *core.OrgHTTPPolicy, sendsHTTP bool) (*httpMerge, *tool.Error) {
	var eff *tool.HTTPSpec
	if m.HTTP != nil {
		c := *m.HTTP
		c.Headers = maps.Clone(m.HTTP.Headers)
		if m.HTTP.TLS != nil {
			t := *m.HTTP.TLS
			c.TLS = &t
		}
		eff = &c
	}
	ua, allowInsecure := "", true
	if hp, ok := pol.(HTTPPolicy); ok && hp != nil {
		ua, allowInsecure = hp.HTTPPolicy()
	}
	skips := eff != nil && eff.TLS != nil && eff.TLS.InsecureSkipVerify
	if !allowInsecure && skips {
		return nil, refusedErr("the local policy forbids skipping TLS verification (http.allow_insecure_tls: false); %s sets tls.insecure_skip_verify", m.Name)
	}
	applied := &tool.AppliedIdentity{Tool: m.Name}
	uaSource := ""
	if ua != "" {
		uaSource = tool.SourceSensor
	}
	if org != nil {
		if org.AllowInsecureTLS != nil && !*org.AllowInsecureTLS && skips {
			return nil, refusedErr("the organization's policy forbids skipping TLS verification; %s sets tls.insecure_skip_verify", m.Name)
		}
		// The local policy's User-Agent wins over the organization's,
		// unless the job locks it.
		if org.UserAgent != "" && (ua == "" || org.UserAgentLocked) {
			ua, uaSource = org.UserAgent, tool.SourceJob
			if org.UserAgentLocked {
				uaSource = tool.SourceJobLocked
			}
		}
	}
	if ua != "" {
		if eff == nil {
			eff = &tool.HTTPSpec{}
		}
		eff.UserAgent = ua
	}
	var local []core.LocalHTTPHeader
	if hh, ok := pol.(HTTPHeaderPolicy); ok && hh != nil && sendsHTTP {
		local = hh.HTTPHeaders()
	}
	merged, err := mergeIdentityHeaders(org, local)
	if err != nil {
		return nil, refusedErr("%v", err)
	}
	// The identification's headers replace a tool.yaml header of the same
	// name, whatever its case.
	var idHeaders map[string]string
	for _, h := range merged {
		if !h.Applied {
			continue
		}
		if idHeaders == nil {
			idHeaders = map[string]string{}
		}
		idHeaders[h.Name] = h.Value
		if eff == nil {
			eff = &tool.HTTPSpec{}
		}
		if eff.Headers == nil {
			eff.Headers = map[string]string{}
		}
		for have := range eff.Headers {
			if strings.EqualFold(have, h.Name) {
				delete(eff.Headers, have)
			}
		}
		eff.Headers[h.Name] = h.Value
	}
	for _, h := range merged {
		applied.Headers = append(applied.Headers, tool.AppliedHeader{Name: h.Name, Value: tool.MaskIdentityValue(h.Name, h.Value),
			Source: h.Source, Applied: h.Applied, Reason: h.Reason})
	}
	id := &tool.Identity{Headers: idHeaders}
	// The identification's User-Agent is the job's, or the owner's when the
	// owner's wins and the job also set one (the job's identification names
	// a User-Agent: the owner's replaces it).
	if org != nil && org.UserAgent != "" && eff != nil {
		id.UserAgent = eff.UserAgent
	}
	if eff != nil && eff.UserAgent != "" && uaSource != "" {
		applied.UserAgent, applied.UserAgentSource = eff.UserAgent, uaSource
	}
	if org != nil && org.Query != nil {
		q := &tool.AppliedQuery{Name: org.Query.Name, Value: org.Query.Value}
		if carriesQuery(m) {
			id.Query, q.Applied = org.Query, true
		} else {
			q.Reason = fmt.Sprintf("%s does not carry a query parameter (features.http_query)", m.Name)
		}
		applied.Query = q
	}
	if id.Empty() {
		id = nil
	}
	if id == nil && applied.UserAgent == "" && len(applied.Headers) == 0 && applied.Query == nil {
		applied = nil
	}
	return &httpMerge{eff: eff, identity: id, applied: applied}, nil
}

// carriesQuery reports whether the tool puts the task's query parameter on
// its requests: it declares features.http_query, or its argv passes
// {{http.query:-flag}}.
func carriesQuery(m tool.Manifest) bool {
	if m.Features != nil && m.Features.HTTPQuery {
		return true
	}
	if m.Run != nil && m.Run.Profile == tool.ProfileExec {
		for _, a := range m.Run.Argv {
			for _, name := range tool.ArgvPlaceholders(a) {
				if _, ok := tool.QueryArgs(name); ok {
					return true
				}
			}
		}
	}
	return false
}

// mergedHeader is one header of the merged identification.
type mergedHeader struct {
	Name, Value, Source string
	Applied             bool
	Reason              string
}

// mergeIdentityHeaders merges the job's headers with the sensor owner's by
// name (case-insensitive); see effectiveHTTP. The result is in name order,
// the owner's refused entries (a locked name) included, not applied.
func mergeIdentityHeaders(org *core.OrgHTTPPolicy, local []core.LocalHTTPHeader) ([]mergedHeader, error) {
	locked := map[string]bool{}
	var jobHeaders map[string]string
	if org != nil {
		jobHeaders = org.Headers
		for _, n := range org.LockedHeaders {
			locked[strings.ToLower(n)] = true
		}
	}
	byKey := map[string]*mergedHeader{}
	for name, value := range jobHeaders {
		src := tool.SourceJob
		if locked[strings.ToLower(name)] {
			src = tool.SourceJobLocked
		}
		byKey[strings.ToLower(name)] = &mergedHeader{Name: name, Value: value, Source: src, Applied: true}
	}
	var refused []mergedHeader
	for _, h := range local {
		key := strings.ToLower(h.Name)
		if err := core.CheckIdentityHeader(h.Name, h.Value); err != nil {
			return nil, fmt.Errorf("the sensor's local http.headers are invalid: %v", err)
		}
		if locked[key] {
			refused = append(refused, mergedHeader{Name: h.Name, Value: h.Value, Source: tool.SourceSensor,
				Reason: "the job locks this header (platform-enforced or set by the program); the job's value is sent"})
			continue
		}
		byKey[key] = &mergedHeader{Name: h.Name, Value: h.Value, Source: tool.SourceSensor, Applied: true}
	}
	if len(byKey) > core.MaxIdentityHeaders {
		return nil, fmt.Errorf("the job's identification would carry %d headers (the job's %d plus the sensor's local http.headers); at most %d: remove local headers or ask the platform owner to remove job headers",
			len(byKey), len(jobHeaders), core.MaxIdentityHeaders)
	}
	out := make([]mergedHeader, 0, len(byKey)+len(refused))
	for _, h := range byKey {
		out = append(out, *h)
	}
	out = append(out, refused...)
	slices.SortFunc(out, func(a, b mergedHeader) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		if a.Applied != b.Applied {
			if a.Applied {
				return -1
			}
			return 1
		}
		return 0
	})
	return out, nil
}

func refusedErr(format string, args ...any) *tool.Error {
	return tool.AsError(tool.Refused(fmt.Sprintf(format, args...)))
}

// checkIdentity refuses a task whose identification the tool cannot put on
// every request: a networked tool must declare features.http_identity, or
// be an exec-profile tool whose argv passes the User-Agent
// ({{http.user_agent}}) and the headers ({{http.headers:-flag}}) it is
// given. A tool that would probe without the identification never starts
// (CapabilityHTTPIdentity).
func checkIdentity(m tool.Manifest, task tool.Task) *tool.Error {
	if !task.Identity.NeedsHeaders() || !sendsHTTPToTargets(m, task) {
		return nil
	}
	if m.Features != nil && m.Features.HTTPIdentity {
		return nil
	}
	if m.Run != nil && m.Run.Profile == tool.ProfileExec {
		var ua, headers bool
		for _, a := range m.Run.Argv {
			for _, name := range tool.ArgvPlaceholders(a) {
				if name == "http.user_agent" {
					ua = true
				}
				if _, ok := tool.HeaderArgs(name); ok {
					headers = true
				}
			}
		}
		if (task.Identity.UserAgent == "" || ua) && (len(task.Identity.Headers) == 0 || headers) {
			return nil
		}
	}
	return refusedErr("%s cannot send the job's identification (User-Agent and headers) on every request: it declares no features.http_identity", m.Name)
}

// sendsHTTPToTargets reports whether the task may send HTTP requests to
// its targets (tool.Manifest.SendsHTTPToTargets).
func sendsHTTPToTargets(m tool.Manifest, task tool.Task) bool {
	return m.SendsHTTPToTargets(task.Capability)
}

// orgPolicyFor is the part of the job's organization HTTP policy that
// applies to the task: all of it for a task that sends HTTP to its
// targets; for any other task only the TLS rule, never the User-Agent or
// headers (the identification is for the program's targets, not for a
// passive source, a vendor API or a registry).
func orgPolicyFor(m tool.Manifest, task tool.Task) *core.OrgHTTPPolicy {
	org := task.OrgHTTP
	if org == nil || sendsHTTPToTargets(m, task) {
		return org
	}
	if org.AllowInsecureTLS == nil {
		return nil
	}
	return &core.OrgHTTPPolicy{AllowInsecureTLS: org.AllowInsecureTLS}
}
