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

// HTTPPolicy is a policy that decides about the tools' requests
// (*core.LocalPolicy, schema v3): a User-Agent that replaces every tool's,
// and whether a tool may skip TLS verification.
type HTTPPolicy interface {
	HTTPPolicy() (userAgent string, allowInsecureTLS bool)
}

// effectiveHTTP is the task's http settings: the manifest's, with the
// policy's User-Agent; a tool that skips TLS verification is refused
// where the policy forbids it. nil when nothing is set.
func effectiveHTTP(m tool.Manifest, pol Policy, org *core.OrgHTTPPolicy) (*tool.HTTPSpec, *tool.Error) {
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
	if org != nil {
		if org.AllowInsecureTLS != nil && !*org.AllowInsecureTLS && skips {
			return nil, refusedErr("the organization's policy forbids skipping TLS verification; %s sets tls.insecure_skip_verify", m.Name)
		}
		// The local policy's User-Agent wins over the organization's.
		if ua == "" {
			ua = org.UserAgent
		}
	}
	if ua != "" {
		if eff == nil {
			eff = &tool.HTTPSpec{}
		}
		eff.UserAgent = ua
	}
	// The organization's headers (a program's identification header)
	// replace a tool.yaml header of the same name, whatever its case.
	if org != nil && len(org.Headers) > 0 {
		if eff == nil {
			eff = &tool.HTTPSpec{}
		}
		if eff.Headers == nil {
			eff.Headers = map[string]string{}
		}
		for name, value := range org.Headers {
			for have := range eff.Headers {
				if strings.EqualFold(have, name) {
					delete(eff.Headers, have)
				}
			}
			eff.Headers[name] = value
		}
	}
	return eff, nil
}

func refusedErr(format string, args ...any) *tool.Error {
	return tool.AsError(tool.Refused(fmt.Sprintf(format, args...)))
}

// identityOf is the identification the task's requests must carry: the
// organization's headers, and its User-Agent as it ends up effective (the
// sensor-local policy's wins). nil when the organization sets neither.
func identityOf(eff *tool.HTTPSpec, org *core.OrgHTTPPolicy) *tool.Identity {
	if org == nil || (org.UserAgent == "" && len(org.Headers) == 0) {
		return nil
	}
	id := &tool.Identity{}
	if org.UserAgent != "" && eff != nil {
		id.UserAgent = eff.UserAgent
	}
	if len(org.Headers) > 0 {
		id.Headers = maps.Clone(org.Headers)
	}
	if id.Empty() {
		return nil
	}
	return id
}

// checkIdentity refuses a task whose identification the tool cannot put on
// every request: a networked tool must declare features.http_identity, or
// be an exec-profile tool whose argv passes the User-Agent
// ({{http.user_agent}}) and the headers ({{http.headers:-flag}}) it is
// given. A tool that would probe without the identification never starts
// (CapabilityHTTPIdentity).
func checkIdentity(m tool.Manifest, task tool.Task) *tool.Error {
	if task.Identity.Empty() || !sendsHTTPToTargets(m, task) {
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

// noHTTPCapabilities are the capabilities whose tools reach targets
// without HTTP (a port scan, host discovery, DNS lookups): the
// identification is HTTP headers, so it does not apply to them.
var noHTTPCapabilities = map[string]bool{
	"scan.ports": true, "discover.hosts": true, "resolve.dns": true,
	"lookup.rdap": true, "lookup.asn": true, "discover.subdomains": true,
}

// sendsHTTPToTargets reports whether a task may send HTTP requests to its
// targets: the tool reaches the targets (directly or through the egress
// proxy), and the task's capability, or else every capability the tool
// implements, is not one that reaches targets without HTTP. A tool that
// implements nothing counts as sending HTTP (fail closed).
func sendsHTTPToTargets(m tool.Manifest, task tool.Task) bool {
	switch m.Normalized().Permissions.Network {
	case tool.NetTargets, tool.NetEgressProxy:
	default:
		return false
	}
	noHTTP := func(ref string) bool {
		key, _, _ := strings.Cut(strings.TrimSpace(ref), "@")
		return noHTTPCapabilities[key]
	}
	if task.Capability != "" {
		return !noHTTP(task.Capability)
	}
	if len(m.Implements) == 0 {
		return true
	}
	for _, im := range m.Implements {
		if !noHTTP(im.Capability) {
			return true
		}
	}
	return false
}
