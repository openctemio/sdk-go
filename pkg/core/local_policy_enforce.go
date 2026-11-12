package core

// Enforcement of the sensor-local policy (api RFC-040 §5.7): job admission
// (AdmitCommand, before any tool sees a job), target checks with DNS
// resolution (CheckTarget, also applied by ScanTargetPolicy), and the
// egress hook for in-process dials and the RFC-034 forwarder (CheckDial,
// DialContext), which pins the addresses it checked so a name cannot
// resolve to a denied address between the check and the connection.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/internal/absname"
	"github.com/openctemio/sdk-go/pkg/reach"
)

// blockedAlways reports whether ip is in the built-in deny list whatever
// the private-range switch says (loopback, link-local and metadata,
// CGNAT, multicast, reserved).
func blockedAlways(ip net.IP) bool {
	return httpsec.IsIPBlockedWith(ip, true, false)
}

// policyJob is what admission reads from a command payload: the tool, the
// targets (scan: target/targets; validate: target.address) and the
// switches a job can ask for.
type policyJob struct {
	Scanner       string          `json:"scanner"`
	ScannerName   string          `json:"scanner_name"`
	PreferredTool string          `json:"preferred_tool"`
	Collector     string          `json:"collector"`
	ExecutorKind  string          `json:"executor_kind"`
	Target        json.RawMessage `json:"target"`
	Targets       []string        `json:"targets"`
	Config        map[string]any  `json:"config"`
	// ScannerConfig is the older name of Config some jobs still carry.
	ScannerConfig map[string]any `json:"scanner_config"`
	// Capability and Params are the standard-param form of a job
	// (ScanCommandPayload): the tool runtime writes each param onto the
	// tool's config (tool.Manifest.ApplyParams), so a port list or a top-N
	// count there is a ports setting like Config's.
	Capability string                     `json:"capability"`
	Params     map[string]json.RawMessage `json:"params"`
	// CustomTemplates only needs its length.
	CustomTemplates []json.RawMessage `json:"custom_templates"`
	// SettingsLayers are the tenant's and the sensor's tool settings: they
	// reach the tool's settings like Config does (resolveScanSettings), so
	// a port list in one is a ports setting too.
	SettingsLayers *SettingsLayers `json:"settings_layers"`
}

func (j *policyJob) tool(cmdType string) string {
	for _, s := range []string{j.Scanner, j.ScannerName, j.PreferredTool} {
		if s = strings.TrimSpace(s); s != "" {
			return strings.ToLower(CanonicalScannerName(s))
		}
	}
	switch cmdType {
	case "collect":
		return strings.ToLower(strings.TrimSpace(j.Collector))
	case "validate":
		// A nuclei validation re-runs a nuclei template; a safe-check is a
		// TCP connect and names no tool.
		if strings.EqualFold(strings.TrimSpace(j.ExecutorKind), "nuclei") {
			return "nuclei"
		}
	}
	return ""
}

// targets returns every target the job names. A target the payload carries
// in a shape admission cannot read is an error: it would reach a tool
// unchecked.
func (j *policyJob) targets() ([]string, error) {
	var out []string
	if len(j.Target) > 0 && string(j.Target) != "null" {
		var s string
		if err := json.Unmarshal(j.Target, &s); err == nil {
			if s != "" {
				out = append(out, s)
			}
		} else {
			var obj struct {
				Address string `json:"address"`
			}
			if err := json.Unmarshal(j.Target, &obj); err != nil {
				return nil, fmt.Errorf("the job's target cannot be read")
			}
			if obj.Address != "" {
				out = append(out, obj.Address)
			}
		}
	}
	return append(out, j.Targets...), nil
}

// maxPolicyRefusals caps how many refused targets one refusal names.
const maxPolicyRefusals = 5

// AdmitCommand decides whether cmd may run under the local policy, before
// any tool sees it: the kill switch, checks.allow (the command type),
// tools.allow, allow_custom_templates, and every target
// against targets.allow/deny, the private-range switch, the built-in deny
// list (host names are resolved; every address must pass) and ports.allow.
// A single violation refuses the whole job with a *LocalPolicyError naming
// the rule; nothing in the payload can widen the policy. Without a policy
// the kill switch applies, and a sensor that requires a policy refuses
// every job with a network target or custom templates (rule
// no_local_policy); a legacy install admits the rest. Out-of-band callbacks
// a policy turns off never refuse a job: the executor runs it without them. AdmitCommandTargets
// is the same check that removes refused targets from a scan job instead
// of refusing all of it.
func (lp *LocalPolicy) AdmitCommand(ctx context.Context, cmd *Command) error {
	targets, err := lp.admitJob(cmd)
	if err != nil || len(targets) == 0 {
		return err
	}
	var (
		first error
		names []string
	)
	for _, t := range targets {
		if err := lp.CheckTarget(ctx, t); err != nil {
			if first == nil {
				first = err
			}
			if len(names) < maxPolicyRefusals {
				names = append(names, strconv.Quote(t))
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	if first == nil {
		return nil
	}
	if len(targets) == 1 {
		return first
	}
	var pe *LocalPolicyError
	if !errors.As(first, &pe) {
		return first
	}
	return &LocalPolicyError{Rule: pe.Rule, Detail: fmt.Sprintf("%s (refused targets include %s)", pe.Detail, strings.Join(names, ", "))}
}

// CommandAdmission is what AdmitCommandTargets decided about a command's
// targets.
type CommandAdmission struct {
	// Total is how many targets the command named.
	Total int
	// Refused are the targets removed from the command (or, with an error,
	// the targets that made it refused), in payload order.
	Refused []RefusedTarget
	// Settled is true when no target is left to run and every target was
	// refused as a name that does not resolve: the command completes
	// without running, each target reported on its own with its refusal
	// (reason unresolvable), so the platform settles each name. The
	// refusal stays per target: no tool sees any of them.
	Settled bool
}

// Partial reports whether the command runs on some of its targets only.
func (a *CommandAdmission) Partial() bool { return a != nil && len(a.Refused) > 0 }

// AdmitCommandTargets is AdmitCommand that refuses per target: in a scan
// job, a target the policy refuses or cannot check (it does not resolve,
// it is a wildcard pattern) is removed from cmd.Payload and listed with
// its reason, and the job runs on the rest. It refuses the whole command,
// with a *LocalPolicyError, when a job-wide rule refuses it (kill switch,
// checks.allow, tools.allow, templates, callbacks, the ports setting, an
// unreadable payload), when every target is refused, when the target the
// job runs on alone (payload "target") is refused, and for every other
// command type (a retest or a validation names its targets in items the
// sensor does not rewrite). The admission is returned with the error too,
// so the refusal can list every target.
//
// It rewrites cmd.Payload only when it removed targets. A removed target is
// never handed to an executor or a tool.
func (lp *LocalPolicy) AdmitCommandTargets(ctx context.Context, cmd *Command) (*CommandAdmission, error) {
	// The job's exclusions and the deny lists first, address by address on
	// a range (job_exclusions.go), with or without a policy file: what is
	// cut here never reaches the checks below or a tool.
	cut, err := lp.cutJobTargets(cmd)
	if err != nil {
		return &CommandAdmission{Total: len(cut.refused), Refused: cut.refused}, err
	}
	targets, err := lp.admitJob(cmd)
	adm := &CommandAdmission{Total: len(targets) + len(cut.refused), Refused: cut.refused}
	if err == nil && len(targets) == 0 && len(cut.refused) > 0 && !jobHasTargetsLeft(cmd) {
		// Every target was cut and no policy check runs (no policy file).
		return adm, &LocalPolicyError{Rule: cut.refused[0].Rule, Detail: refusedSummary(adm.Refused)}
	}
	if err != nil || len(targets) == 0 {
		return adm, err
	}
	refused := make(map[string]bool)
	var first error
	capability := ""
	if cmd.Type == "scan" {
		capability = payloadCapability(cmd.Payload)
	}
	lookupOnly := LookupOnlyCapability(capability)
	registryOnly := RegistryOnlyCapability(capability)
	for _, t := range targets {
		if refused[t] {
			continue
		}
		var err error
		if registryOnly {
			err = lp.checkRegistryName(ctx, t)
		} else {
			err = lp.CheckTarget(ctx, t)
		}
		if lookupOnly {
			err = lp.lookupOnlyRefusal(t, err)
		}
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return adm, cerr
			}
			if first == nil {
				first = err
			}
			refused[t] = true
			adm.Refused = append(adm.Refused, refusedTargetOf(t, err))
		}
	}
	if first == nil {
		return adm, nil
	}
	refuseAll := func() error {
		if len(targets) == 1 {
			return first
		}
		rule := "targets"
		var pe *LocalPolicyError
		if errors.As(first, &pe) {
			rule = pe.Rule
		}
		return &LocalPolicyError{Rule: rule, Detail: refusedSummary(adm.Refused)}
	}
	// Nothing is left to run. When every target is a name that does not
	// resolve, nothing was wrong with the job: it completes with each name
	// refused on its own (Settled). Any other refusal refuses the job.
	nothingLeft := func() (*CommandAdmission, error) {
		if allUnresolvable(adm.Refused) {
			adm.Settled = true
			return adm, nil
		}
		return adm, refuseAll()
	}
	if cmd.Type != "scan" {
		return adm, refuseAll()
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(cmd.Payload, &fields); err != nil {
		return adm, refuseAll()
	}
	var job struct {
		Target  json.RawMessage `json:"target"`
		Targets []string        `json:"targets"`
	}
	if err := json.Unmarshal(cmd.Payload, &job); err != nil {
		return adm, refuseAll()
	}
	single := ""
	if len(job.Target) > 0 && string(job.Target) != "null" {
		// "target" is the whole job when set: refused, nothing is left.
		if json.Unmarshal(job.Target, &single) != nil {
			return adm, refuseAll()
		}
		if refused[single] {
			return nothingLeft()
		}
	}
	kept := make([]string, 0, len(job.Targets))
	for _, t := range job.Targets {
		if !refused[t] {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 && single == "" {
		return nothingLeft()
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return adm, refuseAll()
	}
	fields["targets"] = raw
	payload, err := json.Marshal(fields)
	if err != nil {
		return adm, refuseAll()
	}
	cmd.Payload = payload
	return adm, nil
}

// admitJob applies the job-wide rules of the local policy to cmd and
// returns its targets (none to check without a policy).
func (lp *LocalPolicy) admitJob(cmd *Command) ([]string, error) {
	if why := lp.killSwitchReason(); why != "" {
		return nil, refuse("kill_switch", "%s", why)
	}
	if cmd == nil {
		return nil, nil
	}
	if !lp.Present() {
		if lp.failsClosed() {
			return nil, admitWithoutPolicy(cmd)
		}
		return nil, nil
	}
	if !lp.AllowsCheck(cmd.Type) {
		return nil, refuse("checks.allow", "%q jobs are not allowed on this sensor", cmd.Type)
	}
	var job policyJob
	if len(cmd.Payload) > 0 {
		if err := json.Unmarshal(cmd.Payload, &job); err != nil {
			return nil, refuse("payload", "the job payload cannot be read for the policy check: %v", err)
		}
	}
	tool := job.tool(cmd.Type)
	if lp.tools != nil {
		switch {
		case tool != "" && !lp.AllowsTool(tool):
			return nil, refuse("tools.allow", "%s is not allowed on this sensor", tool)
		case tool == "" && (cmd.Type == "scan" || cmd.Type == "collect"):
			return nil, refuse("tools.allow", "the job names no tool")
		}
	}
	if len(job.CustomTemplates) > 0 && !lp.AllowsCustomTemplates() {
		return nil, refuse("allow_custom_templates", "the job carries %d custom template(s); this sensor's policy does not allow platform-supplied templates", len(job.CustomTemplates))
	}
	// Out-of-band callbacks the policy turns off are not a refusal: the
	// executor runs the job without them (applyJobConfig).
	// A port list the job hands its tool, in its config, in the tenant's or
	// the sensor's settings layer, or as a standard param, must lie inside
	// ports.allow too (api RFC-038).
	if lp.ports != nil {
		if err := lp.checkJobPorts(&job); err != nil {
			return nil, err
		}
	}
	targets, err := job.targets()
	if err != nil {
		return nil, refuse("payload", "%v", err)
	}
	if len(targets) > MaxScanTargets {
		return nil, refuse("targets", "%d targets, more than the %d allowed per job", len(targets), MaxScanTargets)
	}
	return targets, nil
}

// admitWithoutPolicy is admission on a sensor that requires a local policy
// and has none: a job with a network target or custom templates is refused
// (rule no_local_policy); out-of-band callbacks are turned off, not
// refused. A job without
// network targets (a repository or filesystem scan, a health check) is
// admitted; the scan workspace confines its paths.
func admitWithoutPolicy(cmd *Command) error {
	var job policyJob
	if len(cmd.Payload) > 0 {
		if err := json.Unmarshal(cmd.Payload, &job); err != nil {
			return refuse("payload", "the job payload cannot be read for the policy check: %v", err)
		}
	}
	if len(job.CustomTemplates) > 0 {
		return refuse(LocalPolicyRuleNoPolicy, "the job carries %d custom template(s); %s", len(job.CustomTemplates), noLocalPolicyHelp)
	}
	// Out-of-band callbacks are turned off by the executor instead
	// (AllowsInteractsh is false here); the job is not refused for them.
	targets, err := job.targets()
	if err != nil {
		return refuse("payload", "%v", err)
	}
	for _, t := range targets {
		if isNetworkTarget(t) {
			return noLocalPolicyTarget(t)
		}
	}
	return nil
}

// isNetworkTarget reports whether a job target reaches a network (a URL, a
// host, an address, a range or an image reference) rather than a path.
func isNetworkTarget(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return false
	}
	return strings.Contains(t, "://") || !isPathLike(t)
}

// noLocalPolicyTarget is the refusal of a network target on a sensor that
// requires a local policy and has none.
func noLocalPolicyTarget(t string) error {
	return refuse(LocalPolicyRuleNoPolicy, "%q is a network target; %s", t, noLocalPolicyHelp)
}

// CommandWarnings are what the sensor logs about cmd when no policy
// decides for it: a job that uses custom templates only because no local
// policy forbids them (owner decision Q4 (a)). Out-of-band callbacks follow
// the platform without a policy, which is no warning.
func (lp *LocalPolicy) CommandWarnings(cmd *Command) []string {
	if lp.Present() || lp.failsClosed() || cmd == nil || len(cmd.Payload) == 0 {
		return nil
	}
	var job policyJob
	if json.Unmarshal(cmd.Payload, &job) != nil {
		return nil
	}
	var out []string
	if len(job.CustomTemplates) > 0 {
		out = append(out, fmt.Sprintf("command %s carries %d custom template(s): allowed only because no local policy sets allow_custom_templates", cmd.ID, len(job.CustomTemplates)))
	}
	return out
}

// CheckTarget checks one job target (URL, host, host:port, IP, CIDR) against
// the policy. Host names are resolved and every address must pass, so a
// name that resolves to a denied address is refused. Filesystem targets
// are not network targets; the scan workspace confines them.
//
// Without a policy, a sensor that requires one refuses every network
// target (rule no_local_policy); a legacy install still applies the
// built-in deny list (loopback, link-local and metadata, multicast,
// unspecified, CGNAT, reserved, and private ranges unless the private-range
// switch allows them), so a caller that checks a target directly (a retest,
// a tool task) never reaches those addresses.
func (lp *LocalPolicy) CheckTarget(ctx context.Context, target string) error {
	t := strings.TrimSpace(target)
	if t == "" {
		return nil
	}
	if !lp.Present() {
		if lp.failsClosed() {
			if isNetworkTarget(t) {
				return noLocalPolicyTarget(t)
			}
			return nil
		}
		return lp.builtinOnly().checkTarget(ctx, t)
	}
	return lp.checkTarget(ctx, t)
}

// builtinOnly is the policy a legacy install without a policy file checks
// targets with: no allow or deny lists, so only the built-in deny list and
// the private-range switch (read as the default scan target policy reads
// it) apply.
func (lp *LocalPolicy) builtinOnly() *LocalPolicy {
	b := &LocalPolicy{allowPrivate: DefaultScanTargetPolicy().AllowPrivate}
	if lp != nil {
		b.allowLoopback, b.lookupIP = lp.allowLoopback, lp.lookupIP
	}
	return b
}

// checkTarget is CheckTarget against lp's rules (t is trimmed, not empty).
func (lp *LocalPolicy) checkTarget(ctx context.Context, t string) error {
	host, port := "", 0
	switch {
	case strings.Contains(t, "://"):
		u, err := url.Parse(t)
		if err != nil || u.Hostname() == "" {
			return markTarget(RefusedTargetInvalid, refuse("targets", "%q is not a URL with a host", t))
		}
		host = u.Hostname()
		p, err := urlPort(u)
		if err != nil {
			return refuse("ports.allow", "%q: %v", t, err)
		}
		if p == 0 && lp.ports != nil {
			// The tool would connect to the scheme's own default port,
			// which this policy does not know: it cannot be checked.
			return refuse("ports.allow", "%q: the %s scheme has no default port this sensor knows; name the port in the URL so it can be checked against %s",
				truncateBytes(t, 128), truncateBytes(u.Scheme, 32), lp.portsText)
		}
		port = p
	case isPathLike(t):
		return nil
	default:
		if _, n, err := net.ParseCIDR(t); err == nil {
			return lp.checkCIDR(n)
		}
		var err error
		host, port, err = splitNetworkTarget(t)
		if err != nil {
			return markTarget(RefusedTargetInvalid, refuse("targets", "%q: %v", t, err))
		}
	}
	if isWildcardHost(host) {
		return markTarget(RefusedTargetWildcard, refuse("targets", "%q is a wildcard pattern, not a host the policy can check", t))
	}
	if port != 0 {
		if err := lp.checkPort(port); err != nil {
			return err
		}
	}
	failClosed := strings.Contains(host, ".") || strings.Contains(host, ":")
	_, err := lp.checkHost(ctx, host, failClosed)
	return err
}

// urlPort is the URL's port, or its scheme's default (0 when the sensor
// does not know the scheme's default). A port is plain digits without a
// leading zero (canonicalPort).
func urlPort(u *url.URL) (int, error) {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || !canonicalPort(p) || n < 1 || n > 65535 {
			return 0, fmt.Errorf("port %q is not valid", p)
		}
		return n, nil
	}
	return schemeDefaultPorts[strings.ToLower(u.Scheme)], nil
}

// schemeDefaultPorts are the default ports of the URL schemes a scan
// target commonly has (IANA). A URL of another scheme without a port is
// refused under ports.allow: its tool's default port is not known here.
var schemeDefaultPorts = map[string]int{
	"http": 80, "ws": 80, "https": 443, "wss": 443,
	"ftp": 21, "ftps": 990, "sftp": 22, "ssh": 22, "telnet": 23,
	"smtp": 25, "smtps": 465, "submission": 587, "dns": 53, "tftp": 69,
	"pop3": 110, "pop3s": 995, "imap": 143, "imaps": 993, "nntp": 119, "nntps": 563,
	"ldap": 389, "ldaps": 636, "smb": 445, "rtsp": 554, "rsync": 873,
	"mssql": 1433, "sqlserver": 1433, "oracle": 1521, "mqtt": 1883, "mqtts": 8883,
	"nfs": 2049, "mysql": 3306, "rdp": 3389, "postgres": 5432, "postgresql": 5432,
	"amqp": 5672, "amqps": 5671, "xmpp": 5222, "sip": 5060, "sips": 5061,
	"vnc": 5900, "redis": 6379, "irc": 6667, "ircs": 6697, "git": 9418,
	"kafka": 9092, "memcached": 11211, "mongodb": 27017,
}

// splitNetworkTarget splits host, host:port, [v6]:port and image
// references (registry/path:tag) the way ScanTargetPolicy reads them.
func splitNetworkTarget(t string) (string, int, error) {
	host := t
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	port := 0
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err == nil && canonicalPort(p) && n >= 1 && n <= 65535 {
			port = n
		} else if err == nil {
			// A number that is not a plain port ("0022", "+22", "0"):
			// a tool may read it differently, so it is not checkable.
			return "", 0, fmt.Errorf("port %q is not valid", p)
		} else if !strings.Contains(t, "/") {
			// host:tag of an image reference ("nginx:latest") is not a port.
			if net.ParseIP(h) != nil || strings.Contains(h, ".") {
				return "", 0, fmt.Errorf("port %q is not valid", p)
			}
		}
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return "", 0, fmt.Errorf("no host")
	}
	return host, port, nil
}

// checkIP checks one address: the built-in deny list, the private-range
// switch, targets.deny and targets.allow (CIDR entries; domain entries do
// not match an address).
func (lp *LocalPolicy) checkIP(ip net.IP, name string) error {
	what := ip.String()
	if name != "" {
		what = fmt.Sprintf("%s (resolved from %s)", ip, name)
	}
	loopback := lp.allowLoopback || httpsec.AllowLoopback
	if httpsec.IsIPBlockedWith(ip, true, loopback) {
		return refuse("builtin", "%s is in the built-in deny list", what)
	}
	if httpsec.IsIPBlockedWith(ip, false, loopback) && !lp.allowPrivate {
		return refuse("targets.allow_private", "%s is a private address", what)
	}
	for _, n := range lp.denyNets {
		if n.Contains(ip) {
			return refuse("targets.deny", "%s is in %s", what, n)
		}
	}
	return nil
}

func (lp *LocalPolicy) inAllowNets(ip net.IP) bool {
	for _, n := range lp.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (lp *LocalPolicy) nameDenied(name string) *domainPattern {
	for i := range lp.denyDomains {
		if lp.denyDomains[i].matches(name) {
			return &lp.denyDomains[i]
		}
	}
	return nil
}

func (lp *LocalPolicy) nameAllowed(name string) bool {
	for _, d := range lp.allowDomains {
		if d.matches(name) {
			return true
		}
	}
	return false
}

// AdmittedAddrs checks a host name or address as CheckTarget does and
// returns the addresses it checked: a confined task's forwarder dials a
// target at these addresses only, never at what the name resolves to
// later. Without a policy the built-in deny list applies, as CheckTarget
// applies it: every address of this lookup is checked again, so a name
// re-bound to a private, loopback, CGNAT or metadata address after the
// target check is refused here and never pinned (DNS rebinding).
func (lp *LocalPolicy) AdmittedAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	if lp.failsClosed() {
		return nil, noLocalPolicyTarget(host)
	}
	check := lp
	if !lp.Present() {
		check = lp.builtinOnly()
	}
	ips, err := check.checkHost(ctx, host, true)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

// checkHost checks a host (name or address literal) and returns the
// addresses it checked. A name is allowed when it matches a targets.allow
// domain or when every address it resolves to lies in a targets.allow
// range; in both cases every address must also pass checkIP. A dotless
// name that does not resolve (an image reference such as "alpine") passes
// unless failClosed.
func (lp *LocalPolicy) checkHost(ctx context.Context, host string, failClosed bool) ([]net.IP, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	if ip := net.ParseIP(name); ip != nil {
		if err := lp.checkIP(ip, ""); err != nil {
			return nil, err
		}
		if lp.targetsAllowSet && !lp.inAllowNets(ip) {
			return nil, refuse("targets.allow", "%s is not in an allowed range", ip)
		}
		return []net.IP{ip}, nil
	}
	if d := lp.nameDenied(name); d != nil {
		return nil, refuse("targets.deny", "%s matches %s", name, d)
	}
	ips, err := lp.resolve(ctx, name)
	if err != nil || len(ips) == 0 {
		if failClosed {
			return nil, markUnresolved(err, refuse("targets", "cannot resolve %s (an address the policy cannot check is refused)", name))
		}
		// An unresolvable dotless name is an image reference ("alpine"),
		// not a host: it reaches no target network.
		return nil, nil
	}
	if err := lp.checkResolved(name, ips); err != nil {
		return nil, err
	}
	return ips, nil
}

// checkResolved checks the addresses a name resolved to: each must pass
// checkIP, and with an allow list the name must match an allowed domain or
// every address must lie in an allowed range.
func (lp *LocalPolicy) checkResolved(name string, ips []net.IP) error {
	for _, ip := range ips {
		if err := lp.checkIP(ip, name); err != nil {
			return err
		}
	}
	if lp.targetsAllowSet && !lp.nameAllowed(name) {
		for _, ip := range ips {
			if !lp.inAllowNets(ip) {
				return refuse("targets.allow", "%s resolves to %s, which is outside the allowed ranges and domains", name, ip)
			}
		}
	}
	return nil
}

func (d *domainPattern) String() string {
	if d.wildcard {
		return "*." + d.name
	}
	return d.name
}

// checkCIDR checks a range target: no overlap with the built-in deny list
// (or private space without the switch) or targets.deny, and, with an
// allow list, inside one targets.allow range.
func (lp *LocalPolicy) checkCIDR(n *net.IPNet) error {
	stp := &ScanTargetPolicy{AllowPrivate: lp.allowPrivate, AllowLoopback: lp.allowLoopback || httpsec.AllowLoopback}
	if err := stp.checkCIDR(n); err != nil {
		rule := "builtin"
		if !lp.allowPrivate && (&ScanTargetPolicy{AllowPrivate: true, AllowLoopback: stp.AllowLoopback}).checkCIDR(n) == nil {
			rule = "targets.allow_private"
		}
		return refuse(rule, "%v", err)
	}
	for _, d := range lp.denyNets {
		if d.Contains(n.IP) || n.Contains(d.IP) {
			return refuse("targets.deny", "%s overlaps %s", n, d)
		}
	}
	if !lp.targetsAllowSet {
		return nil
	}
	ones, bits := n.Mask.Size()
	for _, a := range lp.allowNets {
		aOnes, aBits := a.Mask.Size()
		if aBits == bits && aOnes <= ones && a.Contains(n.IP) {
			return nil
		}
	}
	return refuse("targets.allow", "%s is not inside an allowed range", n)
}

func (lp *LocalPolicy) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if lp != nil && lp.lookupIP != nil {
		return lp.lookupIP(ctx, host)
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", absname.Of(host))
}

// CheckDial is the egress hook (api RFC-034's in-sensor forwarder, and any
// in-process dial a tool makes): it checks a connection to address
// ("host:port") and returns the addresses the connection may use. Callers
// must connect to one of them, never resolve the name again (that is what
// defeats DNS rebinding). The built-in deny list applies even without a
// policy; with one, ports.allow and the target rules apply too. A sensor
// that requires a policy and has none refuses every dial.
func (lp *LocalPolicy) CheckDial(ctx context.Context, network, address string) ([]net.IP, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, refuse("targets", "%q: %v", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, refuse("ports.allow", "%q: port %q is not valid", address, portStr)
	}
	if lp.failsClosed() {
		return nil, noLocalPolicyTarget(address)
	}
	if !lp.Present() {
		// No policy: the built-in deny list, with the private-range switch
		// as the scan target policy reads it.
		stp := DefaultScanTargetPolicy()
		if lp != nil && lp.allowLoopback {
			stp.AllowLoopback = true
		}
		var ips []net.IP
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			if ips, err = lp.resolve(ctx, host); err != nil || len(ips) == 0 {
				return nil, refuse("targets", "cannot resolve %s", host)
			}
		}
		for _, ip := range ips {
			if httpsec.IsIPBlockedWith(ip, stp.AllowPrivate, stp.AllowLoopback) {
				return nil, refuse("builtin", "%s (%s) is in the built-in deny list", host, ip)
			}
		}
		return ips, nil
	}
	if err := lp.checkPort(port); err != nil {
		return nil, err
	}
	ips, err := lp.checkHost(ctx, host, true)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// DialContext wraps d (nil: a zero net.Dialer) with CheckDial: it checks
// every connection against the policy and dials the checked addresses, in
// order, never the name. Use it for in-process scanners and the egress
// forwarder.
func (lp *LocalPolicy) DialContext(d *net.Dialer) func(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil {
		d = &net.Dialer{}
	}
	return lp.DialContextVia(d.DialContext)
}

// DialContextVia is DialContext with the connections made by dial, which is
// given the checked address as ip:port (never a name): a job's proxy pool
// (EgressDialer.Dial) for a probe that must leave through it. A nil dial is
// a zero net.Dialer.
func (lp *LocalPolicy) DialContextVia(dial func(ctx context.Context, network, address string) (net.Conn, error)) func(ctx context.Context, network, address string) (net.Conn, error) {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ips, err := lp.CheckDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		host, port, _ := net.SplitHostPort(address)
		portNum, _ := strconv.Atoi(port)
		rec := reach.FromContext(ctx)
		var last error
		for _, ip := range ips {
			addr, _ := netip.AddrFromSlice(ip)
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			rec.RecordErr(host, addr, portNum, err)
			if err == nil {
				return conn, nil
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, last
	}
}
