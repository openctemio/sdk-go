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
	"net/url"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/httpsec"
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
	// CustomTemplates only needs its length.
	CustomTemplates []json.RawMessage `json:"custom_templates"`
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
// tools.allow, allow_custom_templates, allow_interactsh, and every target
// against targets.allow/deny, the private-range switch, the built-in deny
// list (host names are resolved; every address must pass) and ports.allow.
// A single violation refuses the whole job with a *LocalPolicyError naming
// the rule; nothing in the payload can widen the policy. Without a policy
// only the kill switch applies.
func (lp *LocalPolicy) AdmitCommand(ctx context.Context, cmd *Command) error {
	if why := lp.killSwitchReason(); why != "" {
		return refuse("kill_switch", "%s", why)
	}
	if !lp.Present() || cmd == nil {
		return nil
	}
	if !lp.AllowsCheck(cmd.Type) {
		return refuse("checks.allow", "%q jobs are not allowed on this sensor", cmd.Type)
	}
	var job policyJob
	if len(cmd.Payload) > 0 {
		if err := json.Unmarshal(cmd.Payload, &job); err != nil {
			return refuse("payload", "the job payload cannot be read for the policy check: %v", err)
		}
	}
	tool := job.tool(cmd.Type)
	if lp.tools != nil {
		switch {
		case tool != "" && !lp.AllowsTool(tool):
			return refuse("tools.allow", "%s is not allowed on this sensor", tool)
		case tool == "" && (cmd.Type == "scan" || cmd.Type == "collect"):
			return refuse("tools.allow", "the job names no tool")
		}
	}
	if len(job.CustomTemplates) > 0 && !lp.AllowsCustomTemplates() {
		return refuse("allow_custom_templates", "the job carries %d custom template(s); this sensor's policy does not allow platform-supplied templates", len(job.CustomTemplates))
	}
	// The executor turns callbacks on only for a boolean true; so does this.
	if v, ok := job.Config["allow_interactsh"].(bool); ok && v && !lp.AllowsInteractsh() {
		return refuse("allow_interactsh", "the job asks for out-of-band callbacks (interactsh); this sensor's policy does not allow them")
	}
	// A port list the job hands its tool as a setting (api RFC-038, e.g.
	// naabu's "ports") must lie inside ports.allow too.
	if v, ok := job.Config["ports"]; ok && lp.ports != nil {
		if err := lp.checkPortSetting(v); err != nil {
			return err
		}
	}
	targets, err := job.targets()
	if err != nil {
		return refuse("payload", "%v", err)
	}
	if len(targets) > MaxScanTargets {
		return refuse("targets", "%d targets, more than the %d allowed per job", len(targets), MaxScanTargets)
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

// CommandWarnings are what the sensor logs about cmd when no policy
// decides for it: a job that uses custom templates or out-of-band
// callbacks only because no local policy forbids them (owner decision
// Q4 (a)).
func (lp *LocalPolicy) CommandWarnings(cmd *Command) []string {
	if lp.Present() || cmd == nil || len(cmd.Payload) == 0 {
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
	if v, ok := job.Config["allow_interactsh"].(bool); ok && v {
		out = append(out, fmt.Sprintf("command %s turns on out-of-band callbacks: allowed only because no local policy sets allow_interactsh", cmd.ID))
	}
	return out
}

// CheckTarget checks one job target (URL, host, host:port, IP, CIDR) against
// the policy. Host names are resolved and every address must pass, so a
// name that resolves to a denied address is refused. Filesystem targets
// are not network targets; the scan workspace confines them. Without a
// policy it allows everything (ScanTargetPolicy applies the built-in deny
// list).
func (lp *LocalPolicy) CheckTarget(ctx context.Context, target string) error {
	if !lp.Present() {
		return nil
	}
	t := strings.TrimSpace(target)
	if t == "" {
		return nil
	}
	host, port := "", 0
	switch {
	case strings.Contains(t, "://"):
		u, err := url.Parse(t)
		if err != nil || u.Hostname() == "" {
			return refuse("targets", "%q is not a URL with a host", t)
		}
		host = u.Hostname()
		p, err := urlPort(u)
		if err != nil {
			return refuse("ports.allow", "%q: %v", t, err)
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
			return refuse("targets", "%q: %v", t, err)
		}
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

// urlPort is the URL's port, or its scheme's default (0 when the scheme
// has none).
func urlPort(u *url.URL) (int, error) {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("port %q is not valid", p)
		}
		return n, nil
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "ws":
		return 80, nil
	case "https", "wss":
		return 443, nil
	}
	return 0, nil
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
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
			port = n
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

func (lp *LocalPolicy) checkPort(port int) error {
	if lp.ports == nil {
		return nil
	}
	for _, r := range lp.ports {
		if port >= r.lo && port <= r.hi {
			return nil
		}
	}
	return refuse("ports.allow", "port %d is not in %s", port, lp.portsText)
}

// checkPortSetting checks a job's "ports" setting: a port number or a list
// such as "80,443,8000-8100", every port of which ports.allow must allow. A
// value the policy cannot read ("top-100", "full") is refused.
func (lp *LocalPolicy) checkPortSetting(v any) error {
	var spec string
	switch x := v.(type) {
	case string:
		spec = x
	case float64:
		spec = strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return refuse("ports.allow", "the job's ports setting %v cannot be checked against the policy", v)
	}
	ranges, err := parsePorts(spec)
	if err != nil {
		return refuse("ports.allow", "the job's ports setting %q cannot be checked against the policy", spec)
	}
	for _, r := range ranges {
		for p := r.lo; p <= r.hi; p++ {
			if err := lp.checkPort(p); err != nil {
				return refuse("ports.allow", "the job's ports setting %q includes port %d, which is not in %s", spec, p, lp.portsText)
			}
		}
	}
	return nil
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
			return nil, refuse("targets", "cannot resolve %s (an address the policy cannot check is refused)", name)
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
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// CheckDial is the egress hook (api RFC-034's in-sensor forwarder, and any
// in-process dial a tool makes): it checks a connection to address
// ("host:port") and returns the addresses the connection may use. Callers
// must connect to one of them, never resolve the name again (that is what
// defeats DNS rebinding). The built-in deny list applies even without a
// policy; with one, ports.allow and the target rules apply too.
func (lp *LocalPolicy) CheckDial(ctx context.Context, network, address string) ([]net.IP, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, refuse("targets", "%q: %v", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, refuse("ports.allow", "%q: port %q is not valid", address, portStr)
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
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ips, err := lp.CheckDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		_, port, _ := net.SplitHostPort(address)
		var last error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
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
