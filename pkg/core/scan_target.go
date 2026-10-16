package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/internal/absname"
)

// Scan target validation for server-dispatched commands.
//
// A scan command's target comes from the server. A compromised server, a
// malicious tenant admin, or anyone who can inject a command must not be able
// to turn the sensor into an SSRF proxy (e.g. nuclei against
// http://169.254.169.254 returns cloud IAM credentials inside a finding), a
// local file reader (semgrep/betterleaks over /etc or ~/.ssh ships their content
// back as findings), or a flag injector (a target of "-config=/tmp/x" is
// parsed by the scanner as an option). DefaultCommandExecutor therefore runs
// every scan target through a ScanTargetPolicy before invoking the scanner.

// Environment variables read by DefaultScanTargetPolicy.
const (
	// EnvScanRoots is a filepath.ListSeparator-separated list (':' on Unix)
	// of directories filesystem scan targets must live under.
	EnvScanRoots = "OPENCTEM_SDK_SCAN_ROOTS"
	// EnvSensorAllowPrivateTargets=1 permits RFC1918 / IPv6 ULA network
	// targets. It is the one switch for scan targets.
	EnvSensorAllowPrivateTargets = "SENSOR_ALLOW_PRIVATE_TARGETS"
	// EnvAllowPrivateTargets is EnvSensorAllowPrivateTargets.
	//
	// Deprecated: use EnvSensorAllowPrivateTargets. The separate
	// OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS switch is gone.
	EnvAllowPrivateTargets = EnvSensorAllowPrivateTargets
)

// sensitiveScanRoots are refused as filesystem targets when no AllowedRoots
// are configured. Mirrors the OpenCTEM sensor's confineScanPath.
var sensitiveScanRoots = []string{
	"/etc", "/root", "/proc", "/sys", "/boot", "/dev", "/run",
	"/usr", "/bin", "/sbin", "/lib", "/lib64", "/var/lib", "/var/run",
}

// sensitiveHomeDirs are refused (relative to the user's home) when no
// AllowedRoots are configured.
var sensitiveHomeDirs = []string{".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gcloud", ".azure", ".openctem"}

// blockedTargetHosts are rejected by name before DNS: loopback and cloud
// metadata aliases are never legitimate scan targets.
var blockedTargetHosts = []string{
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata",
	"metadata.google.internal",
	"metadata.google",
	"instance-data",
	"instance-data.ec2.internal",
}

// ScanTargetPolicy decides whether a server-supplied scan target may be
// scanned. The zero value is NOT the secure default; use
// DefaultScanTargetPolicy and adjust.
type ScanTargetPolicy struct {
	// AllowedRoots confines filesystem targets. When non-empty, a path target
	// must resolve (after following symlinks) to one of these directories or
	// a descendant. When empty, filesystem targets are allowed anywhere
	// except the filesystem root, sensitive system directories (/etc, /proc,
	// /root, ...) and credential directories in the user's home (~/.ssh,
	// ~/.aws, ...). Configuring roots is strongly recommended.
	AllowedRoots []string

	// AllowPrivate permits network targets in RFC1918 (10/8, 172.16/12,
	// 192.168/16) and IPv6 ULA (fc00::/7) space, for sensors that scan an
	// internal network. Loopback, link-local (incl. 169.254.169.254 IMDS),
	// CGNAT, multicast, unspecified and reserved ranges stay blocked
	// regardless.
	AllowPrivate bool

	// AllowLoopback permits 127.0.0.0/8 and ::1. Test-only; mirrors
	// httpsec.AllowLoopback.
	AllowLoopback bool

	// ByScanner checks each target by the scanner that receives it
	// (ValidateFor): a code scanner's path is confined to AllowedRoots, and
	// every other scanner is a network scanner whose targets must be hosts,
	// host:port pairs, URLs or ranges, a name that does not resolve being
	// refused. Off, a target is read by its shape whatever the scanner
	// (Validate). A sensor whose tools are known by name sets it.
	ByScanner bool

	// Shared is a shared sensor's job check (api RFC-100 §8): after every
	// other rule passed, a private address or range passes only inside the
	// job's zone (CheckSharedAddr, CheckSharedPrefix); other non-public
	// addresses never do.
	Shared bool

	// Disabled turns validation off entirely. Only for callers that validate
	// targets themselves before the executor sees the command.
	Disabled bool

	// LookupIP resolves a hostname; nil uses net.DefaultResolver. Exposed
	// for tests.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)

	// Local is the sensor-local policy (api RFC-040 §5.7): when set, network
	// targets must also pass its target, range and port rules, checked
	// against the same resolved addresses. It can only narrow what this
	// policy allows. nil: no local policy.
	Local *LocalPolicy
}

// DefaultScanTargetPolicy returns the policy DefaultCommandExecutor uses
// unless SetScanTargetPolicy is called:
//
//   - AllowedRoots from OPENCTEM_SDK_SCAN_ROOTS (unset = sensitive-path
//     denylist only);
//   - AllowPrivate when SENSOR_ALLOW_PRIVATE_TARGETS=1, the one switch for
//     scan targets (the SDK's own egress has its own switch,
//     OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE, which does not widen targets);
//   - AllowLoopback follows httpsec.AllowLoopback (test harnesses only).
func DefaultScanTargetPolicy() *ScanTargetPolicy {
	var roots []string
	for _, r := range filepath.SplitList(os.Getenv(EnvScanRoots)) {
		if r = strings.TrimSpace(r); r != "" {
			roots = append(roots, r)
		}
	}
	return &ScanTargetPolicy{
		AllowedRoots:  roots,
		AllowPrivate:  os.Getenv(EnvSensorAllowPrivateTargets) == "1",
		AllowLoopback: httpsec.AllowLoopback,
	}
}

// CheckEnv reports a configuration error in the environment variables the
// default scan target policy reads: an allow-private switch set to anything
// but "1" (allow) or "0"/empty (refuse). Only "1" enables the switch, so
// "true" or "yes" would otherwise be silently ignored and every private
// target refused. It also reports an unrecognized OPENCTEM_SDK_SCANNER_PROXY
// (EnvScannerProxy). A sensor calls it at startup to refuse to start instead
// of failing jobs later.
func CheckEnv() error {
	if scannerProxyErr != nil {
		return scannerProxyErr
	}
	for _, name := range []string{
		EnvSensorAllowPrivateTargets,
		"OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE",
	} {
		switch v := strings.TrimSpace(os.Getenv(name)); v {
		case "", "0", "1":
		default:
			return fmt.Errorf("%s=%q is not recognized: set it to 1 to allow private-network targets, or 0 (or unset) to refuse them", name, v)
		}
	}
	return nil
}

// Validate checks target and returns the value to hand to the scanner: for
// filesystem targets the cleaned, symlink-resolved absolute path (so the
// scanner reads exactly what was checked); otherwise the target unchanged.
func (p *ScanTargetPolicy) Validate(ctx context.Context, target string) (string, error) {
	if p == nil {
		p = DefaultScanTargetPolicy()
	}
	if p.Disabled {
		return target, nil
	}

	if strings.TrimSpace(target) == "" {
		return "", fmt.Errorf("scan target is required")
	}
	if target != strings.TrimSpace(target) {
		return "", fmt.Errorf("scan target has leading or trailing whitespace")
	}
	if strings.HasPrefix(target, "-") {
		return "", fmt.Errorf("scan target %q looks like a command-line flag", target)
	}
	for _, r := range target {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("scan target contains control characters")
		}
	}

	switch {
	case strings.Contains(target, "://"):
		if p.Local.failsClosed() {
			return "", noLocalPolicyTarget(target)
		}
		return target, p.validateURLTarget(ctx, target)
	case strings.HasPrefix(strings.ToLower(target), "file:"):
		return "", fmt.Errorf("file: URLs are not allowed as scan targets")
	case isPathLike(target):
		return p.validatePathTarget(target)
	default:
		// A sensor that requires a local policy and has none scans no
		// network target (admission refused the job already).
		if p.Local.failsClosed() {
			return "", noLocalPolicyTarget(target)
		}
		return target, p.validateNetworkTarget(ctx, target)
	}
}

// isPathLike reports whether target should be treated as a filesystem path.
// Explicit path syntax always is; a bare relative name is a path only if it
// exists on disk (otherwise it is a host, IP, CIDR or image reference).
func isPathLike(target string) bool {
	if filepath.IsAbs(target) || target == "." || target == ".." ||
		strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") ||
		strings.HasPrefix(target, "~") || strings.HasPrefix(target, `.\`) ||
		strings.HasPrefix(target, `..\`) {
		return true
	}
	_, err := os.Lstat(target)
	return err == nil
}

func (p *ScanTargetPolicy) validatePathTarget(target string) (string, error) {
	if strings.HasPrefix(target, "~") {
		return "", fmt.Errorf("scan target %q: '~' paths are not expanded; use an absolute path", target)
	}
	path := target
	if !filepath.IsAbs(path) && len(p.AllowedRoots) > 0 {
		// A relative target is taken in the first scan root, never in
		// whatever directory the process happens to run in.
		path = filepath.Join(p.AllowedRoots[0], path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid scan target path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("scan target path %q: %w", target, err)
	}

	if len(p.AllowedRoots) > 0 {
		for _, root := range p.AllowedRoots {
			rootAbs, err := filepath.Abs(root)
			if err != nil {
				continue
			}
			rootResolved, err := filepath.EvalSymlinks(rootAbs)
			if err != nil {
				continue
			}
			if isWithin(rootResolved, resolved) {
				// A root configured over a sensitive directory still
				// does not expose it.
				if err := checkSensitivePath(resolved); err != nil {
					return "", err
				}
				return resolved, nil
			}
		}
		return "", fmt.Errorf("scan target path %q is outside the allowed scan roots", target)
	}
	if err := checkSensitivePath(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// checkSensitivePath refuses the filesystem root, sensitive system
// directories and credential directories in the user's home.
func checkSensitivePath(resolved string) error {
	if resolved == string(filepath.Separator) || filepath.Dir(resolved) == resolved {
		return fmt.Errorf("refusing to scan filesystem root")
	}
	for _, root := range sensitiveScanRoots {
		if isWithin(root, resolved) {
			return fmt.Errorf("refusing to scan sensitive system path %q", resolved)
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if h, err := filepath.EvalSymlinks(home); err == nil {
			home = h
		}
		for _, d := range sensitiveHomeDirs {
			if isWithin(filepath.Join(home, d), resolved) {
				return fmt.Errorf("refusing to scan sensitive path %q", resolved)
			}
		}
	}
	return nil
}

// isWithin reports whether path is root or lies inside it. Both must be
// clean absolute paths.
func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func (p *ScanTargetPolicy) validateURLTarget(ctx context.Context, target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("scan target is not a valid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("scan target scheme %q is not allowed (only http/https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("scan target URL has no host")
	}
	if p.Local.Present() {
		port, err := urlPort(u)
		if err != nil {
			return refuse("ports.allow", "%q: %v", target, err)
		}
		if err := p.Local.checkPort(port); err != nil {
			return err
		}
	}
	return p.checkHost(ctx, host, true)
}

// validateNetworkTarget handles bare hosts, host:port, IPs, CIDRs and
// registry/image references (host/path:tag).
func (p *ScanTargetPolicy) validateNetworkTarget(ctx context.Context, target string) error {
	// CIDR range: reject if it overlaps any blocked range.
	if _, ipNet, err := net.ParseCIDR(target); err == nil {
		if err := p.checkCIDR(ipNet); err != nil {
			return err
		}
		if p.Shared {
			if pfx, ok := netip.AddrFromSlice(ipNet.IP); ok {
				ones, _ := ipNet.Mask.Size()
				if err := CheckSharedPrefix(ctx, netip.PrefixFrom(pfx.Unmap(), ones)); err != nil {
					return err
				}
			}
		}
		if p.Local.Present() {
			return p.Local.checkCIDR(ipNet)
		}
		return nil
	}
	if p.Local.Present() {
		_, port, err := splitNetworkTarget(target)
		if err != nil {
			return refuse("targets", "%q: %v", target, err)
		}
		if port != 0 {
			if err := p.Local.checkPort(port); err != nil {
				return err
			}
		}
	}

	host := target
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i] // registry host of an image ref / path suffix
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	} else if strings.Count(host, ":") == 1 {
		host = host[:strings.IndexByte(host, ':')] // name:tag image ref
	}
	if host == "" {
		return fmt.Errorf("scan target %q has no host", target)
	}
	// Dotless names that do not resolve are image references ("alpine",
	// "nginx:latest"), not hosts; dotted names must resolve (fail closed).
	failClosed := strings.Contains(host, ".") || strings.Contains(host, ":")
	return p.checkHost(ctx, host, failClosed)
}

func (p *ScanTargetPolicy) checkHost(ctx context.Context, host string, failClosedOnDNS bool) error {
	lower := strings.TrimSuffix(strings.ToLower(host), ".")
	if isWildcardHost(lower) {
		return markTarget(RefusedTargetWildcard, fmt.Errorf("scan target host %q is a wildcard pattern, not a host", host))
	}
	for _, b := range blockedTargetHosts {
		if lower == b && !(p.AllowLoopback && strings.HasPrefix(b, "localhost")) {
			return markTarget(RefusedTargetDenied, fmt.Errorf("scan target host %q is blocked", host))
		}
	}
	if strings.HasSuffix(lower, ".localhost") && !p.AllowLoopback {
		return markTarget(RefusedTargetDenied, fmt.Errorf("scan target host %q is blocked", host))
	}

	if ip := net.ParseIP(lower); ip != nil {
		if httpsec.IsIPBlockedWith(ip, p.AllowPrivate, p.AllowLoopback) {
			return markTarget(RefusedTargetDenied, fmt.Errorf("scan target IP %s is in a blocked range", ip))
		}
		if err := p.checkShared(ctx, ip); err != nil {
			return err
		}
		if p.Local.Present() {
			_, err := p.Local.checkHost(ctx, lower, true)
			return err
		}
		return nil
	}
	if p.Local.Present() {
		if d := p.Local.nameDenied(lower); d != nil {
			return refuse("targets.deny", "%s matches %s", lower, d)
		}
	}

	lookup := p.LookupIP
	if lookup == nil && p.Local.Present() {
		// The local policy resolves the way admission did.
		lookup = p.Local.resolve
	}
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", absname.Of(host))
		}
	}
	ips, err := lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		if failClosedOnDNS {
			return markTarget(RefusedTargetUnresolvable, fmt.Errorf("cannot resolve scan target host %q (refusing to scan an unverifiable target): %v", host, err))
		}
		return nil
	}
	for _, ip := range ips {
		if httpsec.IsIPBlockedWith(ip, p.AllowPrivate, p.AllowLoopback) {
			return markTarget(RefusedTargetDenied, fmt.Errorf("scan target host %q resolves to blocked address %s", host, ip))
		}
		if err := p.checkShared(ctx, ip); err != nil {
			return err
		}
	}
	if p.Local.Present() {
		// The same addresses, not a second resolution.
		return p.Local.checkResolved(lower, ips)
	}
	return nil
}

// checkCIDR rejects a range that overlaps any blocked address: two prefixes
// overlap iff one contains the other's network address. Each blocked range
// is probed through IsIPBlockedWith so the toggles apply consistently.
func (p *ScanTargetPolicy) checkCIDR(n *net.IPNet) error {
	if httpsec.IsIPBlockedWith(n.IP, p.AllowPrivate, p.AllowLoopback) {
		return markTarget(RefusedTargetDenied, fmt.Errorf("scan target range %s includes blocked addresses", n))
	}
	for _, blocked := range blockedRangesForOverlap {
		if n.Contains(blocked.IP) && httpsec.IsIPBlockedWith(blocked.IP, p.AllowPrivate, p.AllowLoopback) {
			return markTarget(RefusedTargetDenied, fmt.Errorf("scan target range %s overlaps blocked range %s", n, blocked))
		}
	}
	return nil
}

// blockedRangesForOverlap lists the network addresses of every range httpsec
// can block, used to detect a broad CIDR (e.g. 0.0.0.0/0, 169.0.0.0/8)
// that contains a blocked range.
var blockedRangesForOverlap = mustCIDRs(
	"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
	"224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"192.0.0.0/24", "198.18.0.0/15",
	"::1/128", "::/128", "fe80::/10", "fec0::/10", "ff00::/8", "fc00::/7",
	"fd00:ec2::254/128", "fd20:ce::254/128",
	// IPv6 ranges that carry IPv4 addresses (ctis addrscope): a range
	// holding their start holds addresses that carry internal ones.
	"64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// checkShared applies the shared sensor's zone rule to one address (no-op
// unless Shared).
func (p *ScanTargetPolicy) checkShared(ctx context.Context, ip net.IP) error {
	if !p.Shared {
		return nil
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return markTarget(RefusedTargetDenied, fmt.Errorf("scan target address %v is not valid", ip))
	}
	return CheckSharedAddr(ctx, a)
}
