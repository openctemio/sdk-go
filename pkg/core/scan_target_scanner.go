package core

import (
	"context"
	"fmt"
	"net"
	"strings"
	"unicode"
)

// Scan targets are checked according to the scanner that receives them.
//
// Network scanners (nuclei, httpx, the recon tools, and any scanner not
// listed below) take hosts, host:port pairs, URLs and ranges: each is held to
// the network guard (ValidateNetworkTarget), where a name that does not
// resolve is refused, never handed on. Code scanners (betterleaks, semgrep,
// trivy filesystem modes, ...) take a directory: a path target is confined to
// AllowedRoots, a repository URL gets the network guard, and a trivy image
// reference gets its registry host checked.
//
// Threat model: the target is server-supplied and attacker-influenceable (a
// tenant admin or a compromised platform names the asset). Without the guard
// a network scanner aimed at http://169.254.169.254 returns cloud credentials
// inside a finding, and a code scanner aimed at ~/.ssh ships the keys back as
// findings. A target that cannot be checked (a name that does not resolve
// now and could resolve to a private address at scan time) is refused.

// RefusedTargetRuleGuard is the rule of a target the scan-target guard (the
// built-in network and path checks of ScanTargetPolicy) refused, as opposed
// to a local policy rule. The platform counts these per task.
const RefusedTargetRuleGuard = "target_guard"

// codeScanners take a filesystem path (or a remote repository URL) as their
// target. Everything else is a network scanner.
var codeScanners = map[string]bool{
	"betterleaks":  true,
	"trufflehog":   true,
	"semgrep":      true,
	"opengrep":     true,
	"codeql":       true,
	"bandit":       true,
	"gosec":        true,
	"checkov":      true,
	"tfsec":        true,
	"kics":         true,
	"trivy":        true,
	"trivy-fs":     true,
	"trivy-config": true,
	"trivy-full":   true,
	"trivy-image":  true,
}

// trivyScanners accept a container-image reference as well as a path.
var trivyScanners = map[string]bool{
	"trivy": true, "trivy-fs": true, "trivy-full": true, "trivy-image": true,
}

// IsCodeScanner reports whether scanner takes a filesystem path target.
func IsCodeScanner(scanner string) bool {
	return codeScanners[normScanner(scanner)]
}

func normScanner(scanner string) string {
	return strings.ToLower(strings.TrimSpace(CanonicalScannerName(scanner)))
}

// ValidateFor checks target for the scanner that will receive it when the
// policy is ByScanner (Validate otherwise), and returns
// the value to hand to the scanner (a confined, symlink-resolved path for a
// code scanner's directory; the target unchanged otherwise). See the package
// notes above for how each kind of scanner is checked.
func (p *ScanTargetPolicy) ValidateFor(ctx context.Context, scanner, target string) (string, error) {
	if p == nil {
		p = DefaultScanTargetPolicy()
	}
	if p.Disabled {
		return target, nil
	}
	if !p.ByScanner {
		return p.Validate(ctx, target)
	}
	if err := checkTargetSyntax(target); err != nil {
		return "", err
	}
	if !IsCodeScanner(scanner) {
		return target, p.ValidateNetworkTarget(ctx, target)
	}
	// A remote repository URL is fetched over the network.
	if strings.Contains(target, "://") {
		return target, p.ValidateNetworkTarget(ctx, target)
	}
	name := normScanner(scanner)
	if trivyScanners[name] && (name == "trivy-image" || isImageRef(target)) {
		// A container image (nginx:latest, ghcr.io/org/app:1) is pulled from
		// its registry: an explicit registry host is checked.
		return target, p.checkImageRegistry(ctx, target)
	}
	return p.validatePathTarget(target)
}

// checkTargetSyntax refuses targets that are unsafe to hand to any tool:
// empty, padded, flag-like or carrying control characters.
func checkTargetSyntax(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("scan target is required")
	}
	if target != strings.TrimSpace(target) {
		return fmt.Errorf("scan target has leading or trailing whitespace")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("scan target %q looks like a command-line flag", target)
	}
	for _, r := range target {
		if unicode.IsControl(r) {
			return fmt.Errorf("scan target contains control characters")
		}
	}
	return nil
}

// ValidateNetworkTarget checks a target a network tool will connect to: a
// URL (http and https only), a host, an address, host:port ("203.0.113.7:80",
// "example.com:443", "[2001:db8::1]:443") or a range. The host must not be a
// blocked name, an address in a blocked range (loopback, link-local and cloud
// metadata, CGNAT, multicast, reserved; RFC1918 and ULA unless AllowPrivate),
// or a name that resolves to one. A name that does not resolve is refused
// (fail closed): it cannot be proven safe, and it could resolve to a blocked
// address when the tool connects. The local policy, when set, applies too.
func (p *ScanTargetPolicy) ValidateNetworkTarget(ctx context.Context, target string) error {
	if p == nil {
		p = DefaultScanTargetPolicy()
	}
	if p.Disabled {
		return nil
	}
	if p.Local.failsClosed() {
		return noLocalPolicyTarget(target)
	}
	if strings.Contains(target, "://") {
		return p.validateURLTarget(ctx, target)
	}
	if _, ipNet, err := net.ParseCIDR(target); err == nil {
		if err := p.checkCIDR(ipNet); err != nil {
			return err
		}
		if p.Local.Present() {
			return p.Local.checkCIDR(ipNet)
		}
		return nil
	}
	host := target
	if h, port, err := net.SplitHostPort(target); err == nil {
		host = h
		if p.Local.Present() {
			n, perr := parsePort(port)
			if perr != nil {
				return refuse("targets", "%q: %v", target, perr)
			}
			if err := p.Local.checkPort(n); err != nil {
				return err
			}
		}
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return markTarget(RefusedTargetInvalid, fmt.Errorf("scan target %q has no host", target))
	}
	// Everything else (a path, "name/x", "a:b:c") is looked up as a name and,
	// not resolving, refused.
	return p.checkHost(ctx, host, true)
}

// isImageRef reports whether a trivy target is a container-image reference
// (registry coordinate) rather than a local filesystem path.
func isImageRef(target string) bool {
	return strings.HasPrefix(target, "docker:") ||
		strings.HasPrefix(target, "ghcr.io") ||
		strings.HasPrefix(target, "registry.") ||
		(strings.Contains(target, ":") && !strings.Contains(target, "/"))
}

// checkImageRegistry checks the registry host of an image reference when it
// names one ("registry.example.com/app:1", "10.0.0.5:5000/app"). A bare name
// ("nginx:latest") uses the default registry and has no host here.
func (p *ScanTargetPolicy) checkImageRegistry(ctx context.Context, ref string) error {
	ref = strings.TrimPrefix(ref, "docker:")
	first, _, hasPath := strings.Cut(ref, "/")
	if !hasPath || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		return nil
	}
	return p.ValidateNetworkTarget(ctx, first)
}

// guardRefusal describes a target the scan-target policy refused: a local
// policy rule keeps its rule, a built-in check is RefusedTargetRuleGuard.
func guardRefusal(target string, err error) RefusedTarget {
	rt := refusedTargetOf(target, err)
	if rt.Rule == "" {
		rt.Rule = RefusedTargetRuleGuard
	}
	return rt
}
