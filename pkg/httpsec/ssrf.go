// Package httpsec provides SSRF-safe URL validation and HTTP client
// construction for the OpenCTEM SDK.
//
// This is a lifted copy of api/pkg/httpsec. Originally the SDK lived
// in its own Go module and could not import from api/, so the 9+
// outbound-client sites across sdk-go/pkg/* each carried a bare
// &http.Client{Timeout: …} with no dialer-level blocklist. That was
// fine when the SDK only talked to the pinned OpenCTEM API over a
// trusted operator-provided URL, but third-party users of the SDK
// (custom scanners, integration shims) can point it at arbitrary
// hostnames. Any of those callers inherit the same SSRF gap as the
// API did before the audit.
//
// This package mirrors api/pkg/httpsec verbatim — when you change one,
// change the other. A follow-up task tracks hoisting the single
// canonical copy into a top-level shared Go module; until then, the
// drift is caught by scripts/security-lint.sh which grep-checks both
// copies for the same CIDR blocklist.
//
// Any outbound HTTP call in sdk-go/pkg/* that reaches a hostname
// chosen at runtime (API URL from config, KEV/EPSS feed, bootstrap
// token endpoint, command poller, lease endpoint) MUST use
// SafeHTTPClient + ValidateURL, not &http.Client{} directly.
package httpsec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// allowLoopbackEnvVar is the env var name a test harness can set to
// tell SafeHTTPClient and ValidateURL to permit 127.0.0.0/8 and
// [::1]/128 addresses. Intended for unit tests that drive the SDK
// against httptest.NewServer (which binds to a loopback address) —
// production deployments must NEVER set this.
//
// We deliberately use an opt-in env var rather than `testing.Testing()`
// so the SDK binary does not transitively import the Go testing
// package. Callers that need this in-process (e.g. integration tests
// embedding the SDK) can also toggle the runtime variable below.
const allowLoopbackEnvVar = "OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK"

// AllowLoopback, when set to true, skips the loopback (127.0.0.0/8,
// ::1/128) branch of the blocklist. All other CIDRs (RFC1918,
// link-local IMDS, CGNAT, …) remain enforced. Prefer the env var for
// external test harnesses; this variable is for in-process overrides.
var AllowLoopback = os.Getenv(allowLoopbackEnvVar) == "1"

// hardBlockedIPRanges lists CIDRs that MUST NEVER be reachable.
// Mirror of api/pkg/httpsec. See that file for the full rationale.
// Attacks these ranges are not "aggressive configuration" but
// immediate security incidents (cloud IMDS leak, loopback self-
// scan, etc.) — no env var should be able to open them.
var hardBlockedIPRanges = []string{
	"127.0.0.0/8",        // Loopback
	"169.254.0.0/16",     // Link-local (incl. AWS/GCP/Azure IMDS)
	"100.64.0.0/10",      // Carrier-grade NAT
	"0.0.0.0/8",          // "This" network
	"224.0.0.0/4",        // Multicast
	"240.0.0.0/4",        // Reserved
	"255.255.255.255/32", // Broadcast
	"::1/128",            // IPv6 loopback
	"fe80::/10",          // IPv6 link-local
}

// privateIPRanges — blocked by default, opened by setting
// OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE=1 (SDK) or
// OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1 (inherited). An on-prem
// deployment scanning its own 10.x / 192.168.x services needs this
// on.
var privateIPRanges = []string{
	"10.0.0.0/8",     // RFC1918 class A
	"172.16.0.0/12",  // RFC1918 class B
	"192.168.0.0/16", // RFC1918 class C
	"fc00::/7",       // IPv6 ULA
}

// allowPrivate is the runtime toggle. The SDK check is an
// independent switch from the API side so an SDK caller inside a
// cloud VM doesn't inherit the API's opt-in. Accept either env var
// name so ops can set them symmetrically across services.
var allowPrivate = os.Getenv("OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE") == "1" ||
	os.Getenv("OPENCTEM_HTTPSEC_ALLOW_PRIVATE") == "1"

// AllowPrivate reports the current runtime posture for
// startup-logging; do not consult it per-call (that happens inside
// IsIPBlocked).
func AllowPrivate() bool { return allowPrivate }

// dangerousHosts is a string-level rejection for common aliases that
// hit metadata/local services before DNS resolves.
var dangerousHosts = []string{
	"localhost",
	"metadata",
	"metadata.google.internal",
	"metadata.google",
	"169.254.169.254",
}

var hardBlockedCIDRs []*net.IPNet
var privateCIDRs []*net.IPNet

func init() {
	for _, cidr := range hardBlockedIPRanges {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			hardBlockedCIDRs = append(hardBlockedCIDRs, ipNet)
		}
	}
	for _, cidr := range privateIPRanges {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			privateCIDRs = append(privateCIDRs, ipNet)
		}
	}
}

// IsIPBlocked reports whether the given IP falls in a blocked CIDR.
// The hard-blocked set always rejects. The RFC1918 / ULA set is
// conditional on allowPrivate (set via env).
//
// AllowLoopback (test-only) still overrides loopback for httptest
// servers; it does NOT touch IMDS or RFC1918 — those remain on
// their own toggle chains.
func IsIPBlocked(ip net.IP) bool {
	if AllowLoopback && (ip.IsLoopback() || ip.Equal(net.IPv6loopback)) {
		return false
	}
	for _, cidr := range hardBlockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	if !allowPrivate {
		for _, cidr := range privateCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ValidationResult carries the parsed URL + the DNS-pinned IP set so
// callers that want to prevent DNS rebinding can dial one of the
// resolved IPs rather than re-resolve at dial time.
type ValidationResult struct {
	URL         *url.URL
	ResolvedIPs []net.IP
}

// ValidateURL parses rawURL, confirms scheme is http/https, blocks
// common dangerous hostnames, resolves DNS, and rejects if any
// A/AAAA hits a blocked CIDR. On any failure returns an error —
// callers MUST NOT proceed to dial.
//
// Fail-closed on DNS lookup failure: if we cannot resolve, we cannot
// verify the target is safe, so the request is rejected.
func ValidateURL(rawURL string) (*ValidationResult, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s (only http/https allowed)", parsed.Scheme)
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return nil, fmt.Errorf("URL has no host")
	}
	for _, blocked := range dangerousHosts {
		if hostname == blocked {
			// In loopback-allowed mode we still skip "metadata*" aliases
			// because those hit cloud IMDS regardless of loopback
			// semantics — only relax the "localhost" dictionary lookup.
			if AllowLoopback && hostname == "localhost" {
				break
			}
			return nil, fmt.Errorf("blocked hostname: %s", hostname)
		}
	}

	ips, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", parsed.Hostname(), err)
	}
	validIPs := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if IsIPBlocked(ip) {
			return nil, fmt.Errorf("blocked IP address: %s resolves to %s", parsed.Hostname(), ip.String())
		}
		validIPs = append(validIPs, ip)
	}
	if len(validIPs) == 0 {
		return nil, fmt.Errorf("no valid IPs for %s", parsed.Hostname())
	}
	return &ValidationResult{URL: parsed, ResolvedIPs: validIPs}, nil
}

// SafeHTTPClient returns an *http.Client whose dialer rejects any
// connection attempt to a blocked CIDR at the transport layer. This
// is the belt to ValidateURL's braces: even if a caller forgets to
// validate up front, the dial fails closed.
//
// Callers should still ValidateURL themselves because the dialer-only
// check happens AFTER DNS resolution, so a request to an attacker-
// supplied URL will have burned a DNS lookup (possibly against an
// attacker-controlled resolver). ValidateURL rejects before the
// lookup leaves the host process.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	baseDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	safeDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if IsIPBlocked(ip.IP) {
				return nil, fmt.Errorf("ssrf guard: blocked IP %s for host %s", ip.IP, host)
			}
		}
		return baseDialer.DialContext(ctx, network, addr)
	}
	tr := &http.Transport{
		DialContext:           safeDialer,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}
