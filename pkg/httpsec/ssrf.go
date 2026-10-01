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
	"::/128",             // IPv6 unspecified
	"fe80::/10",          // IPv6 link-local
	"ff00::/8",           // IPv6 multicast
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
	return IsIPBlockedWith(ip, allowPrivate, AllowLoopback)
}

// IsIPBlockedWith is IsIPBlocked with the two toggles supplied by the
// caller instead of read from the process-wide env-derived defaults. It
// lets a component (e.g. the scan-target policy in pkg/core) carry its
// own allow-private posture without mutating package globals. The
// hard-blocked set (IMDS/link-local, CGNAT, multicast, unspecified,
// reserved) is enforced regardless of either toggle; allowLoopback only
// relaxes 127.0.0.0/8 and ::1.
func IsIPBlockedWith(ip net.IP, allowPrivateRanges, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	if allowLoopback && (ip.IsLoopback() || ip.Equal(net.IPv6loopback)) {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, cidr := range hardBlockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	if !allowPrivateRanges {
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
	tr := guardedTransport(IsIPBlocked)
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: SafeCheckRedirect,
	}
}

// guardedTransport returns a transport whose dialer resolves the host once,
// refuses it when blocked reports any resolved IP, and dials the checked IP.
func guardedTransport(blocked func(net.IP) bool) *http.Transport {
	baseDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	safeDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var dialIP string
		for _, ip := range ips {
			if blocked(ip.IP) {
				return nil, fmt.Errorf("ssrf guard: blocked IP %s for host %s", ip.IP, host)
			}
			if dialIP == "" {
				dialIP = ip.IP.String()
			}
		}
		if dialIP == "" {
			return nil, fmt.Errorf("ssrf guard: no resolved IP for host %s", host)
		}
		// Dial the IP we just validated rather than the hostname, so a DNS
		// rebinding resolver can't return a different (blocked) IP between the
		// check above and the connect. For https the transport still sets SNI
		// and verifies the cert against the original hostname, so this does not
		// weaken TLS.
		return baseDialer.DialContext(ctx, network, net.JoinHostPort(dialIP, port))
	}
	return &http.Transport{
		DialContext:           safeDialer,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
}

// maxRedirects mirrors net/http's default redirect budget.
const maxRedirects = 10

// SensitiveHeaders are request headers that carry credentials. They are
// stripped from a redirected request whenever the redirect changes origin
// (scheme, host or port). net/http only strips Authorization/Cookie, and
// only when the host leaves the original domain — it keeps them on an
// https->http same-host hop and never touches custom API-key headers.
var SensitiveHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"X-API-Key",
	"X-Api-Token",
	"X-Auth-Token",
	"X-Agent-Key",
	"X-Agent-API-Key",
	"X-Sensor-API-Key",
	"X-ApiKeys",
	"X-Bootstrap-Token",
}

// SafeCheckRedirect is the CheckRedirect policy installed on every
// SafeHTTPClient:
//
//   - at most 10 hops;
//   - a redirect may never downgrade https to http (the credential and
//     the response would cross the network in clear text);
//   - when a hop changes origin relative to the original request, every
//     header in SensitiveHeaders is removed before the request is sent.
//
// The dialer still applies the IP blocklist to the redirect target, so a
// redirect into IMDS/loopback fails at connect time.
func SafeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("httpsec: stopped after %d redirects", maxRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if strings.EqualFold(prev.URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("httpsec: refusing redirect that downgrades https to %s (%s)", req.URL.Scheme, req.URL.Redacted())
	}
	if !sameOrigin(via[0].URL, req.URL) {
		for _, h := range SensitiveHeaders {
			req.Header.Del(h)
		}
	}
	return nil
}

// RefuseRedirects is a CheckRedirect policy that never follows a redirect.
// Use it for clients that only ever talk to the OpenCTEM API: the API does
// not issue redirects, so a 3xx means a misconfigured base URL or a
// hostile intermediary, and following it would forward the bearer key.
func RefuseRedirects(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("httpsec: refusing to follow redirect to %s; configure the API base URL to the final address", req.URL.Redacted())
}

// NewAPIClient returns the client for requests that carry an OpenCTEM API
// key. Every such request goes to the operator-configured API base URL, so
// the destination is trusted configuration, not attacker input: on-prem and
// in-cluster platforms live on loopback, RFC1918, ULA or CGNAT (Tailscale)
// addresses, and SafeHTTPClient's blocklist would refuse all of them. The
// client still refuses every redirect (the bearer key never follows one),
// still refuses link-local destinations such as the cloud metadata service
// and multicast/reserved/unspecified addresses (so a poisoned DNS answer
// cannot point the key there), and honors HTTP(S)_PROXY / NO_PROXY.
func NewAPIClient(timeout time.Duration) *http.Client {
	tr := guardedTransport(isAPIDestinationBlocked)
	tr.Proxy = http.ProxyFromEnvironment
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: RefuseRedirects,
	}
}

// isAPIDestinationBlocked is the IP policy for the OpenCTEM API itself:
// nothing a platform can legitimately listen on is refused.
func isAPIDestinationBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] >= 240 { // 240.0.0.0/4 reserved, incl. broadcast
		return true
	}
	return false
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// CheckAPIBaseURL validates an operator-supplied OpenCTEM API base URL.
//
// It returns an error for anything that cannot be a sane API endpoint:
// a non-http(s) scheme, a missing host, or embedded userinfo (credentials
// in the URL end up in logs and error strings). For a plain-http URL whose
// host is not loopback it returns a non-empty warning instead of an error:
// the API key is sent as a bearer token, so clear-text transport outside a
// local dev setup exposes it, but rejecting it outright would break
// existing in-cluster deployments that terminate TLS elsewhere.
func CheckAPIBaseURL(raw string) (warning string, err error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("API base URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid API base URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("invalid API base URL %q: scheme must be http or https", u.Redacted())
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("invalid API base URL %q: missing host", u.Redacted())
	}
	if u.User != nil {
		return "", fmt.Errorf("invalid API base URL %q: credentials must not be embedded in the URL", u.Redacted())
	}
	if scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Sprintf("API base URL %s uses plain http: the API key is sent in clear text; use https outside local development", u.Redacted()), nil
	}
	return "", nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
