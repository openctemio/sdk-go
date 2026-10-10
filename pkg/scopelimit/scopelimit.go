// Package scopelimit is the port, protocol and path limits of a job's
// targets (api docs/rfcs/RFC-065-bug-bounty-programs.md §16.8): a target the
// organization's scope covers only through a port-limited entry
// ("api.example.com:8443/tcp") or a path-limited URL entry
// ("https://example.com/api/") may be scanned only on those ports and under
// that path.
//
// The platform's job signer puts the limits in the signed job statement
// (jobsig.Statement.Limits), from its own ledger, so neither the API nor
// anyone who can write the commands table can widen or drop them. The SDK
// enforces them outside the tool: the task's egress forwarder refuses a
// connection to a limited host on another port, and reads every HTTP
// request to a path-limited host (terminating TLS with a per-task
// authority) and refuses one whose path is outside the prefixes. Tool flags
// (a port list, a crawl scope) are set as well, but nothing relies on them.
//
// A sensor that enforces limits advertises Capability in its manifest; the
// platform sends a job with limits only to such a sensor. A sensor that
// does not know the statement field refuses the statement (unknown field),
// never runs the job unlimited.
//
// Stability: Beta (docs/STABILITY.md).
package scopelimit

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Capability is the sensor manifest capability of a sensor that enforces
// limits.
const Capability = "scope.limits@1"

// Protocols a limit may name.
const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

// Bounds of a limit list.
const (
	MaxLimits        = 1024
	maxPortRanges    = 32
	maxPathPrefixLen = 1024
	maxHostLen       = 253
)

// ErrOutside is the error of a connection or request outside the limits.
var ErrOutside = errors.New("outside the job's scope limits")

// Limit is one allowance on a limited host. A host that has limits may be
// reached only as one of them allows; a host without any is not limited by
// this package.
type Limit struct {
	// Host is a host name ("api.example.com") or an IP address, lower case,
	// as the job's targets name it.
	Host string `json:"host"`
	// Ports is the canonical port list ("443,8000-8100"); "" = every port.
	Ports string `json:"ports,omitempty"`
	// Protocol is "tcp", "udp" or "" (any).
	Protocol string `json:"protocol,omitempty"`
	// PathPrefix is the URL path the HTTP requests must stay under ("/api"):
	// the prefix itself and the paths under it, segment by segment, case
	// sensitive (RFC 3986 §6.2.2.1). "" = every path.
	PathPrefix string `json:"path_prefix,omitempty"`
}

type span struct{ lo, hi int }

// parsePorts reads a canonical port list: ascending, non-overlapping,
// non-adjacent ranges, each "n" or "lo-hi".
func parsePorts(spec string) ([]span, error) {
	parts := strings.Split(spec, ",")
	if len(parts) > maxPortRanges {
		return nil, fmt.Errorf("more than %d port ranges", maxPortRanges)
	}
	out := make([]span, 0, len(parts))
	for _, part := range parts {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 || strconv.Itoa(a) != lo {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b <= a || b > 65535 || strconv.Itoa(b) != hi {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		if n := len(out); n > 0 && a <= out[n-1].hi+1 {
			return nil, fmt.Errorf("port list %q is not canonical", spec)
		}
		out = append(out, span{a, b})
	}
	return out, nil
}

// Validate checks every limit's syntax, and that each names the host of
// one of the job's targets (as the statement lists them). A job whose
// limits are invalid is refused, never run unlimited.
func Validate(limits []Limit, targets []string) error {
	if len(limits) > MaxLimits {
		return fmt.Errorf("scope limits: %d limits, at most %d", len(limits), MaxLimits)
	}
	known := map[string]bool{}
	for _, t := range targets {
		if h := HostOf(t); h != "" {
			known[h] = true
		}
	}
	for i, l := range limits {
		if err := l.validate(); err != nil {
			return fmt.Errorf("scope limit %d: %w", i, err)
		}
		if !known[l.Host] {
			return fmt.Errorf("scope limit %d: host %q is not one of the job's targets", i, l.Host)
		}
	}
	return nil
}

func (l Limit) validate() error {
	if l.Host == "" || len(l.Host) > maxHostLen || l.Host != NormHost(l.Host) ||
		strings.ContainsAny(l.Host, "/?#@*[] :") && !isAddr(l.Host) {
		return fmt.Errorf("invalid host %q", l.Host)
	}
	if strings.ContainsFunc(l.Host, isControl) {
		return errors.New("invalid host")
	}
	if l.Ports == "" && l.Protocol == "" && l.PathPrefix == "" {
		return errors.New("a limit must name ports, a protocol or a path prefix")
	}
	if l.Ports != "" {
		if _, err := parsePorts(l.Ports); err != nil {
			return err
		}
	}
	if l.Protocol != "" && l.Protocol != ProtocolTCP && l.Protocol != ProtocolUDP {
		return fmt.Errorf("invalid protocol %q", l.Protocol)
	}
	if l.PathPrefix != "" {
		if l.Protocol == ProtocolUDP {
			return errors.New("a path prefix needs tcp")
		}
		if _, err := cleanPrefix(l.PathPrefix); err != nil {
			return err
		}
	}
	return nil
}

func isAddr(h string) bool { _, err := netip.ParseAddr(h); return err == nil }

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// NormHost is a host as limits name it: lower case, no brackets, no
// trailing dot, an IPv4-mapped address unmapped.
func NormHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]")), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}

// HostOf is the host a target names, as limits name it: of a URL, a
// host:port, a host name or an address; "" for a network or a path.
func HostOf(target string) string {
	v := strings.TrimSpace(target)
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		return NormHost(u.Hostname())
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return NormHost(h)
	}
	if v == "" || strings.ContainsAny(v, "/ ") {
		return ""
	}
	return NormHost(v)
}

// cleanPrefix is a limit's path prefix in the form CleanPath gives a
// request path, without a trailing slash ("" for the root).
func cleanPrefix(p string) (string, error) {
	if !strings.HasPrefix(p, "/") || len(p) > maxPathPrefixLen || strings.ContainsAny(p, "?#") ||
		strings.ContainsFunc(p, isControl) {
		return "", fmt.Errorf("invalid path prefix %q", p)
	}
	c, err := CleanPath(p)
	if err != nil {
		return "", fmt.Errorf("invalid path prefix %q: %w", p, err)
	}
	if c != p && c != strings.TrimSuffix(p, "/") && c+"/" != p {
		return "", fmt.Errorf("path prefix %q is not normalized", p)
	}
	return strings.TrimSuffix(c, "/"), nil
}

// CleanPath is the path a server sees for the escaped request path raw:
// percent-decoded, dot segments resolved, never empty. A path an origin
// server could read in more than one way is refused: an encoded "/", "\"
// or NUL, an invalid escape, a backslash, or a dot segment hidden behind
// parameters ("/..;/", which some servers resolve as "..").
func CleanPath(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	if !strings.HasPrefix(raw, "/") {
		return "", errors.New("the path is not absolute")
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") ||
		strings.Contains(raw, `\`) {
		return "", errors.New("encoded separator or backslash in the path")
	}
	dec, err := url.PathUnescape(raw)
	if err != nil {
		return "", errors.New("invalid percent-encoding in the path")
	}
	if strings.ContainsFunc(dec, isControl) {
		return "", errors.New("control character in the path")
	}
	for _, seg := range strings.Split(dec, "/") {
		base, _, hasParam := strings.Cut(seg, ";")
		if hasParam && (base == "." || base == "..") {
			return "", errors.New("dot segment with parameters in the path")
		}
	}
	trailing := strings.HasSuffix(dec, "/")
	c := path.Clean(dec)
	if trailing && c != "/" {
		c += "/"
	}
	return c, nil
}

// Set is a job's limits indexed by host. The zero value limits nothing.
type Set struct {
	byHost map[string][]Limit
}

// NewSet indexes limits (already validated) by host.
func NewSet(limits []Limit) Set {
	s := Set{byHost: map[string][]Limit{}}
	for _, l := range limits {
		h := NormHost(l.Host)
		s.byHost[h] = append(s.byHost[h], l)
	}
	return s
}

// Empty reports whether the set limits no host.
func (s Set) Empty() bool { return len(s.byHost) == 0 }

// Hosts are the limited hosts, sorted.
func (s Set) Hosts() []string {
	out := make([]string, 0, len(s.byHost))
	for h := range s.byHost {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// Limited reports whether host has limits.
func (s Set) Limited(host string) bool { _, ok := s.byHost[NormHost(host)]; return ok }

// Limits are host's limits (nil: not limited).
func (s Set) Limits(host string) []Limit { return s.byHost[NormHost(host)] }

// AllowsPort reports whether a TCP connection to host:port is allowed: the
// host is not limited, or one of its limits allows the port over tcp.
func (s Set) AllowsPort(host string, port int) bool {
	ls, ok := s.byHost[NormHost(host)]
	if !ok {
		return true
	}
	return slices.ContainsFunc(ls, func(l Limit) bool { return l.allowsTCP(port) })
}

func (l Limit) allowsTCP(port int) bool {
	if l.Protocol == ProtocolUDP {
		return false
	}
	if l.Ports == "" {
		return true
	}
	spans, err := parsePorts(l.Ports)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(spans, func(s span) bool { return port >= s.lo && port <= s.hi })
}

// PathPrefixes are the path prefixes HTTP requests to host:port must stay
// under; guarded is false when the host is not limited, or a limit allows
// the port with every path. A guarded destination with no prefix allows no
// request.
func (s Set) PathPrefixes(host string, port int) (prefixes []string, guarded bool) {
	ls, ok := s.byHost[NormHost(host)]
	if !ok {
		return nil, false
	}
	for _, l := range ls {
		if !l.allowsTCP(port) {
			continue
		}
		if l.PathPrefix == "" {
			return nil, false
		}
		prefixes = append(prefixes, l.PathPrefix)
	}
	return prefixes, true
}

// PathAllowed reports whether the escaped request path raw is under one of
// prefixes, after CleanPath, segment by segment and case sensitive.
func PathAllowed(raw string, prefixes []string) error {
	p, err := CleanPath(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOutside, err)
	}
	for _, pre := range prefixes {
		c, err := cleanPrefix(pre)
		if err != nil {
			continue
		}
		if c == "" || p == c || strings.HasPrefix(p, c+"/") {
			return nil
		}
	}
	return fmt.Errorf("%w: path %s is outside the allowed prefixes", ErrOutside, clip(p, 128))
}

// PortList is the union of host's TCP ports as a port list for a tool flag
// ("443,8443"); "" when a limit allows every port or the host is not
// limited.
func (s Set) PortList(host string) string {
	ls, ok := s.byHost[NormHost(host)]
	if !ok {
		return ""
	}
	var parts []string
	for _, l := range ls {
		if l.Protocol == ProtocolUDP {
			continue
		}
		if l.Ports == "" {
			return ""
		}
		parts = append(parts, l.Ports)
	}
	return strings.Join(parts, ",")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
