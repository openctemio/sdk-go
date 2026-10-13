package netctx

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Settings the host owner declares (environment variables).
const (
	// EnvSite is the site label of this host ("hn-dc1"): at most 64 of
	// [A-Za-z0-9._-].
	EnvSite = "SENSOR_NETWORK_SITE"
	// EnvReach lists the CIDRs this host routes to beyond its own links
	// (VPN, peering), comma-separated.
	EnvReach = "SENSOR_NETWORK_REACH"
	// EnvDNSSuffixes lists the DNS suffixes this host resolves with its
	// internal view ("corp.example"), comma-separated.
	EnvDNSSuffixes = "SENSOR_NETWORK_DNS_SUFFIXES"
	// EnvInternet overrides the detected internet mode: auto (default),
	// direct, proxy or none.
	EnvInternet = "SENSOR_INTERNET"
	// EnvReport is how much the report says: summary (default), full or
	// off.
	EnvReport = "SENSOR_NETWORK_REPORT"
	// EnvDNSResolvers is the resolvers a sensor's tools use instead of the
	// system's ("10.0.0.2,10.0.0.3:53"); read for the report and the DNS
	// view check, declared by the sensor that reads it.
	EnvDNSResolvers = "SENSOR_DNS_RESOLVERS"
)

// Bounds of a report and of a declaration.
const (
	MaxOnLink        = 32
	MaxReach         = 64
	MaxDNSSuffixes   = 32
	MaxResolvers     = 8
	MaxSearchDomains = 8
	MaxSiteLen       = 64
	maxNameLen       = 253
)

// Shortest prefixes a declaration may name (a wider one says nothing a
// default route does not).
const (
	minReachBitsV4 = 8
	minReachBitsV6 = 32
)

// Internet is how this host reaches the internet.
type Internet string

// Internet modes. Auto is a declaration only (detect it); Unknown is a
// detection result only.
const (
	InternetAuto    Internet = "auto"
	InternetDirect  Internet = "direct"
	InternetProxy   Internet = "proxy"
	InternetNone    Internet = "none"
	InternetUnknown Internet = "unknown"
)

// Mode is how much a report says.
type Mode string

// Report modes.
const (
	// ModeSummary lists private prefixes and counts public ones (default).
	ModeSummary Mode = "summary"
	// ModeFull lists public on-link prefixes too.
	ModeFull Mode = "full"
	// ModeOff sends only the fingerprint and the internet mode.
	ModeOff Mode = "off"
)

// Declared is what the host owner states about this host's network.
type Declared struct {
	Site        string
	Reach       []netip.Prefix
	DNSSuffixes []string
	Internet    Internet
	Mode        Mode
}

// ErrInvalidDeclaration is wrapped by every ParseDeclared error.
var ErrInvalidDeclaration = errors.New("invalid network declaration")

// ParseDeclared reads the declaration from the environment (lookup is
// os.LookupEnv in a sensor). A value it cannot use is an error naming the
// setting, never a silent default: the host owner asked for something.
func ParseDeclared(lookup func(string) (string, bool)) (Declared, error) {
	get := func(k string) string {
		v, _ := lookup(k)
		return strings.TrimSpace(v)
	}
	d := Declared{Internet: InternetAuto, Mode: ModeSummary}
	if s := get(EnvSite); s != "" {
		if !validSite(s) {
			return Declared{}, fmt.Errorf("%w: %s must be 1 to %d of A-Z a-z 0-9 . _ -", ErrInvalidDeclaration, EnvSite, MaxSiteLen)
		}
		d.Site = s
	}
	reach, err := parseReach(get(EnvReach))
	if err != nil {
		return Declared{}, fmt.Errorf("%w: %s: %w", ErrInvalidDeclaration, EnvReach, err)
	}
	d.Reach = reach
	suffixes, err := parseSuffixes(get(EnvDNSSuffixes))
	if err != nil {
		return Declared{}, fmt.Errorf("%w: %s: %w", ErrInvalidDeclaration, EnvDNSSuffixes, err)
	}
	d.DNSSuffixes = suffixes
	switch v := Internet(strings.ToLower(get(EnvInternet))); v {
	case "", InternetAuto:
	case InternetDirect, InternetProxy, InternetNone:
		d.Internet = v
	default:
		return Declared{}, fmt.Errorf("%w: %s must be auto, direct, proxy or none", ErrInvalidDeclaration, EnvInternet)
	}
	switch v := Mode(strings.ToLower(get(EnvReport))); v {
	case "", ModeSummary:
	case ModeFull, ModeOff:
		d.Mode = v
	default:
		return Declared{}, fmt.Errorf("%w: %s must be summary, full or off", ErrInvalidDeclaration, EnvReport)
	}
	return d, nil
}

func validSite(s string) bool {
	if s == "" || len(s) > MaxSiteLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// parseReach parses, canonicalizes (masked), de-duplicates and sorts a CIDR
// list. A bare address is a host prefix.
func parseReach(s string) ([]netip.Prefix, error) {
	items := splitList(s)
	if len(items) > MaxReach {
		return nil, fmt.Errorf("at most %d entries", MaxReach)
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, it := range items {
		p, err := parsePrefix(it)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", len(out)+1, err)
		}
		a := p.Addr()
		switch {
		case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsMulticast(), a.IsUnspecified():
			return nil, fmt.Errorf("entry %d: a loopback, link-local, multicast or unspecified prefix is not a route", len(out)+1)
		case a.Is4() && p.Bits() < minReachBitsV4, a.Is6() && p.Bits() < minReachBitsV6:
			return nil, fmt.Errorf("entry %d: wider than /%d (IPv4) or /%d (IPv6)", len(out)+1, minReachBitsV4, minReachBitsV6)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sortPrefixes(out)
	return out, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, errors.New("not a CIDR")
		}
		return netip.PrefixFrom(p.Addr().Unmap(), unmapBits(p)).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, errors.New("not a CIDR")
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// unmapBits is p's length once an IPv4-mapped address is read as IPv4.
func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() {
		return max(p.Bits()-96, 0)
	}
	return p.Bits()
}

func parseSuffixes(s string) ([]string, error) {
	items := splitList(s)
	if len(items) > MaxDNSSuffixes {
		return nil, fmt.Errorf("at most %d entries", MaxDNSSuffixes)
	}
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		n := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(it), "."), ".")
		if !validDomain(n) {
			return nil, fmt.Errorf("entry %d: not a DNS name", len(out)+1)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// validDomain reports whether s is a DNS name of LDH labels.
func validDomain(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}
