// Package politeness is the one definition of the per-host politeness keys
// of scan work: which hosts a job sends traffic to, and when two jobs touch
// the same host. The platform computes the keys of the work it hands out,
// holds them while the work runs and sends them with the work; a sensor
// admits the work under those same keys. Both sides use this package, so a
// sensor never hands back work the platform has just offered it because the
// two disagree about a host (api docs/rfcs/RFC-090-work-pool.md).
//
// The keys of one target:
//
//   - a name: the lower-case name without a trailing dot ("www.example.com"),
//     also for the host of a URL ("https://www.example.com:8443/x") or of a
//     service ("www.example.com:443:tcp");
//   - an address: its canonical form ("203.0.113.5", "2001:db8::1"; an
//     IPv4-mapped IPv6 address is the IPv4 address) and the marker of its
//     bucket ("in:203.0.113.0/24");
//   - a range: the range key of every bucket it covers ("net:203.0.113.0/24");
//   - a repository clone URL ("https://host/owner/repo.git") or one in scp
//     form ("git@host:owner/repo"): "host/owner";
//   - a local path: the path itself.
//
// Buckets are one IPv4 /24 or one IPv6 /120. Two jobs conflict when one's
// keys share an element with the other's Conflicts: the same name or
// address, or an address and a range scan of the same bucket, either way
// round. Two addresses of one bucket do not conflict.
//
// Network context (api RFC-089): when the work names a network, the keys of
// private, shared (100.64.0.0/10), loopback and link-local addresses and the
// keys of names end in "#<network>", so 10.0.0.5 at one site and 10.0.0.5 at
// another are two hosts. Keys of public addresses never carry a network:
// a public host is one host whichever network the work came from.
//
// The package has no dependencies outside the standard library and is its
// own Go module (github.com/openctemio/sdk-go/pkg/politeness, tagged
// pkg/politeness/vX.Y.Z), so the platform imports it without the SDK.
//
// Stability: Experimental (docs/STABILITY.md).
package politeness

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Prefixes of the bucket keys.
const (
	// AddrInBucket marks work that sends traffic to one or more addresses
	// of the bucket ("in:203.0.113.0/24").
	AddrInBucket = "in:"
	// RangeBucket marks work that scans (part of) the bucket as a range
	// ("net:203.0.113.0/24").
	RangeBucket = "net:"
)

// Bucket sizes: an IPv4 /24, an IPv6 /120.
const (
	BucketBitsV4 = 24
	BucketBitsV6 = 120
)

// MaxKeys bounds the keys of one job. A range wider than MaxKeys buckets is
// keyed by its widest covering prefixes instead.
const MaxKeys = 500

// NetworkSep separates a key from the network it is scoped to.
const NetworkSep = "#"

// maxNetworkLen bounds a network id (a UUID is 36 characters).
const maxNetworkLen = 64

// AddrBucket is the bucket prefix an address falls in.
func AddrBucket(a netip.Addr) netip.Prefix {
	a = a.Unmap().WithZone("")
	p, _ := a.Prefix(bucketBits(a))
	return p
}

func bucketBits(a netip.Addr) int {
	if a.Is4() {
		return BucketBitsV4
	}
	return BucketBitsV6
}

// Keys is the politeness keys of a job's targets in network ("" for the
// internet or a tenant's only network): sorted, without duplicates, at most
// MaxKeys; nil when no target names a host.
func Keys(targets []string, network string) []string {
	if len(targets) == 0 {
		return nil
	}
	keys := make([]string, 0, 2*len(targets))
	for _, t := range targets {
		keys = append(keys, TargetKeys(t, network)...)
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	if len(keys) > MaxKeys {
		keys = keys[:MaxKeys]
	}
	if len(keys) == 0 {
		return nil
	}
	return keys
}

// TargetKeys is the politeness keys of one target in network (see the
// package comment); nil when the target names no host.
func TargetKeys(target, network string) []string {
	ns := networkSuffix(network)
	if r, ok := parseRange(target); ok {
		if r.lo == r.hi {
			return addrKeys(r.lo, ns)
		}
		return rangeKeys(r, ns)
	}
	h := HostOf(target)
	if h == "" {
		return nil
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return addrKeys(a, ns)
	}
	if isLocalPath(h) {
		return []string{h}
	}
	return []string{h + ns}
}

// HostOf is the host a target names: the lower-case host of a URL or a
// service, a host:port without its port, an address in canonical form, a
// name without its trailing dot, "host/owner" of a repository clone URL
// (ending in ".git") or of one in scp form,
// a local path as given, a CIDR as its masked prefix. Empty when nothing
// can be read.
func HostOf(target string) string {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return ""
	}
	if isLocalPath(raw) {
		return raw
	}
	t := strings.ToLower(raw)
	if rest, ok := strings.CutPrefix(t, "git@"); ok && !strings.Contains(t, "://") {
		if host, path, ok := strings.Cut(rest, ":"); ok && host != "" && !strings.ContainsAny(host, "/@") {
			host = strings.TrimSuffix(host, ".")
			if owner := firstSegment(path); owner != "" {
				return host + "/" + owner
			}
			return host
		}
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return ""
		}
		host := canonicalHost(u.Hostname())
		if host != "" && strings.HasSuffix(u.Path, ".git") {
			if owner := firstSegment(u.Path); owner != "" && strings.Count(strings.Trim(u.Path, "/"), "/") >= 1 {
				return host + "/" + owner // a clone URL: one key per owner
			}
		}
		return host
	}
	if h, ok := serviceHost(t); ok {
		return canonicalHost(h)
	}
	if strings.Contains(t, "/") {
		if p, err := netip.ParsePrefix(t); err == nil {
			if r, ok := prefixRange(p); ok && r.lo == r.hi {
				return r.lo.String()
			}
			return p.Masked().String()
		}
		t, _, _ = strings.Cut(t, "/")
	}
	if host, _, err := net.SplitHostPort(t); err == nil {
		t = host
	}
	return canonicalHost(strings.Trim(t, "[]"))
}

// canonicalHost drops a trailing dot and writes an address canonically.
func canonicalHost(h string) string {
	h = strings.TrimSuffix(h, ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return h
}

// isLocalPath reports a filesystem path: absolute, relative ("./", "../")
// or a drive path ("C:\", "C:/").
func isLocalPath(t string) bool {
	switch {
	case strings.HasPrefix(t, "/"), strings.HasPrefix(t, "./"), strings.HasPrefix(t, "../"), t == ".":
		return true
	case len(t) > 2 && t[1] == ':' && (t[2] == '\\' || t[2] == '/'):
		c := t[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return false
}

func firstSegment(path string) string {
	seg, _, _ := strings.Cut(strings.Trim(path, "/"), "/")
	return strings.TrimSuffix(seg, ".git")
}

// serviceRe reads a service name: "host:port:proto", "host:port/proto",
// "host:port", their bracketed IPv6 forms and the stored "v6:port:proto".
var serviceRe = regexp.MustCompile(`^(.+):(\d{1,5})(?:[:/](tcp|udp|sctp))?$`)

// serviceHost is the host of a service name (t is lower-case, not a URL).
func serviceHost(t string) (string, bool) {
	m := serviceRe.FindStringSubmatch(t)
	if m == nil {
		return "", false
	}
	host, proto := m[1], m[3]
	if port, err := strconv.Atoi(m[2]); err != nil || port < 1 || port > 65535 {
		return "", false
	}
	switch {
	case strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]"):
		host = host[1 : len(host)-1]
		if _, err := netip.ParseAddr(host); err != nil {
			return "", false
		}
	case strings.Contains(host, ":"):
		// An unbracketed IPv6 host is read only with an explicit protocol:
		// "2001:db8::1:443" is itself an address.
		if proto == "" {
			return "", false
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return "", false
		}
	case strings.ContainsAny(host, "/?#[]@ "):
		return "", false
	}
	host = strings.TrimSuffix(host, ".")
	return host, host != ""
}

// addrKeys is an address and the marker of its bucket.
func addrKeys(a netip.Addr, ns string) []string {
	a = a.Unmap().WithZone("")
	s := scoped(a, ns)
	return []string{a.String() + s, AddrInBucket + AddrBucket(a).String() + s}
}

// rangeKeys is the range key of every bucket a range covers; for a range of
// more than MaxKeys buckets, the keys of its widest covering prefixes.
func rangeKeys(r addrRange, ns string) []string {
	ps, err := r.prefixes(bucketBits(r.lo), MaxKeys)
	if err != nil {
		ps, _ = r.prefixes(0, MaxKeys)
	}
	out := make([]string, 0, len(ps))
	seen := make(map[string]bool, len(ps))
	for _, p := range ps {
		b, _ := p.Addr().Prefix(min(p.Bits(), bucketBits(p.Addr())))
		k := RangeBucket + b.String() + scoped(b.Addr(), ns)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// cgnat is the shared address space (RFC 6598), used inside networks.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// scoped is the network suffix for an address key: only a non-public
// address belongs to a network.
func scoped(a netip.Addr, ns string) string {
	if ns == "" {
		return ""
	}
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || cgnat.Contains(a) {
		return ns
	}
	return ""
}

// networkSuffix is "#<network>" for a well-formed network id (letters,
// digits, '-', at most 64), else "": an id that cannot be read leaves the
// keys global, which only holds more work back, never less.
func networkSuffix(network string) string {
	n := strings.ToLower(strings.TrimSpace(network))
	if n == "" || len(n) > maxNetworkLen {
		return ""
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return ""
		}
	}
	return NetworkSep + n
}

// Conflicts is the keys that conflict with a job holding keys: a plain key
// (a name or an address) conflicts with itself; an address in a bucket
// conflicts with a range scan of that bucket; a range scan of a bucket
// conflicts with both. Two jobs conflict when one's keys share an element
// with the other's Conflicts (the relation is symmetric). Sorted, without
// duplicates. A key's network suffix is kept.
func Conflicts(keys []string) []string {
	out := make([]string, 0, len(keys)+2)
	for _, k := range keys {
		switch {
		case strings.HasPrefix(k, AddrInBucket):
			out = append(out, RangeBucket+strings.TrimPrefix(k, AddrInBucket))
		case strings.HasPrefix(k, RangeBucket):
			b := strings.TrimPrefix(k, RangeBucket)
			out = append(out, k, AddrInBucket+b)
		default:
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Lock is the lock name of a key: a bucket marker and a bucket range key
// share one lock, so taking an address job and a range job of one bucket
// happens one after the other.
func Lock(k string) string {
	switch {
	case strings.HasPrefix(k, AddrInBucket):
		return "b:" + strings.TrimPrefix(k, AddrInBucket)
	case strings.HasPrefix(k, RangeBucket):
		return "b:" + strings.TrimPrefix(k, RangeBucket)
	}
	return k
}
