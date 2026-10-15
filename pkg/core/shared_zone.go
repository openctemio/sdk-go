package core

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// Private targets on a shared sensor (api RFC-100 §8).
//
// A shared sensor runs jobs of many tenants from the operator's network.
// A job reaches a private address (RFC 1918, IPv6 ULA) only when three
// things allow it: the operator's private-range switch
// (SENSOR_ALLOW_PRIVATE_TARGETS=1, and targets.allow_private in a local
// policy), the job's zone ranges (Command.ZoneRanges: the instance scan
// zone the platform assigned to the job's tenant), and the address lying
// inside one of them. The platform can only narrow what the operator
// allows, never widen it. Loopback, link-local, metadata, CGNAT,
// multicast and reserved addresses are refused whatever the zone says.

type jobZoneKey struct{}

// WithJobZone returns a context that carries the zone ranges of the job
// the work under it belongs to. The CommandPoller sets it from
// Command.ZoneRanges around every command.
func WithJobZone(ctx context.Context, zone []netip.Prefix) context.Context {
	if len(zone) == 0 {
		return ctx
	}
	return context.WithValue(ctx, jobZoneKey{}, zone)
}

// JobZoneFromContext returns the zone ranges set by WithJobZone (nil: the
// job has no zone, so no private address).
func JobZoneFromContext(ctx context.Context) []netip.Prefix {
	if ctx == nil {
		return nil
	}
	z, _ := ctx.Value(jobZoneKey{}).([]netip.Prefix)
	return z
}

// ParseZoneRanges reads a job's zone ranges (CIDRs or single addresses).
// An entry that is not a range, or not wholly inside one private range
// (a public, loopback, link-local or metadata range), is dropped: it can
// never widen what a shared sensor reaches.
func ParseZoneRanges(ranges []string) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range ranges {
		if p, ok := parsePrefix(strings.TrimSpace(r)); ok && privatePrefix(p) {
			out = append(out, p)
		}
	}
	return out
}

// parsePrefix reads a CIDR or an address as a masked prefix, IPv4-mapped
// forms as IPv4.
func parsePrefix(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

// privatePrefix reports whether p lies wholly inside one private range.
func privatePrefix(p netip.Prefix) bool {
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// CheckSharedAddr checks one address a shared sensor's job would reach:
// an address outside every private and denied range passes; a private one
// passes only inside the job's zone (JobZoneFromContext); every other
// non-public address is refused. It does not replace the scan target
// policy or the local policy (the operator's switch): callers apply those
// first.
func CheckSharedAddr(ctx context.Context, a netip.Addr) error {
	a = a.Unmap()
	ip := net.IP(a.AsSlice())
	if !httpsec.IsIPBlockedWith(ip, false, false) {
		return nil
	}
	if httpsec.IsIPBlockedWith(ip, true, false) {
		return markTarget(RefusedTargetDenied, refuse("shared.zone", "%s is never reachable from a shared sensor", a))
	}
	for _, z := range JobZoneFromContext(ctx) {
		if z.Contains(a) {
			return nil
		}
	}
	return markTarget(RefusedTargetDenied, refuse("shared.zone", "%s is a private address outside the job's zone", a))
}

// CheckSharedPrefix checks a range target as CheckSharedAddr checks an
// address: a range that overlaps any private or denied range must lie
// wholly inside one zone range of the job.
func CheckSharedPrefix(ctx context.Context, p netip.Prefix) error {
	p, ok := parsePrefix(p.String())
	if !ok {
		return markTarget(RefusedTargetInvalid, refuse("shared.zone", "%s is not a range", p))
	}
	if !overlapsNonPublic(p) {
		return nil
	}
	for _, z := range JobZoneFromContext(ctx) {
		if z.Bits() <= p.Bits() && z.Contains(p.Addr()) {
			return nil
		}
	}
	return markTarget(RefusedTargetDenied, refuse("shared.zone", "%s overlaps addresses outside the public internet and the job's zone", p))
}

// overlapsNonPublic reports whether p shares an address with any range a
// shared sensor treats as non-public.
func overlapsNonPublic(p netip.Prefix) bool {
	if httpsec.IsIPBlockedWith(net.IP(p.Addr().AsSlice()), false, false) {
		return true
	}
	for _, n := range blockedRangesForOverlap {
		ones, _ := n.Mask.Size()
		a, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		if p.Overlaps(netip.PrefixFrom(a.Unmap(), ones)) {
			return true
		}
	}
	return false
}
