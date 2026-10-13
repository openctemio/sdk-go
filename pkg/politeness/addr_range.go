package politeness

import (
	"errors"
	"net/netip"
	"strings"
)

// errTooManyPrefixes: the range does not fit the requested number of
// prefixes.
var errTooManyPrefixes = errors.New("politeness: range splits into too many prefixes")

// addrRange is an inclusive address range of one family.
type addrRange struct {
	lo, hi netip.Addr
}

func (r addrRange) valid() bool {
	return r.lo.IsValid() && r.hi.IsValid() && r.lo.Is4() == r.hi.Is4() && !r.hi.Less(r.lo)
}

// parseRange reads an address, a CIDR (host bits masked off) or an "a-b"
// range. It never resolves names. An IPv4-mapped IPv6 address is read as
// IPv4 and a zone is dropped.
func parseRange(s string) (addrRange, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return addrRange{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return addrRange{}, false
		}
		return prefixRange(p)
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, errA := netip.ParseAddr(strings.TrimSpace(lo))
		b, errB := netip.ParseAddr(strings.TrimSpace(hi))
		if errA != nil || errB != nil {
			return addrRange{}, false
		}
		r := addrRange{lo: a.Unmap().WithZone(""), hi: b.Unmap().WithZone("")}
		return r, r.valid()
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return addrRange{}, false
	}
	a = a.Unmap().WithZone("")
	return addrRange{lo: a, hi: a}, true
}

// prefixRange is the range a prefix covers. An IPv4-mapped IPv6 prefix of
// /96 or longer is read as the IPv4 prefix it maps.
func prefixRange(p netip.Prefix) (addrRange, bool) {
	if !p.IsValid() {
		return addrRange{}, false
	}
	p = p.Masked()
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	p = netip.PrefixFrom(p.Addr().WithZone(""), p.Bits())
	return addrRange{lo: p.Addr(), hi: lastAddr(p)}, true
}

// lastAddr is the highest address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= byte(0x80) >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// prefixes writes r as the fewest prefixes that cover it exactly, none
// wider than /minBits; more than limit is errTooManyPrefixes.
func (r addrRange) prefixes(minBits, limit int) ([]netip.Prefix, error) {
	var out []netip.Prefix
	lo := r.lo
	for {
		p, ok := largestPrefixAt(lo, r.hi, minBits)
		if !ok {
			return nil, errors.New("politeness: no prefix fits a valid range")
		}
		if limit > 0 && len(out) >= limit {
			return nil, errTooManyPrefixes
		}
		out = append(out, p)
		last := lastAddr(p)
		if last == r.hi {
			return out, nil
		}
		lo = last.Next()
	}
}

// largestPrefixAt is the widest prefix that starts at lo, ends at or before
// hi and is no wider than /minBits.
func largestPrefixAt(lo, hi netip.Addr, minBits int) (netip.Prefix, bool) {
	for b := max(0, minBits); b <= lo.BitLen(); b++ {
		p := netip.PrefixFrom(lo, b)
		if p.Masked().Addr() != lo {
			continue
		}
		if !hi.Less(lastAddr(p)) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
