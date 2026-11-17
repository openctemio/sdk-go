package adapt

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/openctemio/contract/politeness"
	"golang.org/x/net/idna"
)

// HostKey is the host a target's budget is counted under: the politeness
// host of the target (contract politeness.HostOf, which drops the scheme,
// the port and the path) in canonical form (CanonicalHost). Empty when the
// target names no host.
//
// It is the one key function of the per-host budget: the task forwarder,
// the canary, the mapping of a budget to a tool's flags and the coverage
// gaps all count a host under it, so two spellings of one host never get
// two budgets.
func HostKey(target string) string {
	h := politeness.HostOf(target)
	if h == "" || strings.ContainsAny(h, `/\`) {
		// A local path, a range or a repository owner: not a network host
		// in another spelling.
		return h
	}
	return CanonicalHost(h)
}

// CanonicalHost is the canonical form of a host given without scheme, port
// or path: the form every spelling of one host reduces to.
//
//   - an address is written as netip writes it: an IPv6 address in its
//     shortest lower-case form, an IPv4-mapped IPv6 address as the IPv4
//     address, no brackets and no zone;
//   - an IPv4 address in a form the C library reads as one (hexadecimal,
//     octal or decimal parts, fewer than four parts: 0x7f000001,
//     2130706433, 0177.0.0.1, 127.1) is that address: a tool that resolves
//     through the C library connects there;
//   - a name is lower case without its trailing dot, in its ASCII form
//     (IDNA): bücher.example and xn--bcher-kva.example are one host. A name
//     IDNA cannot map is kept lower case as given.
//
// It never resolves a name: two names of one address are two keys here,
// and share that address's budget where the address is known (the task
// forwarder, HostRate.AcquireAddr).
func CanonicalHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return ""
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().WithZone("").String()
	}
	if a, ok := atonAddr(h); ok {
		return a.String()
	}
	if ascii, err := idna.Lookup.ToASCII(h); err == nil && ascii != "" {
		return strings.TrimSuffix(ascii, ".")
	}
	return h
}

// atonAddr reads an IPv4 address the way the C library's inet_aton does:
// one to four parts, each decimal, hexadecimal (0x) or octal (a leading 0),
// the last part filling the remaining bytes.
func atonAddr(h string) (netip.Addr, bool) {
	parts := strings.Split(h, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var v uint64
	for i, p := range parts {
		if p == "" {
			return netip.Addr{}, false
		}
		base := 10
		switch {
		case strings.HasPrefix(p, "0x"):
			base, p = 16, p[2:]
		case len(p) > 1 && p[0] == '0':
			base, p = 8, p[1:]
		}
		n, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		if i == len(parts)-1 {
			// The last part fills what is left of the four bytes.
			if n >= 1<<(8*uint(5-len(parts))) {
				return netip.Addr{}, false
			}
			v = v<<(8*uint(5-len(parts))) | n
			break
		}
		if n > 255 {
			return netip.Addr{}, false
		}
		v = v<<8 | n
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}
