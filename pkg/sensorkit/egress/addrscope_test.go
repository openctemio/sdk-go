package egress

import (
	"net/netip"
	"testing"
)

// SECURITY: a destination that must be public (a vendor host, an
// egress-proxy tool's) is refused when it is CGNAT or an IPv6 address
// carrying an internal IPv4 address, as the platform's deny list says.
func TestPublicOnlyIsAddrscope(t *testing.T) {
	for addr, refused := range map[string]bool{
		"100.64.0.1":     true,
		"64:ff9b::a00:1": true,
		"2002:a00:1::1":  true,
		"198.18.0.1":     true,
		"10.0.0.1":       true,
		"8.8.8.8":        false,
		"2606:4700::1":   false,
	} {
		if got := publicOnly(netip.MustParseAddr(addr)); got != refused {
			t.Errorf("%s: refused %v, want %v", addr, got, refused)
		}
	}
}
