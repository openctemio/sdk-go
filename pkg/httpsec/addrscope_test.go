package httpsec

import (
	"net"
	"testing"
)

// The deny list is ctis addrscope's, the one the platform checks job
// targets with: an IPv6 address that carries an internal IPv4 address
// (NAT64, 6to4, Teredo) is internal, even where private ranges are
// allowed; one that carries a public address is not.
func TestDenyListIsAddrscope(t *testing.T) {
	for _, tc := range []struct {
		ip           string
		allowPrivate bool
		blocked      bool
	}{
		{"64:ff9b::a00:1", false, true},                        // NAT64 of 10.0.0.1
		{"64:ff9b::a00:1", true, true},                         // never a private target
		{"2002:a00:1::1", true, true},                          // 6to4 of 10.0.0.1
		{"2001:0:4136:e378:8000:63bf:f5ff:fffe", true, true},   // Teredo client 10.0.0.1
		{"64:ff9b::a9fe:a9fe", true, true},                     // NAT64 of 169.254.169.254
		{"fec0::1", true, true},                                // deprecated site-local
		{"fd00:ec2::254", true, true},                          // metadata inside ULA
		{"fd20:ce::254", true, true},                           // metadata inside ULA
		{"fd12:3456::1", true, false},                          // ULA, private allowed
		{"fd12:3456::1", false, true},                          // ULA, private refused
		{"10.1.2.3", true, false},                              // private allowed
		{"64:ff9b::808:808", false, false},                     // NAT64 of a public address
		{"2002:808:808::1", false, false},                      // 6to4 of a public address
		{"2001:0:4136:e378:8000:63bf:f7f7:f7f7", false, false}, // Teredo client 8.8.8.8
		{"203.0.113.10", false, false},                         // documentation, used as public
	} {
		if got := IsIPBlockedWith(net.ParseIP(tc.ip), tc.allowPrivate, false); got != tc.blocked {
			t.Errorf("%s (allow private %v): blocked %v, want %v", tc.ip, tc.allowPrivate, got, tc.blocked)
		}
	}
}
