package core

import (
	"context"
	"net"
	"testing"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// SECURITY: a scan target whose name resolves to, or whose range holds, an
// IPv6 address that carries an internal IPv4 address (NAT64, 6to4,
// Teredo) is refused, even where private targets are allowed: a gateway on
// the path would deliver it to 10.0.0.1. One that carries a public
// address is a public target.
func TestScanTargetEmbeddedIPv4(t *testing.T) {
	prev := httpsec.AllowLoopback
	httpsec.AllowLoopback = false
	t.Cleanup(func() { httpsec.AllowLoopback = prev })
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"64:ff9b::a00:1", false},
		{"2002:a00:1::1", false},
		{"2001:0:4136:e378:8000:63bf:f5ff:fffe", false},
		{"64:ff9b::a9fe:a9fe", false},
		{"fec0::1", false},
		{"64:ff9b::808:808", true},
	} {
		for _, allowPrivate := range []bool{false, true} {
			p := &ScanTargetPolicy{AllowPrivate: allowPrivate, LookupIP: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP(tc.addr)}, nil
			}}
			if _, err := p.Validate(context.Background(), "https://app.example.com/"); (err == nil) != tc.ok {
				t.Errorf("name -> %s (allow private %v): err %v, want ok %v", tc.addr, allowPrivate, err, tc.ok)
			}
			if _, err := p.Validate(context.Background(), tc.addr); (err == nil) != tc.ok {
				t.Errorf("address %s (allow private %v): err %v, want ok %v", tc.addr, allowPrivate, err, tc.ok)
			}
		}
	}
	for target, ok := range map[string]bool{
		"64:ff9b::/96":         false,
		"2002::/16":            false,
		"2001::/32":            false,
		"fec0::/10":            false,
		"198.16.0.0/14":        false, // holds 198.18.0.0/15 (benchmarking)
		"64:ff9b::808:800/120": true,
		"2002:808:808::/48":    true,
	} {
		p := &ScanTargetPolicy{AllowPrivate: true}
		if _, err := p.Validate(context.Background(), target); (err == nil) != ok {
			t.Errorf("range %s: err %v, want ok %v", target, err, ok)
		}
	}
}
