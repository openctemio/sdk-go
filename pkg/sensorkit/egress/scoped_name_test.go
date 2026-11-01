package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// Only a target the job scoped by name is marked for remote DNS (socks5h);
// an address target, a vendor host and an address a name is pinned to are
// dialed by the checked address. A name whose admitted address is denied
// is refused before any Dial.
func TestOnlyNameScopedTargetsAreMarkedForRemoteDNS(t *testing.T) {
	scope := Scope{
		Names: map[string][]netip.Addr{
			"app.example":  {netip.MustParseAddr("192.0.2.10")},
			"meta.example": {netip.MustParseAddr("169.254.169.254")},
		},
		Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Vendor:   []string{"vendor.example"},
	}
	f := New(scope, Limits{Rate: 1000})
	f.LookupVendor = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	}
	seen := map[string]bool{}
	f.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		seen[TargetHost(ctx)] = TargetScopedByName(ctx)
		c, s := net.Pipe()
		t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
		return c, nil
	}
	ctx := context.Background()
	for _, h := range []string{"APP.example.", "198.51.100.4", "192.0.2.10", "vendor.example"} {
		if _, _, err := f.dial(ctx, "connect", h, 443); err != nil {
			t.Fatalf("%s: %v", h, err)
		}
	}
	want := map[string]bool{"app.example": true, "198.51.100.4": false, "192.0.2.10": false, "vendor.example": false}
	for h, w := range want {
		if got, ok := seen[h]; !ok || got != w {
			t.Fatalf("%s scoped by name = %v (dialed %v), want %v", h, got, ok, w)
		}
	}
	if _, _, err := f.dial(ctx, "connect", "meta.example", 443); !errors.Is(err, ErrRefused) {
		t.Fatalf("a name pinned to a metadata address: %v, want ErrRefused", err)
	}
	if _, ok := seen["meta.example"]; ok {
		t.Fatal("a name with a denied address reached Dial")
	}
}
