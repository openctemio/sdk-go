package egress

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/openctemio/sdk-go/pkg/reach"
)

// The forwarder records every dial toward a target with its class, and
// nothing for a vendor host or a refused destination.
func TestForwarderRecordsReach(t *testing.T) {
	fw := New(Scope{
		Prefixes: []netip.Prefix{pfx("192.0.2.0/24"), pfx("2001:db8::/64")},
		Names:    map[string][]netip.Addr{"app.example.com": {addr("192.0.2.7")}},
		Vendor:   []string{"vendor.example.net"},
	}, Limits{})
	fw.Reach = reach.NewRecorder()
	fw.LookupVendor = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{addr("203.0.113.5")}, nil }
	errs := map[string]syscall.Errno{
		"192.0.2.1:443":    syscall.ECONNREFUSED,
		"[2001:db8::2]:22": syscall.ENETUNREACH,
		"192.0.2.7:443":    syscall.ETIMEDOUT,
		"203.0.113.5:443":  syscall.ETIMEDOUT,
	}
	fw.Dial = func(_ context.Context, _, a string) (net.Conn, error) {
		if e, ok := errs[a]; ok {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
		}
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	ctx := context.Background()
	for _, d := range []struct {
		host string
		port int
	}{{"192.0.2.1", 443}, {"192.0.2.3", 80}, {"2001:db8::2", 22}, {"app.example.com", 443}, {"vendor.example.net", 443}, {"198.51.100.1", 443}} {
		if c, _, err := fw.dial(ctx, "connect", d.host, d.port); err == nil {
			_ = c.Close()
		}
	}
	rep := fw.Reach.Report()
	want := map[reach.Class]int{reach.PortClosed: 1, reach.Reached: 1, reach.NoRoute: 1, reach.Timeout: 1}
	if rep.Targets != 4 || len(rep.Classes) != len(want) {
		t.Fatalf("report %+v", rep.Summary)
	}
	for c, n := range want {
		if rep.Classes[c] != n {
			t.Errorf("%s = %d, want %d", c, rep.Classes[c], n)
		}
	}
	for _, u := range rep.UnreachedList {
		if u.Target == "vendor.example.net" || u.Target == "198.51.100.1" {
			t.Errorf("recorded a non-target: %+v", u)
		}
	}
}
