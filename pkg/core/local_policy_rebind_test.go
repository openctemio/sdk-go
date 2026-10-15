package core

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// flipResolver answers the first lookup with first and every later one
// with later: a name re-bound between the target check and the dial (DNS
// rebinding).
func flipResolver(first, later string) (func(context.Context, string) ([]net.IP, error), *atomic.Int32) {
	var n atomic.Int32
	return func(context.Context, string) ([]net.IP, error) {
		if n.Add(1) == 1 {
			return []net.IP{net.ParseIP(first)}, nil
		}
		return []net.IP{net.ParseIP(later)}, nil
	}, &n
}

// noLoopbackAllowance pins the production loopback posture for a test
// (CI sets OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK=1 for its local fakes).
func noLoopbackAllowance(t *testing.T) {
	t.Helper()
	prev := httpsec.AllowLoopback
	httpsec.AllowLoopback = false
	t.Cleanup(func() { httpsec.AllowLoopback = prev })
}

func absentPolicyWithResolver(t *testing.T, lookup func(context.Context, string) ([]net.IP, error)) *LocalPolicy {
	t.Helper()
	lp, err := LoadLocalPolicy(LocalPolicyOptions{DefaultPath: filepath.Join(t.TempDir(), "none.yaml"),
		LookupEnv: env(nil), LookupIP: lookup})
	if err != nil {
		t.Fatal(err)
	}
	if lp.Present() {
		t.Fatal("a policy is loaded")
	}
	return lp
}

// Without a policy file, the addresses a confined task's forwarder dials
// (AdmittedAddrs) pass the built-in deny list too: a name that resolves to
// a private, loopback, CGNAT or metadata address is refused, never pinned.
func TestAdmittedAddrs_NoPolicyRefusesInternalAddresses(t *testing.T) {
	noLoopbackAllowance(t)
	t.Setenv(EnvSensorAllowPrivateTargets, "")
	for _, addr := range []string{"10.1.2.3", "169.254.169.254", "127.0.0.1", "100.64.0.1", "fd00:ec2::254", "192.168.1.1"} {
		lp := absentPolicyWithResolver(t, func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP(addr)}, nil
		})
		if got, err := lp.AdmittedAddrs(context.Background(), "rebind.example.com"); err == nil {
			t.Errorf("%s: admitted %v", addr, got)
		}
	}
}

// A name that resolves public when the target is checked and private when
// the forwarder's addresses are taken is refused at the second look: what
// is pinned is always what was checked.
func TestAdmittedAddrs_NoPolicyRebindIsRefused(t *testing.T) {
	t.Setenv(EnvSensorAllowPrivateTargets, "")
	for _, later := range []string{"10.0.0.5", "169.254.169.254"} {
		lookup, calls := flipResolver("203.0.113.10", later)
		lp := absentPolicyWithResolver(t, lookup)
		ctx := context.Background()
		if err := lp.CheckTarget(ctx, "rebind.example.com"); err != nil {
			t.Fatalf("check: %v", err)
		}
		got, err := lp.AdmittedAddrs(ctx, "rebind.example.com")
		if calls.Load() < 2 {
			t.Fatal("the name was not looked up again")
		}
		if err == nil {
			t.Errorf("re-bound to %s: pinned %v", later, got)
		}
	}
}

// A public name stays admitted, at the addresses checked.
func TestAdmittedAddrs_NoPolicyPublicPinned(t *testing.T) {
	lp := absentPolicyWithResolver(t, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})
	got, err := lp.AdmittedAddrs(context.Background(), "public.example.com")
	if err != nil || len(got) != 1 || got[0].String() != "203.0.113.10" {
		t.Fatalf("got %v, %v", got, err)
	}
}
