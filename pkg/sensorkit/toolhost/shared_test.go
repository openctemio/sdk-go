package toolhost

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

var targetsTool = tool.Manifest{Name: "probe", Version: "1.0.0", Permissions: tool.Permissions{Network: tool.NetTargets}}

// SECURITY: a shared sensor runs no tool on a backend that does not
// enforce every control and confine the network (fail closed).
func TestSharedHostRefusesUnconfinedBackend(t *testing.T) {
	for _, st := range []executor.Status{
		{},
		{NetworkEnforced: true, Mode: executor.ModeAuto},
		{Mode: executor.ModeRequired},
	} {
		h := &Host{Shared: true, Backend: statusBackend{st: st}}
		_, ierr, err := h.prepare(context.Background(), targetsTool, tool.Task{Targets: []tool.Target{{Ref: "t0", Value: "203.0.113.5"}}}, RunOptions{})
		if err == nil && (ierr == nil || ierr.Class != tool.RefusedByPolicy || !strings.Contains(ierr.Detail, "shared sensor")) {
			t.Errorf("status %+v: ierr %+v err %v", st, ierr, err)
		}
	}
}

// SECURITY: a shared sensor's admission refuses a target that names an
// internal address: a private one outside the job's zone (or without the
// operator's switch), any metadata, loopback or CGNAT address.
func TestSharedPolicyZones(t *testing.T) {
	zone := core.WithJobZone(context.Background(), core.ParseZoneRanges([]string{"10.1.0.0/16"}))
	cases := []struct {
		name, target, resolves string
		allowPrivate           bool
		ctx                    context.Context
		ok                     bool
	}{
		{"public name", "https://app.example.com/", "203.0.113.7", false, context.Background(), true},
		{"private name, no zone", "https://app.example.com/", "10.1.2.3", true, context.Background(), false},
		{"private name, in zone", "https://app.example.com/", "10.1.2.3", true, zone, true},
		{"private name, in zone, operator refuses", "https://app.example.com/", "10.1.2.3", false, zone, false},
		{"private address, in zone", "10.1.2.3:8443", "", true, zone, true},
		{"private address, outside zone", "10.9.2.3", "", true, zone, false},
		{"metadata", "http://169.254.169.254/latest/", "", true, zone, false},
		{"range in zone", "10.1.4.0/24", "", true, zone, true},
		{"range wider than zone", "10.0.0.0/8", "", true, zone, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.allowPrivate {
				t.Setenv(core.EnvSensorAllowPrivateTargets, "1")
			} else {
				t.Setenv(core.EnvSensorAllowPrivateTargets, "")
			}
			stubLookup(t, func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(c.resolves)}, nil
			})
			p := sharedPolicy{inner: addrPolicy{resolves: c.resolves}}
			err := p.CheckTarget(c.ctx, c.target)
			if (err == nil) != c.ok {
				t.Fatalf("err %v, want ok %v", err, c.ok)
			}
		})
	}
}

// addrPolicy checks a name target as the address it resolves to (a policy
// whose resolver the test controls).
type addrPolicy struct {
	builtinPolicy
	resolves string
}

func (p addrPolicy) CheckTarget(ctx context.Context, target string) error {
	if p.resolves != "" && strings.Contains(target, "app.example.com") {
		target = p.resolves
	}
	return p.builtinPolicy.CheckTarget(ctx, target)
}

// SECURITY: the addresses pinned for a shared sensor's task pass the job's
// zone rule too: a name the policy admits (private switch on) that resolves
// to a private address outside the zone gets no address to dial.
func TestSharedTaskScopePinsOnlyZoneAddresses(t *testing.T) {
	t.Setenv(core.EnvSensorAllowPrivateTargets, "1")
	stubLookup(t, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("10.9.9.9")}, nil
	})
	zone := core.WithJobZone(context.Background(), core.ParseZoneRanges([]string{"10.1.0.0/16"}))
	task := tool.Task{Targets: []tool.Target{{Ref: "t0", Value: "https://app.example.com/"}}}
	for _, pol := range []Policy{builtinPolicy{}, nil} {
		h := &Host{Shared: true, Policy: pol}
		got := h.taskScope(zone, targetsTool, task).Names["app.example.com"]
		if !slices.Contains(got, netip.MustParseAddr("203.0.113.7")) || !slices.Contains(got, netip.MustParseAddr("10.1.2.3")) ||
			slices.Contains(got, netip.MustParseAddr("10.9.9.9")) {
			t.Errorf("policy %T: pinned %v", pol, got)
		}
		if got := h.taskScope(context.Background(), targetsTool, task).Names["app.example.com"]; len(got) != 1 {
			t.Errorf("policy %T, no zone: pinned %v", pol, got)
		}
	}
}
