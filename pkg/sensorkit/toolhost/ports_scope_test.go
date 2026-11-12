package toolhost

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// The local policy's ports.allow is enforced at connect time: a task's
// forwarder scope carries the allowed destination ports, so a connection to
// any other port is refused whatever the tool was configured with.
func TestTaskScopeCarriesLocalPolicyPorts(t *testing.T) {
	lp, err := core.ParseLocalPolicy([]byte(`apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["192.0.2.0/24"]
ports:
  allow: "80,443,8000-8002"
`), core.LocalPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	h := &Host{Policy: lp}
	task := tool.Task{Targets: []tool.Target{{Ref: "t0", Value: "192.0.2.5"}}}
	s := h.taskScope(ctx, tool.Manifest{Permissions: tool.Permissions{Network: tool.NetTargets}}, task)
	if want := []int{80, 443, 8000, 8001, 8002}; !slices.Equal(s.Ports, want) {
		t.Fatalf("scope ports %v, want %v", s.Ports, want)
	}
	// The forwarder built from it refuses another port to an admitted
	// target, and keeps allowing the listed ones.
	f := egress.New(s, egress.Limits{})
	for _, port := range []int{22, 79, 8003, 65535} {
		if _, err := f.Resolve(ctx, "192.0.2.5", port); !errors.Is(err, egress.ErrRefused) {
			t.Errorf("port %d: %v, want refused", port, err)
		}
	}
	for _, port := range []int{80, 443, 8001} {
		if _, err := f.Resolve(ctx, "192.0.2.5", port); err != nil {
			t.Errorf("port %d: %v", port, err)
		}
	}
	// A DNS-only task connects to nothing, so its scope needs no ports; a
	// tool that reaches a vendor's API or the internet through the sensor's
	// egress is not scanning its targets' ports.
	for name, m := range map[string]tool.Manifest{
		"vendor":       {Permissions: tool.Permissions{Network: tool.NetVendor, VendorHosts: []string{"api.vendor.example:443"}}},
		"egress proxy": {Permissions: tool.Permissions{Network: tool.NetEgressProxy}},
	} {
		if s := h.taskScope(ctx, m, tool.Task{}); s.Ports != nil {
			t.Errorf("%s tool: ports %v", name, s.Ports)
		}
	}
	// No policy, a policy without ports.allow, or a Policy that has none to
	// offer: no restriction beyond what the scope already says.
	open, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"192.0.2.0/24\"]\n"), core.LocalPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, pol := range map[string]Policy{"no policy": nil, "no ports.allow": open, "builtin": builtinPolicy{}} {
		hh := &Host{Policy: pol}
		if s := hh.taskScope(ctx, tool.Manifest{Permissions: tool.Permissions{Network: tool.NetTargets}}, task); s.Ports != nil {
			t.Errorf("%s: ports %v", name, s.Ports)
		}
	}
}
