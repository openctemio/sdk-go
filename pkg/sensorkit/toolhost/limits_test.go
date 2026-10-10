package toolhost

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

type statusBackend struct {
	executor.Backend
	st executor.Status
}

func (b statusBackend) Status() executor.Status { return b.st }

// SECURITY: a task with scope limits runs only where they are enforced:
// never on a sandbox that does not confine the network, never for a tool
// that reaches more than its targets, never with limits for another host.
func TestCheckLimits(t *testing.T) {
	targets := []tool.Target{{Ref: "a", Value: "https://a.example/api/"}}
	limits := []scopelimit.Limit{{Host: "a.example", Ports: "443", PathPrefix: "/api"}}
	m := tool.Manifest{Name: "crawler", Permissions: tool.Permissions{Network: tool.NetTargets}}
	confined := &Host{Backend: statusBackend{st: executor.Status{NetworkEnforced: true}}}
	open := &Host{Backend: statusBackend{st: executor.Status{}}}

	if e := confined.checkLimits(m, tool.Task{Targets: targets, Limits: limits}); e != nil {
		t.Fatalf("confined: %v", e)
	}
	if e := open.checkLimits(m, tool.Task{Targets: targets}); e != nil {
		t.Fatalf("no limits: %v", e)
	}
	if e := open.checkLimits(m, tool.Task{Targets: targets, Limits: limits}); e == nil || e.Class != tool.RefusedByPolicy ||
		!strings.Contains(e.Detail, "does not confine") {
		t.Fatalf("unconfined sandbox: %+v", e)
	}
	for _, n := range []tool.Network{tool.NetEgressProxy, tool.NetVendor} {
		mm := m
		mm.Permissions.Network = n
		if e := confined.checkLimits(mm, tool.Task{Targets: targets, Limits: limits}); e == nil || e.Class != tool.RefusedByPolicy {
			t.Fatalf("network %s: %+v", n, e)
		}
	}
	if e := confined.checkLimits(m, tool.Task{Targets: targets, Limits: []scopelimit.Limit{{Host: "b.example", Ports: "443"}}}); e == nil {
		t.Fatal("a limit for another host accepted")
	}
	none := m
	none.Permissions.Network = tool.NetNone
	if e := open.checkLimits(none, tool.Task{Targets: targets, Limits: limits}); e != nil {
		t.Fatalf("a tool without network: %v", e)
	}
	// The forwarder of a targets tool receives the limits.
	if s := confined.taskScope(context.Background(), m, tool.Task{Targets: targets, Limits: limits}); len(s.Limits) != 1 {
		t.Fatalf("scope limits %+v", s.Limits)
	}
}
