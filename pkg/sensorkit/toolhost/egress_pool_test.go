package toolhost

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

type nopDialer struct{}

func (nopDialer) Dial(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }

// SECURITY: a task of a pooled job runs only behind a forwarder that
// confines the network; a tool with network "none" makes no connection
// and runs anywhere.
func TestCheckEgress(t *testing.T) {
	m := tool.Manifest{Name: "scanner", Permissions: tool.Permissions{Network: tool.NetTargets}}
	confined := &Host{Backend: statusBackend{st: executor.Status{NetworkEnforced: true}}}
	open := &Host{Backend: statusBackend{st: executor.Status{}}}
	if e := confined.checkEgress(m, nopDialer{}); e != nil {
		t.Fatalf("confined: %v", e)
	}
	if e := open.checkEgress(m, nil); e != nil {
		t.Fatalf("no pool: %v", e)
	}
	for _, n := range []tool.Network{tool.NetTargets, tool.NetResolver, tool.NetVendor, tool.NetEgressProxy} {
		mm := m
		mm.Permissions.Network = n
		e := open.checkEgress(mm, nopDialer{})
		if e == nil || e.Class != tool.RefusedByPolicy || !strings.Contains(e.Detail, core.RefusalEgressUnavailable) {
			t.Fatalf("network %s on an unconfined sandbox: %+v", n, e)
		}
	}
	none := m
	none.Permissions.Network = tool.NetNone
	if e := open.checkEgress(none, nopDialer{}); e != nil {
		t.Fatalf("a tool without network: %v", e)
	}
}

// The pool reaches the host from the task or, for a path that builds its
// own task, from the job's context.
func TestTaskEgressDialer(t *testing.T) {
	if taskEgressDialer(context.Background(), tool.Task{}) != nil {
		t.Fatal("a pool from nowhere")
	}
	ctx := core.WithEgressDialer(context.Background(), nopDialer{})
	if taskEgressDialer(ctx, tool.Task{}) == nil {
		t.Fatal("the job context's pool is not used")
	}
	if taskEgressDialer(context.Background(), tool.Task{Egress: nopDialer{}}) == nil {
		t.Fatal("the task's pool is not used")
	}
}

// SECURITY: a pooled task on a sandbox that does not confine the network
// is refused before anything runs.
func TestPooledTaskRefusedOnUnconfinedSandbox(t *testing.T) {
	h := testHost(t)
	h.Backend = statusBackend{Backend: executor.Current(), st: executor.Status{}}
	m := tool.Manifest{
		Name: "pool-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"domain"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetTargets},
		Run:         &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{h.Self}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	task := tool.Task{Targets: oneTarget, Egress: nopDialer{}}
	out, err := h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "argv-cli"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err == nil || out.Err.Class != tool.RefusedByPolicy || out.Report != nil && len(out.Report.Findings) > 0 {
		t.Fatalf("pooled task ran unconfined: %+v %+v", out.Err, out.Report)
	}
}
