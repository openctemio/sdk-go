package toolhost

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: a tool that runs a web browser (permissions.sandbox: browser)
// is refused unless the sandbox enforces every control in required mode and
// confines the task's network: a target's scripts never run on a sensor
// whose task could reach anything but its forwarder.
func TestBrowserToolNeedsAFullSandbox(t *testing.T) {
	m := browserTool()
	task := tool.Task{Targets: []tool.Target{{Ref: "t0", Value: "https://203.0.113.5"}}}
	full := executor.Status{Backend: "process", Mode: executor.ModeRequired, Sandboxed: true, Landlock: 4,
		Seccomp: true, NoNewPrivs: true, Rlimits: true, NetworkEnforced: true}
	for _, st := range []executor.Status{
		{},
		{NetworkEnforced: true, Mode: executor.ModeAuto, Sandboxed: true, Landlock: 4, Seccomp: true, NoNewPrivs: true, Rlimits: true},
		{Mode: executor.ModeRequired, Sandboxed: true, Landlock: 4, Seccomp: true, NoNewPrivs: true, Rlimits: true},
		{Mode: executor.ModeRequired, NetworkEnforced: true, Sandboxed: true, Seccomp: true, NoNewPrivs: true, Rlimits: true},
	} {
		h := &Host{Backend: statusBackend{st: st}}
		_, ierr, err := h.prepare(context.Background(), m, task, RunOptions{})
		// The browser's own check, or the general refusal of a tool that
		// contacts its targets on a host whose sandbox is not fully
		// enforced (it runs first): either way the tool does not run.
		if err != nil || ierr == nil || ierr.Class != tool.RefusedByPolicy ||
			(!strings.Contains(ierr.Detail, "web browser") && !strings.Contains(ierr.Detail, "not fully enforced")) {
			t.Errorf("status %+v: ierr %+v err %v", st, ierr, err)
		}
	}
	h := &Host{Backend: statusBackend{st: full}}
	if _, ierr, _ := h.prepare(context.Background(), m, task, RunOptions{}); ierr != nil && strings.Contains(ierr.Detail, "web browser") {
		t.Errorf("a full sandbox refused the browser tool: %+v", ierr)
	}
}

// The manifest's sandbox is browser or nothing, and a browser reaches the
// network only as a targets tool.
func TestManifestSandboxValues(t *testing.T) {
	m := browserTool()
	m.Permissions.Sandbox = "privileged"
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "/permissions/sandbox") {
		t.Errorf("unknown sandbox accepted: %v", err)
	}
	m.Permissions.Sandbox = tool.SandboxBrowser
	if err := m.Validate(); err != nil {
		t.Errorf("browser sandbox refused: %v", err)
	}
	m.Permissions.Network = tool.NetResolver
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "/permissions/sandbox") {
		t.Errorf("browser sandbox with network resolver accepted: %v", err)
	}
}

// browserTool is a valid manifest of a tool in the browser sandbox.
func browserTool() tool.Manifest {
	return tool.Manifest{
		APIVersion: tool.APIVersion, Name: "shot", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"web_origin"}, Produces: []string{"asset:web_origin"},
		Permissions: tool.Permissions{Network: tool.NetTargets, Sandbox: tool.SandboxBrowser},
	}
}
