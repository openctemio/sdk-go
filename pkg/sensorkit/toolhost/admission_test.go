package toolhost

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// The sensor-local policy is the policy a sensor admits tasks against.
var _ Policy = (*core.LocalPolicy)(nil)

// fakePolicy refuses the targets in deny (by value) and the tools not in
// tools (nil: every tool).
type fakePolicy struct {
	deny    map[string]bool
	tools   []string
	maxRun  time.Duration
	kill    bool
	checked []string
}

func (f *fakePolicy) AllowsTool(name string) bool {
	if f.tools == nil {
		return true
	}
	for _, t := range f.tools {
		if t == name {
			return true
		}
	}
	return false
}

func (f *fakePolicy) CheckTarget(_ context.Context, target string) error {
	f.checked = append(f.checked, target)
	if f.deny[target] {
		return fmt.Errorf("refused by local policy (targets.deny): %s", target)
	}
	return nil
}

func (f *fakePolicy) CapTimeout(d time.Duration) time.Duration {
	if f.maxRun > 0 && (d <= 0 || d > f.maxRun) {
		return f.maxRun
	}
	return d
}

func (f *fakePolicy) KillSwitchEngaged() bool { return f.kill }

var scanManifest = tool.Manifest{
	Name: "probe", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces: []string{"finding:misconfiguration"}, Permissions: tool.Permissions{Network: tool.NetTargets},
}

func threeTargets() tool.Task {
	return tool.Task{Targets: []tool.Target{{Ref: "a", Value: "a.example"}, {Ref: "b", Value: "b.example"}, {Ref: "c", Value: "c.example"}}}
}

func TestAdmit(t *testing.T) {
	ctx := context.Background()
	refusedClass := func(t *testing.T, e *tool.Error, want string) {
		t.Helper()
		if e == nil || e.Class != tool.RefusedByPolicy || !strings.Contains(e.Detail, want) {
			t.Fatalf("want refused_by_policy containing %q, got %+v", want, e)
		}
	}

	t.Run("no policy admits by the manifest", func(t *testing.T) {
		a, e := Admit(ctx, scanManifest, threeTargets(), nil, "")
		if e != nil || len(a.Task.Targets) != 3 || a.Timeout != tool.DefaultTimeout {
			t.Fatalf("got %+v %v", a, e)
		}
	})
	t.Run("refused targets are removed, the rest admitted", func(t *testing.T) {
		pol := &fakePolicy{deny: map[string]bool{"b.example": true}}
		a, e := Admit(ctx, scanManifest, threeTargets(), pol, "")
		if e != nil {
			t.Fatal(e)
		}
		if len(a.Task.Targets) != 2 || a.Task.Targets[0].Ref != "a" || a.Task.Targets[1].Ref != "c" {
			t.Fatalf("admitted %+v", a.Task.Targets)
		}
		if len(a.Refused) != 1 || a.Refused[0].Ref != "b" || a.Refused[0].State != tool.StateSkipped || a.Refused[0].Class != tool.RefusedByPolicy {
			t.Fatalf("refused %+v", a.Refused)
		}
	})
	t.Run("every target refused refuses the task", func(t *testing.T) {
		pol := &fakePolicy{deny: map[string]bool{"a.example": true, "b.example": true, "c.example": true}}
		_, e := Admit(ctx, scanManifest, threeTargets(), pol, "")
		refusedClass(t, e, "refused every target")
	})
	t.Run("tools allow-list", func(t *testing.T) {
		_, e := Admit(ctx, scanManifest, threeTargets(), &fakePolicy{tools: []string{"other"}}, "")
		refusedClass(t, e, "tools.allow")
	})
	t.Run("kill switch", func(t *testing.T) {
		_, e := Admit(ctx, scanManifest, threeTargets(), &fakePolicy{kill: true}, "")
		refusedClass(t, e, "kill switch")
	})
	t.Run("linux capabilities are never granted", func(t *testing.T) {
		m := scanManifest
		m.Permissions.LinuxCaps = []string{"NET_RAW"}
		_, e := Admit(ctx, m, threeTargets(), nil, "")
		refusedClass(t, e, "NET_RAW")
	})
	t.Run("modes", func(t *testing.T) {
		m := scanManifest
		m.Modes = []tool.Mode{tool.Runner}
		_, e := Admit(ctx, m, threeTargets(), nil, tool.Daemon)
		refusedClass(t, e, "daemon mode")
		if _, e := Admit(ctx, m, threeTargets(), nil, tool.Runner); e != nil {
			t.Fatal(e)
		}
		if _, e := Admit(ctx, m, threeTargets(), nil, ""); e != nil {
			t.Fatal("an unknown mode is not checked:", e)
		}
	})
	t.Run("timeout capped by the policy", func(t *testing.T) {
		a, e := Admit(ctx, scanManifest, threeTargets(), &fakePolicy{maxRun: time.Minute}, "")
		if e != nil || a.Timeout != time.Minute {
			t.Fatalf("got %v %v", a.Timeout, e)
		}
	})
	t.Run("targets of a tool without target network are not network targets", func(t *testing.T) {
		m := tool.Manifest{Name: "parse", Version: "1.0.0", Class: tool.Parser, Tier: tool.T0, Produces: []string{"finding:vulnerability"}}
		pol := &fakePolicy{deny: map[string]bool{"/src": true}}
		a, e := Admit(ctx, m, tool.Task{Targets: []tool.Target{{Ref: "r", Value: "/src"}}}, pol, "")
		if e != nil || len(a.Task.Targets) != 1 || len(pol.checked) != 0 {
			t.Fatalf("got %+v %v checked=%v", a, e, pol.checked)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		c, cancel := context.WithCancel(ctx)
		cancel()
		_, e := Admit(c, scanManifest, threeTargets(), &fakePolicy{}, "")
		if e == nil || e.Class != tool.Canceled {
			t.Fatalf("got %+v", e)
		}
	})
}

// TestAdmitLocalPolicy runs the admission against a real sensor-local
// policy file.
func TestAdmitLocalPolicy(t *testing.T) {
	lp, err := core.ParseLocalPolicy([]byte(`apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["198.51.100.0/24"]
ports:
  allow: "443"
tools:
  allow: ["probe"]
rate:
  max_job_seconds: 120
`), core.LocalPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	task := tool.Task{Targets: []tool.Target{
		{Ref: "in", Value: "https://198.51.100.7"},
		{Ref: "out", Value: "https://203.0.113.9"},
		{Ref: "port", Value: "https://198.51.100.7:8443"},
		{Ref: "meta", Value: "http://169.254.169.254/latest"},
	}}
	a, e := Admit(context.Background(), scanManifest, task, lp, "")
	if e != nil {
		t.Fatal(e)
	}
	if len(a.Task.Targets) != 1 || a.Task.Targets[0].Ref != "in" {
		t.Fatalf("admitted %+v", a.Task.Targets)
	}
	if len(a.Refused) != 3 {
		t.Fatalf("refused %+v", a.Refused)
	}
	if a.Timeout != 2*time.Minute {
		t.Fatalf("timeout %v", a.Timeout)
	}
	m := scanManifest
	m.Name = "other"
	if _, e := Admit(context.Background(), m, task, lp, ""); e == nil || e.Class != tool.RefusedByPolicy {
		t.Fatalf("a tool outside tools.allow: %+v", e)
	}
}

// dialTool fetches every target it is given (compiled in; see TestMain).
var dialTool = tool.New(tool.Manifest{
	Name: "dial-tool", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces: []string{"finding:misconfiguration"}, Permissions: tool.Permissions{Network: tool.NetTargets},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	c := &http.Client{Timeout: 5 * time.Second}
	for _, tg := range task.Targets {
		resp, err := c.Get(tg.Value)
		if err != nil {
			ctx.TargetError(tg, tool.Unreachable(err))
			continue
		}
		_ = resp.Body.Close()
		if err := ctx.Emit().Finding(tg, ctis.Finding{Type: "misconfiguration", RuleID: "seen", Title: "fetched " + tg.Ref, Severity: "info"}); err != nil {
			return err
		}
		ctx.TargetDone(tg)
	}
	return nil
})

// recorder is a server that counts the connections it accepts.
func recorder(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			n.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &n
}

// TestRefusedTargetIsNeverTouched: the tool runs out of process and fetches
// every target it receives; the policy refuses one, which never sees a
// connection and is reported skipped (refused_by_policy).
func TestRefusedTargetIsNeverTouched(t *testing.T) {
	allowed, allowedHits := recorder(t)
	refused, refusedHits := recorder(t)
	h := testHost(t)
	h.Policy = &fakePolicy{deny: map[string]bool{refused.URL: true}}
	task := tool.Task{ID: "adm-1", Targets: []tool.Target{{Ref: "ok", Value: allowed.URL}, {Ref: "no", Value: refused.URL}}}
	out, err := h.RunBuiltin(context.Background(), dialTool, task, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err != nil {
		t.Fatalf("task error: %+v (stderr %s)", out.Err, out.Stderr)
	}
	if refusedHits.Load() != 0 {
		t.Fatalf("the refused target was contacted %d time(s)", refusedHits.Load())
	}
	if allowedHits.Load() == 0 {
		t.Fatal("the admitted target was never contacted")
	}
	if out.Status != tool.StatusPartial {
		t.Fatalf("status %s, want partial", out.Status)
	}
	states := map[string]TargetOutcome{}
	for _, to := range out.Targets {
		states[to.Ref] = to
	}
	if states["ok"].State != tool.StateDone || states["no"].State != tool.StateSkipped || states["no"].Class != tool.RefusedByPolicy {
		t.Fatalf("targets %+v", out.Targets)
	}
	if len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != "fetched ok" {
		t.Fatalf("findings %+v", out.Report.Findings)
	}
}

// TestFullyRefusedTaskNeverStarts: no process, no task directory, no
// credential read; the outcome says why.
func TestFullyRefusedTaskNeverStarts(t *testing.T) {
	refused, hits := recorder(t)
	h := testHost(t)
	h.Policy = &fakePolicy{deny: map[string]bool{refused.URL: true}}
	out, err := h.RunBuiltin(context.Background(), dialTool, tool.Task{Targets: []tool.Target{{Ref: "no", Value: refused.URL}}}, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusFailed || out.Err == nil || out.Err.Class != tool.RefusedByPolicy || out.ExitCode != -1 {
		t.Fatalf("outcome %+v", out)
	}
	if hits.Load() != 0 {
		t.Fatal("a refused target was contacted")
	}
	h.Policy = &fakePolicy{tools: []string{"something-else"}}
	out, err = h.RunBuiltin(context.Background(), echoTool, tool.Task{Targets: oneTarget}, RunOptions{
		Credentials: map[string]string{"api_key": "sk-never-read"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err == nil || out.Err.Class != tool.RefusedByPolicy {
		t.Fatalf("outcome %+v", out)
	}
}

// TestPolicyCapsTheRunTime: the policy's run-time cap stops a task the
// manifest would let run for an hour.
func TestPolicyCapsTheRunTime(t *testing.T) {
	h := testHost(t)
	h.Policy = &fakePolicy{maxRun: 2 * time.Second}
	start := time.Now()
	out, err := h.RunBuiltin(context.Background(), echoTool, tool.Task{Targets: oneTarget}, RunOptions{Env: map[string]string{"TOOLHOST_SLEEP": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err == nil || out.Err.Class != tool.Timeout {
		t.Fatalf("outcome %+v", out.Err)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("took %v", d)
	}
}

// TestExecProfileAdmission: the exec profile is admitted the same way.
func TestExecProfileAdmission(t *testing.T) {
	refused, hits := recorder(t)
	h := testHost(t)
	h.Policy = &fakePolicy{deny: map[string]bool{refused.URL: true}}
	m := tool.Manifest{Name: "cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Produces: []string{"finding:misconfiguration"}, Permissions: tool.Permissions{Network: tool.NetTargets},
		Run: &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{"/bin/true"}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}}}
	out, err := h.RunManifest(context.Background(), m, tool.Task{Targets: []tool.Target{{Ref: "no", Value: refused.URL}}}, RunOptions{Trusted: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err == nil || out.Err.Class != tool.RefusedByPolicy || hits.Load() != 0 {
		t.Fatalf("outcome %+v", out.Err)
	}
}
