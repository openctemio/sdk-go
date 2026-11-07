package executor

import (
	"context"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// A launcher that cannot run stands for any host that cannot give a required
// control (no user namespaces, a blocked profile, no Landlock).
const brokenLauncher = "/nonexistent/openctem-launcher"

// research/468 D3: a required control the host cannot give no longer fails
// the backend when the caller asks to refuse active work instead; the
// backend then never runs a task that may contact its targets, and passive
// tasks still run.
func TestRequiredUnmetRefusesActiveTasks(t *testing.T) {
	for _, cfg := range []Config{
		{Mode: ModeRequired, Launcher: brokenLauncher, RefuseActiveWhenUnmet: true},
		{Mode: ModeAuto, Launcher: brokenLauncher, ConfineNetwork: true, RequireNetwork: true, RefuseActiveWhenUnmet: true},
	} {
		b, err := NewProcessBackend(cfg)
		if err != nil {
			t.Fatalf("%+v: %v, want a backend that refuses active tasks", cfg, err)
		}
		st := b.Status()
		if st.RequiredUnmet == "" || st.Mode != cfg.Mode {
			t.Fatalf("status %+v: want RequiredUnmet and mode %s", st, cfg.Mode)
		}
		if st.Unconfined() != UnconfinedRefused || !st.RefusesActiveTools() || !slices.Contains(st.FailedControls(), "required") {
			t.Fatalf("status %+v must refuse active tools and name the required control", st)
		}
		if !strings.Contains(st.UnconfinedDetail(), "required: ") {
			t.Fatalf("detail %q lacks the required cause", st.UnconfinedDetail())
		}
		// Every network class a tool that contacts its targets may use is
		// refused unless the caller states the task is passive.
		for _, n := range []NetworkClass{"", NetworkAny, NetworkTargetsOnly, NetworkResolver, NetworkEgressProxy} {
			if _, err := b.Prepare(TaskSpec{ID: "active", Argv: []string{"true"}, Network: n}); !errors.Is(err, ErrActiveRefused) {
				t.Fatalf("network %q: Prepare = %v, want ErrActiveRefused", n, err)
			}
		}
		// Passive tasks and tasks without network run.
		for _, spec := range []TaskSpec{
			{ID: "passive", Argv: []string{"true"}, Network: NetworkAny, Passive: true, Stdout: io.Discard, Stderr: io.Discard},
			{ID: "offline", Argv: []string{"true"}, Network: NetworkNone, Stdout: io.Discard, Stderr: io.Discard},
		} {
			task, err := b.Prepare(spec)
			if err != nil {
				t.Fatalf("%s: Prepare = %v, want it to run", spec.ID, err)
			}
			if runtime.GOOS != "windows" {
				if err := task.Start(context.Background()); err != nil {
					t.Fatalf("%s: start: %v", spec.ID, err)
				}
				if res, err := task.Wait(); err != nil || res.ExitCode != 0 {
					t.Fatalf("%s: wait %+v %v", spec.ID, res, err)
				}
			}
			_ = task.Cleanup()
		}
	}
}

// Without the opt-in, for a shared sensor, and for a configuration error the
// backend still fails: only a host limit becomes a refusal of active work.
func TestRequiredUnmetStillFails(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no opt-in": {Mode: ModeRequired, Launcher: brokenLauncher},
		"shared":    {Mode: ModeRequired, Launcher: brokenLauncher, Shared: true, RefuseActiveWhenUnmet: true},
		"bad mode":  {Mode: "bogus", RefuseActiveWhenUnmet: true},
		"bad path":  {Mode: ModeRequired, Launcher: brokenLauncher, ReadDeny: []string{"/"}, RefuseActiveWhenUnmet: true},
	} {
		if b, err := NewProcessBackend(cfg); err == nil {
			t.Fatalf("%s: backend %+v, want an error", name, b.Status())
		}
	}
	// Auto without a requirement is unchanged: no RequiredUnmet.
	b, err := NewProcessBackend(Config{Mode: ModeAuto, Launcher: brokenLauncher, RefuseActiveWhenUnmet: true})
	if err != nil || b.Status().RequiredUnmet != "" {
		t.Fatalf("auto: %v %+v", err, b)
	}
}

func TestStatusRequiredUnmet(t *testing.T) {
	// Even a status that looks complete refuses when a required control is
	// missing (the network, here).
	st := Status{Mode: ModeRequired, Sandboxed: true, Landlock: 4, RequiredUnmet: "network confinement required but not available"}
	if !st.RefusesActiveTools() || !slices.Equal(st.FailedControls(), []string{"required"}) {
		t.Fatalf("%+v: refuses %t, controls %v", st, st.RefusesActiveTools(), st.FailedControls())
	}
}
