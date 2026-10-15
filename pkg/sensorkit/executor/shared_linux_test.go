package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A shared backend refuses to exist without every control: the sandbox in
// required mode and network confinement (fail closed, never degraded).
func TestSharedRefusesWithoutSandbox(t *testing.T) {
	for _, m := range []Mode{ModeOff, ModeAuto, ""} {
		if _, err := NewProcessBackend(Config{Mode: m, Shared: true, WorkRoot: t.TempDir()}); err == nil {
			t.Errorf("shared backend accepted in mode %q", m)
		}
	}
	b, err := NewProcessBackend(Config{Mode: ModeRequired, Shared: true, WorkRoot: t.TempDir(), Limits: Limits{Processes: 64}})
	if err != nil {
		if !strings.Contains(err.Error(), "required") {
			t.Fatalf("refusal does not say what is missing: %v", err)
		}
		return // this host cannot confine: refused, as it must be
	}
	if st := b.Status(); !st.NetworkEnforced || !st.Complete() {
		t.Fatalf("a shared backend runs without every control: %+v", st)
	}
}

func newSharedBackend(t *testing.T) *ProcessBackend {
	t.Helper()
	b, err := NewProcessBackend(Config{Mode: ModeRequired, Shared: true, WorkRoot: t.TempDir(), Limits: Limits{Processes: 64}})
	if err != nil {
		if os.Getenv("OPENCTEM_TEST_REQUIRE_NETNS") == "1" {
			t.Fatalf("shared backend required by the environment, not available: %v", err)
		}
		t.Skipf("shared backend not available here: %v", err)
	}
	return b
}

// SECURITY: on a shared backend nothing a task writes outlives it or
// reaches another job: a write path or a state directory outside the task
// root (a tool cache, an output directory) is refused.
func TestSharedRefusesWritableStateOutsideTaskRoot(t *testing.T) {
	b := newSharedBackend(t)
	exe, _ := os.Executable()
	shared := t.TempDir() // a cache directory every job would share
	for name, spec := range map[string]TaskSpec{
		"write path":     {WritePaths: []string{shared}},
		"cache variable": {SetEnv: map[string]string{"XDG_CACHE_HOME": shared}},
		"home variable":  {SetEnv: map[string]string{"HOME": "/var/lib/sensor"}},
		"escape":         {WritePaths: []string{filepath.Join(TaskRoot(), "..", "cache")}},
		"the root":       {WritePaths: []string{TaskRoot()}},
	} {
		spec.Argv = []string{exe}
		if task, err := b.Prepare(spec); err == nil {
			_ = task.Cleanup()
			t.Errorf("%s: accepted", name)
		}
	}
	// A directory of this task's own, beneath the task root, is fine.
	own, err := NewTaskDir("own-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(own) }()
	task, err := b.Prepare(TaskSpec{Argv: []string{exe}, WritePaths: []string{own}, SetEnv: map[string]string{"XDG_CONFIG_HOME": own}})
	if err != nil {
		t.Fatalf("own task directory refused: %v", err)
	}
	_ = task.Cleanup()
}

// SECURITY (acceptance): two jobs on a shared backend: the second cannot
// read what the first wrote, and the first's directory is gone after its
// task, even when the task failed.
func TestSharedJobsAreIsolatedAndCleanedAfterFailure(t *testing.T) {
	b := newSharedBackend(t)
	exe, _ := os.Executable()
	run := func(mode string, args ...string) (string, string) {
		var out, errb bytes.Buffer
		task, err := b.Prepare(TaskSpec{Argv: append([]string{exe}, args...), Env: []string{"EXECUTOR_TEST_TOOL=" + mode, "PATH=/usr/bin:/bin"}, Stdout: &out, Stderr: &errb})
		if err != nil {
			t.Fatal(err)
		}
		dir := task.Workdir()
		if err := task.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		_, _ = task.Wait()
		if err := task.Cleanup(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: task directory left after the task: %v", mode, err)
		}
		return strings.TrimSpace(out.String()), dir
	}
	// Job A writes a secret in its directory, then fails.
	outA, dirA := run("write", "secret.txt")
	if outA != "OK" {
		t.Fatalf("job A could not write its own directory: %q", outA)
	}
	_, _ = run("read", filepath.Join(os.TempDir(), "does-not-exist")) // a failing task
	// Job B tries A's directory (gone) and the task root listing.
	if out, _ := run("read", filepath.Join(dirA, "secret.txt")); out == "OK" {
		t.Error("job B read job A's file")
	}
	if out, _ := run("list", b.cfg.WorkRoot); out == "OK" {
		t.Error("job B listed the task root")
	}
}
