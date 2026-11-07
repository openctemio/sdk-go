//go:build linux

package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A confined task runs in its own PID namespace: it cannot signal the
// sensor or another task (the same user outside the namespace), and
// nothing it starts outlives it, a process that left the task's process
// group included.
func TestConfinedTaskIsolatesProcesses(t *testing.T) {
	b := newConfinedBackend(t)
	// A process of the sensor's user outside the task (the sensor itself
	// may be PID 1 of its container, a number the task's own init has).
	other := exec.Command("/bin/sleep", "30")
	if err := other.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	if out, _ := runTool(t, b, TaskSpec{ID: "signal"}, "signal", strconv.Itoa(other.Process.Pid)); !strings.HasPrefix(out, "ERR") {
		t.Errorf("a task signaled a process of the sensor's user (pid %d): %q", other.Process.Pid, out)
	}

	marker := filepath.Join(t.TempDir(), "marker")
	out, _ := runTool(t, b, TaskSpec{ID: "escape", WritePaths: []string{filepath.Dir(marker)}}, "escape", marker)
	if out != "OK" {
		t.Fatalf("escape: %q", out)
	}
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Error("a process that left the task's process group outlived the task")
	}
}

// The launcher is the PID namespace's init: it reaps the task's orphans,
// so they never pile up as zombies (which count against the task's
// process limit).
func TestConfinedTaskOrphansAreReaped(t *testing.T) {
	b := newConfinedBackend(t)
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	out, _ := runTool(t, b, TaskSpec{ID: "orphans"}, "orphans", "20")
	if out != "ZOMBIES 0" {
		t.Errorf("orphans: %q, want none left as zombies", out)
	}
}
