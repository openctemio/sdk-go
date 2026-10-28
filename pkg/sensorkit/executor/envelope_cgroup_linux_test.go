//go:build linux

package executor

// The cgroup envelope on a real kernel (research/318 §6.2). It moves the
// test process into a leaf cgroup, so it runs only in a throwaway container
// where the test binary is alone in a writable cgroup
// (scripts/fault-injection.sh, OPENCTEM_CGROUP_ENVELOPE_TEST=1).

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEnvelopeHelperProcess is the task the envelope test starts.
func TestEnvelopeHelperProcess(t *testing.T) {
	switch os.Getenv("ENVELOPE_HELPER") {
	case "":
		t.Skip("helper")
	case "show":
		b, _ := os.ReadFile("/proc/self/cgroup")
		path := strings.TrimPrefix(strings.TrimSpace(string(b)), "0::")
		for _, f := range []string{"cpu.max", "memory.max", "pids.max", "cpu.weight"} {
			v, _ := os.ReadFile(filepath.Join("/sys/fs/cgroup", path, f))
			fmt.Printf("%s=%s\n", f, strings.TrimSpace(string(v)))
		}
		fmt.Printf("cgroup=%s\n", path)
		os.Exit(0)
	case "hog":
		var keep [][]byte
		for range 256 {
			b := make([]byte, 1<<20)
			for i := range b {
				b[i] = 1
			}
			keep = append(keep, b)
		}
		fmt.Println(len(keep))
		os.Exit(0)
	}
}

func TestCgroupEnvelope(t *testing.T) {
	if os.Getenv("OPENCTEM_CGROUP_ENVELOPE_TEST") != "1" {
		t.Skip("moves the process into a leaf cgroup: runs in a throwaway container (scripts/fault-injection.sh)")
	}
	mode, why := EnableEnvelopes()
	if mode != EnvelopeCgroup {
		t.Fatalf("envelope %s: %s", mode, why)
	}
	exe, _ := os.Executable()
	run := func(helper string, e *Envelope) (*Result, string) {
		var out bytes.Buffer
		task, err := Current().Prepare(TaskSpec{ID: "envelope-" + helper, Argv: []string{exe, "-test.run=TestEnvelopeHelperProcess"},
			Env: []string{"ENVELOPE_HELPER=" + helper}, Stdout: &out, Stderr: &out, Envelope: e})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = task.Cleanup() }()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := task.Start(ctx); err != nil {
			t.Fatal(err)
		}
		res, err := task.Wait()
		if err != nil {
			t.Fatal(err)
		}
		return res, out.String()
	}
	res, out := run("show", &Envelope{CPU: 0.5, MemoryMax: 128 << 20, Pids: 64})
	for _, want := range []string{"cpu.max=50000 100000", "memory.max=134217728", "pids.max=64", "cpu.weight=50", "/openctem-tasks/task-envelope-show-"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the task was not born in its envelope (%q missing):\n%s", want, out)
		}
	}
	if res.EnvelopeOOM || res.Sandbox.Envelope != EnvelopeCgroup {
		t.Fatalf("result %+v", res)
	}
	res, out = run("hog", &Envelope{MemoryMax: 64 << 20, Pids: 64})
	if !res.EnvelopeOOM {
		t.Fatalf("256 MiB in a 64 MiB envelope not reported as its OOM: exit %d %s", res.ExitCode, out)
	}
	entries, _ := os.ReadDir(currentTasksDir(t))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "task-envelope-") {
			t.Fatalf("task cgroup %s left behind", e.Name())
		}
	}
}

func currentTasksDir(t *testing.T) string {
	t.Helper()
	m, _ := currentEnvelopes()
	if m == nil {
		t.Fatal("no envelopes")
	}
	return m.tasks
}
