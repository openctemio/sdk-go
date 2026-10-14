package core

import (
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProgress_LivenessCounters(t *testing.T) {
	p := NewProgress(3)
	p.RecordOutput(2, 300)
	p.RecordOutput(0, 0)
	p.RecordOutput(-5, -1) // never goes down
	got := p.Snapshot()
	if got.Records != 2 || got.OutputBytes != 300 {
		t.Fatalf("snapshot %+v", got)
	}
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), `"records":2`) || !strings.Contains(string(b), `"output_bytes":300`) {
		t.Fatalf("json %s", b)
	}
	// Counters a sensor never moved are left out of the heartbeat.
	b, _ = json.Marshal(NewProgress(1).Snapshot())
	if strings.Contains(string(b), "records") || strings.Contains(string(b), "cpu_ms") {
		t.Fatalf("json %s", b)
	}
	var nilP *Progress
	nilP.RecordOutput(1, 1)
	nilP.TrackProcess(1)
}

// The CPU time of a tracked process and of what it starts counts, and is
// kept after the process exits.
func TestProgress_TrackedProcessCPU(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process CPU time is read on Linux")
	}
	p := NewProgress(1)
	// A shell whose child burns CPU for a while.
	cmd := exec.Command("sh", "-c", `sh -c 'i=0; end=$(( $(date +%s) + 2 )); while [ $(date +%s) -lt $end ]; do i=$((i+1)); done' & wait`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p.TrackProcess(cmd.Process.Pid)
	time.Sleep(1200 * time.Millisecond)
	mid := p.Snapshot().CPUMs
	if mid <= 0 {
		_ = cmd.Process.Kill()
		t.Fatalf("no CPU time from the tracked process tree while it ran")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	after := p.Snapshot().CPUMs
	if after < mid {
		t.Fatalf("CPU time went down after the process exited: %d -> %d", mid, after)
	}
	if again := p.Snapshot().CPUMs; again != after {
		t.Fatalf("CPU time moved with nothing running: %d -> %d", after, again)
	}
}
