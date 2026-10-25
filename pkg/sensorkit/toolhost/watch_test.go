package toolhost

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func hostileRunWatch(t *testing.T, ctx context.Context, mode string, w core.RunWatch) (*Outcome, time.Duration) {
	t.Helper()
	exe, _ := os.Executable()
	m := hostileManifest
	m.Run = &tool.RunSpec{Argv: []string{exe}}
	start := time.Now()
	out, err := testHost(t).RunManifest(ctx, m, tool.Task{Targets: twoTargets}, RunOptions{Trusted: true, Watch: w,
		Env: map[string]string{"TOOLHOST_HOSTILE": mode}, Credentials: map[string]string{"api_key": "sk-declared-123"}})
	if err != nil {
		t.Fatal(err)
	}
	return out, time.Since(start)
}

// The incident (2026-10-25): the tool settled every target and then hung,
// heartbeating (so the idle timeout never fired) and ignoring a cancel. The
// watch stops it once the finish grace passed, kills it after the cancel
// grace, and the run delivers every target's results with an honest log
// line instead of waiting for the task timeout (24h for nuclei).
func TestWatchStopsAToolThatHangsAfterSettlingEveryTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, took := hostileRunWatch(t, ctx, "settle-all-then-hang", core.RunWatch{FinishGrace: 500 * time.Millisecond, Inactivity: -1})
	if took > 30*time.Second {
		t.Fatalf("took %s", took)
	}
	if out.Status != tool.StatusOK || out.Err != nil {
		t.Fatalf("status %s err %v (stderr %q)", out.Status, out.Err, out.Stderr)
	}
	if len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != "on t1" {
		t.Fatalf("findings %+v", out.Report.Findings)
	}
	if len(out.Unfinished) != 0 {
		t.Fatalf("unfinished %v", out.Unfinished)
	}
	logged := false
	for _, l := range out.Logs {
		logged = logged || l.Fields["watchdog"] == watchFinished
	}
	if !logged {
		t.Fatalf("no watchdog line in %+v", out.Logs)
	}
}

// A tool that sends nothing but heartbeats and uses no CPU is stopped as
// timed out after the inactivity window: what it settled is delivered as
// partial, the rest listed unfinished.
func TestWatchStopsAnInactiveTool(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process CPU time is read on Linux only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, took := hostileRunWatch(t, ctx, "settle-one-then-heartbeat", core.RunWatch{FinishGrace: -1, Inactivity: 1500 * time.Millisecond})
	if took > 20*time.Second {
		t.Fatalf("took %s", took)
	}
	if out.Status != tool.StatusPartial || out.Err == nil || out.Err.Class != tool.Timeout {
		t.Fatalf("status %s err %v (stderr %q)", out.Status, out.Err, out.Stderr)
	}
	if len(out.Unfinished) != 1 || out.Unfinished[0] != "b.example" {
		t.Fatalf("unfinished %v", out.Unfinished)
	}
}

// Without its watch (both checks off) a heartbeating tool is not stopped:
// the watch, not the heartbeat handling, ends the runs above.
func TestWatchOffLeavesAHeartbeatingToolRunning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	out, _ := hostileRunWatch(t, ctx, "settle-one-then-heartbeat", core.RunWatch{FinishGrace: -1, Inactivity: -1})
	// The job's own budget (the context deadline) stopped it.
	if out.Err == nil || out.Err.Detail != "the job's time budget ran out" {
		t.Fatalf("status %s err %v", out.Status, out.Err)
	}
}

// The watch of a run: the caller's fields, then the job's (from the
// context), then the defaults; negative turns a check off.
func TestWatchFor(t *testing.T) {
	got := watchFor(core.RunWatch{FinishGrace: time.Minute}, core.RunWatch{FinishGrace: time.Hour, Inactivity: 7 * time.Minute})
	if got.FinishGrace != time.Minute || got.Inactivity != 7*time.Minute {
		t.Fatalf("%+v", got)
	}
	got = watchFor(core.RunWatch{}, core.RunWatch{})
	if got.FinishGrace != core.DefaultFinishGrace || got.Inactivity != core.DefaultInactivity {
		t.Fatalf("defaults %+v", got)
	}
	got = watchFor(core.RunWatch{Inactivity: -1}, core.RunWatch{Inactivity: time.Minute})
	if got.Inactivity != 0 {
		t.Fatalf("off %+v", got)
	}
}
