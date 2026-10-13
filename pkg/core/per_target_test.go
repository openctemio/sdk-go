package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/reach"
)

// One unresponsive host costs one target budget: 70 fast targets and 2 that
// never answer finish in about one budget, not 72 serial waits, the slow
// ones are reach timeouts and every finished target counts as progress.
func TestRunPerTargetBoundsEachTarget(t *testing.T) {
	targets := make([]string, 0, 72)
	for i := range 70 {
		targets = append(targets, "fast-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	targets = append(targets, "blackhole-1", "blackhole-2")

	rec := reach.NewRecorder()
	prog := NewProgress(len(targets))
	ctx := WithProgress(reach.WithRecorder(context.Background(), rec), prog)

	start := time.Now()
	out := RunPerTarget(ctx, targets, PerTargetOptions{Timeout: 200 * time.Millisecond, Concurrency: 8},
		func(ctx context.Context, target string) error {
			if target[:5] == "black" {
				<-ctx.Done()
				return ctx.Err()
			}
			time.Sleep(5 * time.Millisecond)
			return nil
		})
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("took %s: slow targets held the others up", took)
	}
	timedOut := 0
	for _, o := range out {
		switch {
		case o.TimedOut:
			timedOut++
			if !errors.Is(o.Err, context.DeadlineExceeded) {
				t.Errorf("%s: err %v", o.Target, o.Err)
			}
		case o.Err != nil || o.Skipped:
			t.Errorf("%s: unexpected outcome %+v", o.Target, o)
		}
	}
	if timedOut != 2 {
		t.Fatalf("timed out %d, want 2", timedOut)
	}
	if got := prog.Snapshot(); got.Done != 72 {
		t.Fatalf("progress %+v, want 72 done", got)
	}
	if rec.Empty() {
		t.Fatal("the timed out targets were not recorded as reach outcomes")
	}
}

// When the job's context ends, finished targets keep their outcome, running
// ones end with the job (not counted as their own timeout), and the rest are
// skipped, never started.
func TestRunPerTargetKeepsFinishedTargetsWhenTheJobEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var started atomic.Int32
	out := RunPerTarget(ctx, []string{"a", "b", "c", "d"}, PerTargetOptions{Timeout: time.Minute, Concurrency: 1},
		func(tctx context.Context, target string) error {
			started.Add(1)
			if target == "b" {
				cancel()
				<-tctx.Done()
				return tctx.Err()
			}
			return nil
		})
	if out[0].Err != nil || out[0].Skipped || out[0].TimedOut {
		t.Fatalf("a: %+v", out[0])
	}
	if out[1].TimedOut || !errors.Is(out[1].Err, context.Canceled) {
		t.Fatalf("b: %+v", out[1])
	}
	if !out[2].Skipped || !out[3].Skipped {
		t.Fatalf("c, d: %+v %+v", out[2], out[3])
	}
	if started.Load() != 2 {
		t.Fatalf("started %d targets, want 2", started.Load())
	}
}
