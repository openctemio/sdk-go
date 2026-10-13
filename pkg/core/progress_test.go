package core

import (
	"context"
	"testing"
	"time"
)

func TestProgressCountsEachTargetOnceAndIsBounded(t *testing.T) {
	p := NewProgress(3)
	p.TargetDone("a")
	p.TargetDone("a")
	p.TargetDone("b")
	if got := p.Snapshot(); !sameCounts(got, CommandProgress{Done: 2, Total: 3}) {
		t.Fatalf("got %+v", got)
	}
	// A tool (or a bug) reporting more targets than the job has never
	// reports more than the total.
	p.TargetDone("c")
	p.TargetDone("d")
	p.DoneN(5)
	if got := p.Snapshot(); !sameCounts(got, CommandProgress{Done: 3, Total: 3}) {
		t.Fatalf("over the total: %+v", got)
	}
	var nilP *Progress
	nilP.TargetDone("x")
	nilP.DoneN(1)
	nilP.SetTotal(4)
	if !sameCounts(nilP.Snapshot(), CommandProgress{}) {
		t.Fatal("nil progress counts nothing")
	}
}

func TestProgressInContext(t *testing.T) {
	TargetDone(context.Background(), "outside a job") // no panic
	p := NewProgress(0)
	ctx := WithProgress(context.Background(), p)
	ProgressFrom(ctx).SetTotal(2)
	TargetDone(ctx, "a")
	if got := p.Snapshot(); !sameCounts(got, CommandProgress{Done: 1, Total: 2}) {
		t.Fatalf("got %+v", got)
	}
}

func TestQueueReportsProgressOfHeldCommands(t *testing.T) {
	q := newLocalQueue()
	q.admit("c1", nil, 0, time.Now())
	q.admit("c2", nil, 0, time.Now())
	if q.progress() != nil {
		t.Fatal("no progress registered yet")
	}
	p := NewProgress(4)
	p.TargetDone("a")
	q.setProgress("c1", p)
	q.setProgress("c2", NewProgress(0)) // nothing known: not reported
	got := q.progress()
	if len(got) != 1 || !sameCounts(got["c1"], CommandProgress{Done: 1, Total: 4}) {
		t.Fatalf("got %+v", got)
	}
	q.forget("c1")
	if q.progress() != nil {
		t.Fatal("a forgotten command is not reported")
	}
}

// Finished targets are reported as merged index ranges into the job's list,
// so the platform can settle them one by one.
func TestProgressReportsFinishedIndexes(t *testing.T) {
	p := NewProgress(0)
	p.SetTargets([]string{"a", "b", "c", "d", "e", "f"})
	for _, x := range []string{"a", "b", "d", "f", "f", "unknown"} {
		p.TargetDone(x)
	}
	got := p.Snapshot()
	if got.Done != 5 || got.Total != 6 {
		t.Fatalf("counts %+v", got)
	}
	want := [][2]int{{0, 1}, {3, 3}, {5, 5}}
	if len(got.Finished) != len(want) {
		t.Fatalf("finished %v, want %v", got.Finished, want)
	}
	for i := range want {
		if got.Finished[i] != want[i] {
			t.Fatalf("finished %v, want %v", got.Finished, want)
		}
	}

	// Too fragmented: counts only.
	targets := make([]string, 2*MaxProgressRanges+2)
	for i := range targets {
		targets[i] = string(rune(0x4e00 + i))
	}
	q := NewProgress(0)
	q.SetTargets(targets)
	for i := 0; i < len(targets); i += 2 {
		q.TargetDone(targets[i])
	}
	if s := q.Snapshot(); s.Finished != nil || s.Done != MaxProgressRanges+1 {
		t.Fatalf("fragmented: %+v ranges, done %d", len(s.Finished), s.Done)
	}
}

func sameCounts(a, b CommandProgress) bool { return a.Done == b.Done && a.Total == b.Total }
