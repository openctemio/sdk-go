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
	if got := p.Snapshot(); got != (CommandProgress{Done: 2, Total: 3}) {
		t.Fatalf("got %+v", got)
	}
	// A tool (or a bug) reporting more targets than the job has never
	// reports more than the total.
	p.TargetDone("c")
	p.TargetDone("d")
	p.DoneN(5)
	if got := p.Snapshot(); got != (CommandProgress{Done: 3, Total: 3}) {
		t.Fatalf("over the total: %+v", got)
	}
	var nilP *Progress
	nilP.TargetDone("x")
	nilP.DoneN(1)
	nilP.SetTotal(4)
	if nilP.Snapshot() != (CommandProgress{}) {
		t.Fatal("nil progress counts nothing")
	}
}

func TestProgressInContext(t *testing.T) {
	TargetDone(context.Background(), "outside a job") // no panic
	p := NewProgress(0)
	ctx := WithProgress(context.Background(), p)
	ProgressFrom(ctx).SetTotal(2)
	TargetDone(ctx, "a")
	if got := p.Snapshot(); got != (CommandProgress{Done: 1, Total: 2}) {
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
	if len(got) != 1 || got["c1"] != (CommandProgress{Done: 1, Total: 4}) {
		t.Fatalf("got %+v", got)
	}
	q.forget("c1")
	if q.progress() != nil {
		t.Fatal("a forgotten command is not reported")
	}
}
