package outbox

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A report the platform accepted (202) but has not processed stays in the
// outbox, survives a restart, no longer holds back its command's result,
// and leaves only on the deliverer's final answer.
func TestAcceptedItemIsKeptUntilFinal(t *testing.T) {
	dir := t.TempDir()
	var final atomic.Bool
	var reportCalls atomic.Int32
	order := make(chan string, 16)
	d := DelivererFunc(func(_ context.Context, dl *Delivery) (any, error) {
		order <- string(dl.Meta.Kind)
		if dl.Meta.Kind != KindReport {
			return "result", nil
		}
		reportCalls.Add(1)
		if !dl.State.Accepted {
			return nil, Accepted(10*time.Millisecond, "report r1 queued", "queued")
		}
		if final.Load() {
			return "completed", nil
		}
		return nil, Accepted(10*time.Millisecond, "report r1 processing", nil)
	})
	o := openTest(t, dir, nil)
	rep, _ := o.Enqueue(Meta{Kind: KindReport, CommandID: "cmd-1"}, []byte("findings"))
	res, _ := o.Enqueue(Meta{Kind: KindCommandResult, CommandID: "cmd-1"}, []byte("result"))
	stop := runFor(t, o, d)
	r := waitResult(t, rep)
	if !r.Delivered || !r.Accepted || r.Value != "queued" {
		t.Fatalf("report ticket = %+v, want delivered+accepted with the 202 value", r)
	}
	// The command result goes once the report is accepted, not processed.
	if rr := waitResult(t, res); !rr.Delivered || rr.Accepted {
		t.Fatalf("result ticket = %+v", rr)
	}
	time.Sleep(60 * time.Millisecond)
	stop()
	if st := o.Stats(); st.PendingCount != 1 || st.CircuitOpen {
		t.Fatalf("after acceptance: %+v, want the report kept and no circuit", st)
	}
	_ = o.Close()

	// A restart keeps it accepted; the final answer removes it.
	o2 := openTest(t, dir, nil)
	final.Store(true)
	stop2 := runFor(t, o2, d)
	deadline := time.Now().Add(5 * time.Second)
	for o2.Stats().PendingCount != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("accepted report never left: %+v", o2.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop2()
	if reportCalls.Load() < 2 {
		t.Fatalf("report offered %d times, want the 202 and a status check", reportCalls.Load())
	}
}

// Without the acceptance a pending report still holds back its command's
// result (unchanged).
func TestPendingReportStillHoldsBackResult(t *testing.T) {
	o := openTest(t, t.TempDir(), nil)
	var mu sync.Mutex
	var seen []Kind
	d := DelivererFunc(func(_ context.Context, dl *Delivery) (any, error) {
		mu.Lock()
		seen = append(seen, dl.Meta.Kind)
		mu.Unlock()
		if dl.Meta.Kind == KindReport {
			return nil, RetryAfter(context.DeadlineExceeded, time.Hour)
		}
		return nil, nil
	})
	_, _ = o.Enqueue(Meta{Kind: KindReport, CommandID: "cmd-1"}, []byte("findings"))
	_, _ = o.Enqueue(Meta{Kind: KindCommandResult, CommandID: "cmd-1"}, []byte("result"))
	stop := runFor(t, o, d)
	time.Sleep(80 * time.Millisecond)
	stop()
	mu.Lock()
	defer mu.Unlock()
	for _, k := range seen {
		if k == KindCommandResult {
			t.Fatal("the result went before its report was accepted")
		}
	}
}

// A refused report is kept as a dead letter: no byte cap, age cap or
// janitor purge deletes it; it holds the claim gate; only DiscardDead
// removes it.
func TestReportDeadLettersAreNeverEvicted(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	mod := func(c *Config) {
		c.now = func() time.Time { return now }
		c.MaxAge = time.Hour
		c.MaxBytes = 2500
		c.MaxDiskFraction = -1
	}
	o := openTest(t, dir, mod)
	dead, _ := o.Enqueue(Meta{Kind: KindReport, CommandID: "cmd-1"}, []byte(strings.Repeat("f", 900)))
	stop := runFor(t, o, &recorder{errs: func(*Delivery) error { return Permanent(422, "bad", nil, nil) }})
	if waitResult(t, dead).Dead == nil {
		t.Fatal("not dead-lettered")
	}
	stop()
	// Byte cap: new items do not evict it.
	for range 3 {
		_, _ = o.Enqueue(Meta{Kind: KindCommandLog}, []byte(strings.Repeat("l", 200)))
	}
	if o.Stats().DeadLetterCount != 1 {
		t.Fatal("the byte cap evicted a report dead letter")
	}
	// Age cap and janitor purge.
	now = now.Add(30 * 24 * time.Hour)
	if n, _ := o.PurgeDead(context.Background(), time.Hour, 0); n != 0 {
		t.Fatalf("PurgeDead removed %d report dead letter(s)", n)
	}
	_ = o.Close()
	o2 := openTest(t, dir, mod)
	if o2.Stats().DeadLetterCount != 1 {
		t.Fatal("the age cap deleted a report dead letter")
	}
	// It counts towards the claim gate.
	if o2.heldForTest() == 0 {
		t.Fatal("a report dead letter does not count towards the claim gate")
	}
	if err := o2.DiscardDead(dead.Meta.ID); err != nil {
		t.Fatal(err)
	}
	if o2.Stats().DeadLetterCount != 0 {
		t.Fatal("DiscardDead left it")
	}
	if err := o2.DiscardDead(dead.Meta.ID); err == nil {
		t.Fatal("DiscardDead of a missing item succeeded")
	}
}

// heldForTest is the bytes AcceptsWork counts as unacknowledged.
func (o *Outbox) heldForTest() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	var held int64
	for _, e := range o.entries {
		if (e.dead == nil && e.meta.Kind != KindCommandLog) || e.keptDead() {
			held += e.size()
		}
	}
	return held
}
