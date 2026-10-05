package outbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// idempotentPlatform stands in for the platform's results endpoint: a
// report is stored once per report id; a second delivery of the same id is
// a replay (accepted, nothing stored again), which is what the v2 protocol
// does with the report id as idempotency key.
type idempotentPlatform struct {
	mu       sync.Mutex
	down     bool
	loseNext bool // process the next delivery, then lose the answer
	stored   map[string]string
	attempts int
}

func (p *idempotentPlatform) Deliver(_ context.Context, d *Delivery) (any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attempts++
	if p.down {
		return nil, errors.New("dial tcp: connection refused")
	}
	if _, dup := p.stored[d.Meta.ReportID]; !dup {
		p.stored[d.Meta.ReportID] = string(d.Payload)
	}
	if p.loseNext {
		p.loseNext = false
		return nil, errors.New("read tcp: connection reset by peer") // processed, answer lost
	}
	return "accepted", nil
}

// A one-hour platform outage with the default caps, a sensor restart in the
// middle, and an answer lost on the way back: every result is kept on disk
// (sealed), nothing is evicted or dead-lettered, and after recovery each one
// reaches the platform exactly once (its report id is stable across retries
// and the restart, so the lost answer's retry is a replay).
func TestOneHourOutageDeliversEachResultExactlyOnce(t *testing.T) {
	// Real time plus a jump: the outage lasts an hour of the outbox's clock.
	var clockMu sync.Mutex
	var offset time.Duration
	clock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return time.Now().Add(offset) }
	advance := func(d time.Duration) { clockMu.Lock(); offset += d; clockMu.Unlock() }
	dir := t.TempDir()
	// Default MaxBytes, MaxAge (7 days) and back-off ceiling; a short base
	// keeps the test fast.
	mod := func(c *Config) { c.now = clock; c.BackoffBase = 5 * time.Millisecond; c.BackoffMax = 20 * time.Millisecond }

	p := &idempotentPlatform{down: true, stored: map[string]string{}}
	o := openTest(t, dir, mod)
	ids := map[string]bool{}
	for i := range 5 {
		tk, err := o.Enqueue(Meta{Kind: KindReport}, fmt.Appendf(nil, "report-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		ids[tk.Meta.ReportID] = true
	}
	stop := runFor(t, o, p)
	// The circuit opens after a few refused attempts: nothing hammers the
	// platform while it is down.
	waitFor(t, func() bool { return o.Stats().CircuitOpen })
	stop()
	_ = o.Close() // the sensor restarts during the outage

	advance(61 * time.Minute)
	o2 := openTest(t, dir, mod)
	if st := o2.Stats(); st.PendingCount != 5 || st.Evicted != 0 || st.DeadLetterCount != 0 {
		t.Fatalf("after an hour down and a restart: %+v", st)
	}
	p.mu.Lock()
	p.down, p.loseNext = false, true
	p.mu.Unlock()
	stop2 := runFor(t, o2, p)
	defer stop2()
	o2.Wake() // the platform answered a heartbeat again
	deadline := time.Now().Add(5 * time.Second)
	for o2.Stats().PendingCount != 0 {
		if time.Now().After(deadline) {
			p.mu.Lock()
			t.Fatalf("not drained: %+v, platform attempts %d stored %d", o2.Stats(), p.attempts, len(p.stored))
		}
		time.Sleep(5 * time.Millisecond)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.stored) != 5 {
		t.Fatalf("stored %d reports, want 5", len(p.stored))
	}
	for id := range p.stored {
		if !ids[id] {
			t.Errorf("report id %s changed across the restart", id)
		}
	}
	if st := o2.Stats(); st.DeadLetterCount != 0 || st.Evicted != 0 {
		t.Fatalf("final stats %+v", st)
	}
}
