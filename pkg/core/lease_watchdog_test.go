package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestLeaseTTL(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name    string
		expires time.Time
		want    time.Duration
	}{
		{"no lease", time.Time{}, 0},
		{"three minutes", now.Add(3 * time.Minute), 3 * time.Minute},
		{"already past (clock ahead)", now.Add(-time.Minute), DefaultLeaseTTL},
		{"implausibly short", now.Add(5 * time.Second), DefaultLeaseTTL},
		{"implausibly long (clock behind)", now.Add(3 * time.Hour), DefaultLeaseTTL},
	} {
		if got := leaseTTL(c.expires, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if g := leaseGrace(3 * time.Minute); g != 45*time.Second {
		t.Errorf("grace of 3m = %s", g)
	}
	if g := leaseGrace(time.Minute); g != minLeaseGrace {
		t.Errorf("grace of 1m = %s", g)
	}
}

// An outage longer than the lease and its grace stops the job with
// ErrLeaseLost, marking it lost before it is stopped; a short outage, or a
// renewal in time, changes nothing; nothing stops before a heartbeat armed
// the watchdog.
func TestLeaseWatch_StopsOnlyAfterTheLeaseAndGrace(t *testing.T) {
	t0 := time.Now()
	var w leaseWatch
	ctxA, cancelA := context.WithCancelCause(context.Background())
	ctxB, cancelB := context.WithCancelCause(context.Background())
	defer cancelA(nil)
	defer cancelB(nil)
	w.track("a", t0.Add(3*time.Minute), t0, cancelA)
	w.track("b", t0.Add(3*time.Minute), t0, cancelB)
	w.track("no-lease", time.Time{}, t0, func(error) { t.Error("a job without a lease was stopped") })

	if got := w.expire(t0.Add(time.Hour), nil); len(got) != 0 {
		t.Fatalf("stopped %v before any heartbeat armed the watchdog", got)
	}
	w.renewed(t0.Add(time.Minute), []string{"b"})
	if got := w.expire(t0.Add(3*time.Minute+44*time.Second), nil); len(got) != 0 {
		t.Fatalf("stopped %v inside the grace", got)
	}
	var order []string
	var mu sync.Mutex
	got := w.expire(t0.Add(3*time.Minute+46*time.Second), func(id string) {
		mu.Lock()
		defer mu.Unlock()
		if context.Cause(ctxA) != nil {
			t.Error("the job was stopped before it was marked lost")
		}
		order = append(order, id)
	})
	if len(got) != 1 || got[0] != "a" || len(order) != 1 {
		t.Fatalf("stopped %v (marked %v), want only a", got, order)
	}
	if !errors.Is(context.Cause(ctxA), ErrLeaseLost) || context.Cause(ctxB) != nil || !w.lost("a") || w.lost("b") {
		t.Fatalf("causes a=%v b=%v", context.Cause(ctxA), context.Cause(ctxB))
	}
	// A late heartbeat never revives a lost lease; a lost job is stopped once.
	w.renewed(t0.Add(4*time.Minute), []string{"a"})
	if got := w.expire(t0.Add(time.Hour), nil); len(got) != 1 || got[0] != "b" {
		t.Fatalf("second expiry stopped %v, want only b", got)
	}
	w.untrack("a")
	if w.lost("a") {
		t.Fatal("an ended job is still tracked")
	}
}

// lossRecorder is a queueClient that records MarkLeaseLost.
type lossRecorder struct {
	*queueClient
	mu   sync.Mutex
	lost []string
}

func (r *lossRecorder) MarkLeaseLost(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lost = append(r.lost, id)
}

// The poller end to end: a held job whose lease is not renewed past its
// lease and grace is stopped, marked lost on the client, and neither
// reported nor released; a job whose lease the heartbeats renew keeps
// running.
func TestCommandPoller_LeaseWatchdog(t *testing.T) {
	lost := scanCmd("lost", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.9"})
	kept := scanCmd("kept", "normal", map[string]any{"scanner": "nuclei", "target": "203.0.113.10"})
	lost.LeaseExpiresAt = time.Now().Add(3 * time.Minute)
	kept.LeaseExpiresAt = time.Now().Add(3 * time.Minute)
	c := &lossRecorder{queueClient: newQueueClient(lost, kept)}
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 4})
	p.pollAndExecute(context.Background())
	for range 2 {
		select {
		case <-e.started:
		case <-time.After(5 * time.Second):
			t.Fatal("the commands did not start")
		}
	}

	// Heartbeats keep renewing "kept" only (as if "lost" had been dropped
	// from the answers); the clock moves past lost's lease and grace.
	start := time.Now()
	p.LeasesRenewed(start.Add(4*time.Minute), []string{"kept"})
	p.watchLeases(start.Add(4 * time.Minute))

	c.mu.Lock()
	marked := append([]string(nil), c.lost...)
	c.mu.Unlock()
	if len(marked) != 1 || marked[0] != "lost" {
		t.Fatalf("marked lost: %v, want [lost]", marked)
	}
	deadline := time.Now().Add(5 * time.Second)
	for p.ActiveJobs() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("active jobs %d, want 1 (the renewed one)", p.ActiveJobs())
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.queueClient.mu.Lock()
	if _, ok := c.results["lost"]; ok {
		t.Errorf("a job whose lease was lost reported a result: %q", c.results["lost"])
	}
	if _, ok := c.released["lost"]; ok {
		t.Error("a job whose lease was lost was released")
	}
	c.queueClient.mu.Unlock()

	close(e.release)
	p.activeCmds.Wait()
	c.queueClient.mu.Lock()
	defer c.queueClient.mu.Unlock()
	if c.results["kept"] != "completed" {
		t.Fatalf("the renewed job: %q, want completed", c.results["kept"])
	}
}

// renewObserver is a load reporter that holds two commands and records
// LeasesRenewed.
type renewObserver struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *renewObserver) ActiveJobs() int { return 2 }
func (r *renewObserver) MaxJobs() int    { return 4 }
func (r *renewObserver) ReportStatus(s *SensorStatus) {
	s.RunningCommands = []string{"c1", "c2"}
}
func (r *renewObserver) LeasesRenewed(_ time.Time, ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string(nil), ids...))
}

// An answered heartbeat tells the poller which leases it renewed (the ids
// it carried as running).
func TestBaseSensor_AnsweredHeartbeatRenewsTheLeasesItListed(t *testing.T) {
	obs := &renewObserver{}
	p := &doorbellPusher{answer: func(int) *HeartbeatHints { return &HeartbeatHints{} }}
	s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Hour}, p)
	s.SetLoadReporter(obs)
	if _, err := s.heartbeatOnce(context.Background(), s.Status()); err != nil {
		t.Fatal(err)
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.calls) != 1 || len(obs.calls[0]) != 2 || obs.calls[0][0] != "c1" || obs.calls[0][1] != "c2" {
		t.Fatalf("renewals %v, want one with [c1 c2]", obs.calls)
	}
}
