package core

// The per-job lease watchdog (api docs/architecture/sensor-platform-workflow.md,
// edge case "Network loss longer than the lease").
//
// A claimed job is held under a lease the platform renews on each heartbeat
// that lists the job as running. When the sensor cannot reach the platform,
// no heartbeat is answered, the lease runs out, and the platform re-queues
// the job for another sensor. Without a watchdog the first sensor would keep
// scanning: two sensors on the same targets, and a run whose results the
// platform refuses anyway.
//
// The watchdog keeps, per held job, the lease duration learned at the claim
// and when its lease was last renewed (the claim, then every answered
// heartbeat that listed it). When a job has gone longer than its lease plus
// a grace without a renewal, it is stopped with ErrLeaseLost: the poller
// neither reports nor releases it, and the client refuses to send its
// results (Client.MarkLeaseLost), bound or unbound.
//
// Every time is the sensor's own clock. Only a duration is taken from the
// platform (the lease's length at the claim), so clock skew between the
// two never decides a stop. The watchdog arms only once a heartbeat was
// observed, so a poller run without BaseSensor's heartbeat never stops jobs.

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrLeaseLost is the cause a job is stopped with when its lease could not
// be renewed for longer than the lease and its grace: the platform has
// handed it, or will hand it, to another sensor.
var ErrLeaseLost = errors.New("lease lost: the platform could not be reached to renew this job's lease for longer than the lease; it hands the job to another sensor")

// Lease watchdog bounds.
const (
	// DefaultLeaseTTL is the lease length assumed when the claim's lease
	// expiry gives none that is plausible (the platform default, 3 minutes).
	DefaultLeaseTTL = 3 * time.Minute
	minLeaseTTL     = 30 * time.Second
	maxLeaseTTL     = time.Hour
	// minLeaseGrace is the least time a job keeps running past its lease
	// without a renewal: the platform re-queues on a controller tick after
	// the expiry, and a heartbeat in flight may yet be answered.
	minLeaseGrace = 30 * time.Second
	// LeaseWatchInterval is how often held leases are checked.
	LeaseWatchInterval = 5 * time.Second
)

// LeaseRenewalObserver is told, after each answered heartbeat, which held
// commands that heartbeat listed (their leases were renewed). BaseSensor
// calls it on its load reporter; *CommandPoller implements it.
type LeaseRenewalObserver interface {
	LeasesRenewed(at time.Time, ids []string)
}

// LeaseLossRecorder is told when a job's lease is lost locally, so nothing
// of the job is sent afterwards. *client.Client implements it.
type LeaseLossRecorder interface {
	MarkLeaseLost(cmdID string)
}

type leaseJob struct {
	ttl     time.Duration
	renewed time.Time
	cancel  context.CancelCauseFunc
	lost    bool
}

// leaseWatch is the poller's table of held leases.
type leaseWatch struct {
	mu    sync.Mutex
	armed bool
	jobs  map[string]*leaseJob
}

// leaseTTL is the lease's length from its expiry as the platform stated it
// and the sensor's clock when the claim was answered. An expiry that is
// missing, already past or implausibly far (clock skew) gives
// DefaultLeaseTTL.
func leaseTTL(expires, claimedAt time.Time) time.Duration {
	if expires.IsZero() {
		return 0
	}
	d := expires.Sub(claimedAt)
	if d < minLeaseTTL || d > maxLeaseTTL {
		return DefaultLeaseTTL
	}
	return d
}

// leaseGrace is how long past its lease a job may run without a renewal.
func leaseGrace(ttl time.Duration) time.Duration {
	return max(minLeaseGrace, ttl/4)
}

// track starts watching a claimed job. A job without a lease expiry (a
// platform without leases) is not watched.
func (w *leaseWatch) track(id string, expires, claimedAt time.Time, cancel context.CancelCauseFunc) {
	ttl := leaseTTL(expires, claimedAt)
	if ttl <= 0 || id == "" || cancel == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.jobs == nil {
		w.jobs = map[string]*leaseJob{}
	}
	w.jobs[id] = &leaseJob{ttl: ttl, renewed: claimedAt, cancel: cancel}
}

// untrack stops watching a job (it ended).
func (w *leaseWatch) untrack(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.jobs, id)
}

// renewed records an answered heartbeat sent at at that listed ids. It arms
// the watchdog.
func (w *leaseWatch) renewed(at time.Time, ids []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.armed = true
	for _, id := range ids {
		if j, ok := w.jobs[id]; ok && !j.lost && at.After(j.renewed) {
			j.renewed = at
		}
	}
}

// expire stops every job whose lease ran out (plus its grace) without a
// renewal, and returns their ids. onLost runs for each before its job is
// stopped, so nothing the stop triggers can be sent first. Nothing is
// stopped before the first answered heartbeat.
func (w *leaseWatch) expire(now time.Time, onLost func(id string)) []string {
	w.mu.Lock()
	var out []string
	var stops []context.CancelCauseFunc
	if w.armed {
		for id, j := range w.jobs {
			if j.lost || now.Sub(j.renewed) <= j.ttl+leaseGrace(j.ttl) {
				continue
			}
			j.lost = true
			out = append(out, id)
			stops = append(stops, j.cancel)
		}
	}
	w.mu.Unlock()
	for i, id := range out {
		if onLost != nil {
			onLost(id)
		}
		stops[i](ErrLeaseLost)
	}
	return out
}

// lost reports whether the job's lease was lost here.
func (w *leaseWatch) lost(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	j, ok := w.jobs[id]
	return ok && j.lost
}
