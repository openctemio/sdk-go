package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"time"
)

// Deliverer sends one item to the platform. Its returned error classifies
// the outcome:
//
//   - nil: acknowledged (2xx). The item is deleted; value is passed to the
//     item's Ticket.
//   - an error wrapping *PermanentError (see Permanent): refused for good
//     (400, 409, 413 after splitting, 415, 422 ...). The item moves to the
//     dead-letter folder with the reason; it is never retried by itself.
//   - an error wrapping *AuthError (see Unauthorized): the platform rejected
//     the credentials (401). All delivery pauses until Wake or Resume; the
//     attempt is not counted against the item.
//   - an error wrapping *RetryError (see RetryAfter): transient with a
//     server-advised delay (429/503 Retry-After).
//   - any other error: transient (network, 5xx). Exponential back-off with
//     jitter; consecutive ones open the circuit.
type Deliverer interface {
	Deliver(ctx context.Context, d *Delivery) (value any, err error)
}

// DelivererFunc adapts a function to Deliverer.
type DelivererFunc func(ctx context.Context, d *Delivery) (any, error)

// Deliver implements Deliverer.
func (f DelivererFunc) Deliver(ctx context.Context, d *Delivery) (any, error) { return f(ctx, d) }

// Delivery is one attempt at one item.
type Delivery struct {
	Meta    Meta
	Payload []byte
	// State is the item's state before this attempt (Attempts counts earlier
	// attempts).
	State State

	o *Outbox
	e *entry
}

// SaveProgress persists deliverer-owned progress (for example which v2
// segments were acknowledged) so a restart resumes instead of starting over.
// It is crash-safe like every outbox write.
func (d *Delivery) SaveProgress(progress json.RawMessage) error {
	d.o.mu.Lock()
	defer d.o.mu.Unlock()
	if _, ok := d.o.entries[d.Meta.ID]; !ok {
		return fmt.Errorf("outbox: item %s is gone", d.Meta.ID)
	}
	d.e.state.Progress = append(json.RawMessage(nil), progress...)
	d.State.Progress = d.e.state.Progress
	return d.o.writeState(d.o.pendingDir, d.e)
}

// Outbox returns the outbox the item belongs to (for DeadLetterForCommand).
func (d *Delivery) Outbox() *Outbox { return d.o }

// PermanentError is a refusal that retrying cannot fix.
type PermanentError struct {
	Status  int
	Reason  string
	Problem json.RawMessage
	Err     error
}

func (e *PermanentError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("refused (HTTP %d): %s", e.Status, e.Reason)
	}
	return "refused: " + e.Reason
}

func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent classifies a refusal as permanent. problem is the server's RFC
// 9457 document, if any.
func Permanent(status int, reason string, problem []byte, err error) error {
	return &PermanentError{Status: status, Reason: reason, Problem: problem, Err: err}
}

// AuthError is a rejection of the credentials.
type AuthError struct{ Err error }

func (e *AuthError) Error() string { return "credentials rejected: " + e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

// Unauthorized classifies err as a credentials rejection.
func Unauthorized(err error) error { return &AuthError{Err: err} }

// RetryError is a transient failure with a server-advised delay.
type RetryError struct {
	After time.Duration
	Err   error
}

func (e *RetryError) Error() string {
	return fmt.Sprintf("retry after %s: %v", e.After, e.Err)
}
func (e *RetryError) Unwrap() error { return e.Err }

// RetryAfter classifies err as transient, to be retried no sooner than after.
func RetryAfter(err error, after time.Duration) error {
	return &RetryError{After: after, Err: err}
}

// Wake says the platform is reachable again (a heartbeat was accepted): the
// circuit closes, an authentication pause lifts and every item backing off
// after a network or server error becomes ready now. Items told to wait by a
// Retry-After keep their delay.
func (o *Outbox) Wake() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.resumeLocked("the platform answered a heartbeat")
	now := o.cfg.now()
	if o.circuitUntil.After(now) {
		o.cfg.Logf("platform reachable again: delivering the queue now")
	}
	o.circuitUntil = time.Time{}
	o.consecutiveFail = 0
	for _, e := range o.entries {
		if e.dead == nil && !e.state.RateLimited && e.state.NextAttempt.After(now) {
			e.state.NextAttempt = time.Time{}
		}
	}
	o.signalLocked()
}

// Resume lifts an authentication pause (the API key was replaced).
func (o *Outbox) Resume() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.resumeLocked("the API key was replaced")
	o.signalLocked()
}

func (o *Outbox) resumeLocked(why string) {
	if o.authPaused {
		o.authPaused = false
		o.authErr = ""
		o.cfg.Logf("delivery resumed: %s", why)
	}
}

// readyLocked reports whether e may be attempted at now (its own back-off and
// dependencies; not the global pause and circuit).
func (o *Outbox) readyLocked(e *entry, now time.Time) bool {
	if e.dead != nil || e.inflight || e.state.NextAttempt.After(now) {
		return false
	}
	if e.meta.Kind == KindCommandResult && e.meta.CommandID != "" {
		// A command is reported only after every older result of it was
		// acknowledged (or dead-lettered).
		for _, other := range o.entries {
			if other != e && other.dead == nil && other.meta.Kind != KindCommandResult &&
				other.meta.CommandID == e.meta.CommandID {
				return false
			}
		}
	}
	return true
}

// next picks the oldest ready item and marks it in flight, or returns the
// time to wait for (zero: wait for a change).
func (o *Outbox) nextLocked(now time.Time) (*entry, time.Time) {
	if o.closed || o.authPaused {
		return nil, time.Time{}
	}
	if now.Before(o.circuitUntil) {
		return nil, o.circuitUntil
	}
	var wake time.Time
	for _, e := range o.sortedLocked(func(e *entry) bool { return e.dead == nil && !e.inflight }) {
		if o.readyLocked(e, now) {
			e.inflight = true
			return e, time.Time{}
		}
		if t := e.state.NextAttempt; t.After(now) && (wake.IsZero() || t.Before(wake)) {
			wake = t
		}
	}
	return nil, wake
}

// Run delivers items with d until ctx ends: oldest first, Concurrency at a
// time. Call it once per outbox.
func (o *Outbox) Run(ctx context.Context, d Deliverer) error {
	done := make(chan struct{})
	for range o.cfg.Concurrency {
		go func() {
			defer func() { done <- struct{}{} }()
			o.worker(ctx, d)
		}()
	}
	housekeep := time.NewTicker(time.Minute)
	defer housekeep.Stop()
	running := o.cfg.Concurrency
	for running > 0 {
		select {
		case <-done:
			running--
		case <-housekeep.C:
			o.mu.Lock()
			evicted, reason := o.enforceCapsLocked(0)
			o.mu.Unlock()
			o.notifyEvicted(evicted, reason)
			o.trimCorrupt()
		}
	}
	return ctx.Err()
}

func (o *Outbox) worker(ctx context.Context, d Deliverer) {
	for {
		o.mu.Lock()
		e, wake := o.nextLocked(o.cfg.now())
		ch := o.changed
		closed := o.closed
		o.mu.Unlock()
		if closed || ctx.Err() != nil {
			if e != nil {
				o.mu.Lock()
				e.inflight = false
				o.mu.Unlock()
			}
			return
		}
		if e == nil {
			var timer <-chan time.Time
			if !wake.IsZero() {
				t := time.NewTimer(time.Until(wake))
				timer = t.C
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-ch:
					t.Stop()
				case <-timer:
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-ch:
			}
			continue
		}
		o.attempt(ctx, d, e)
	}
}

// attempt delivers one in-flight entry and records the outcome.
func (o *Outbox) attempt(ctx context.Context, d Deliverer, e *entry) {
	payload, err := o.readPayload(e)
	if err != nil {
		o.mu.Lock()
		o.cfg.Logf("item %s became unreadable (%v): quarantined", e.meta.ID, err)
		o.quarantine(filepath.Join(o.pendingDir, e.meta.ID+itemExt), "")
		o.quarantine(filepath.Join(o.pendingDir, e.meta.ID+stateExt), "")
		delete(o.entries, e.meta.ID)
		o.finishLocked(e.meta.ID, Result{Evicted: true})
		o.signalLocked()
		o.mu.Unlock()
		return
	}
	o.mu.Lock()
	del := &Delivery{Meta: e.meta, Payload: payload, State: e.state, o: o, e: e}
	o.attempts++
	o.mu.Unlock()

	value, derr := safeDeliver(ctx, d, del)

	o.mu.Lock()
	defer o.mu.Unlock()
	e.inflight = false
	defer o.signalLocked()
	if _, still := o.entries[e.meta.ID]; !still {
		return // evicted meanwhile is impossible (in flight), but be safe
	}
	now := o.cfg.now()
	var perm *PermanentError
	var auth *AuthError
	var retry *RetryError
	switch {
	case derr == nil:
		_ = removeFiles(filepath.Join(o.pendingDir, e.meta.ID+itemExt), filepath.Join(o.pendingDir, e.meta.ID+stateExt))
		delete(o.entries, e.meta.ID)
		o.delivered++
		o.consecutiveFail = 0
		o.circuitUntil = time.Time{}
		o.finishLocked(e.meta.ID, Result{Delivered: true, Value: value})
	case ctx.Err() != nil:
		// Shutting down mid-attempt: nothing is known; try again next run.
	case errors.As(derr, &perm):
		o.deadLetterLocked(e, perm, now)
	case errors.As(derr, &auth):
		if !o.authPaused {
			o.cfg.Logf("delivery paused: the platform rejected the API key (%v). %d item(s) wait; delivery resumes when a heartbeat is accepted or the key is replaced",
				auth.Err, o.pendingCountLocked())
		}
		o.authPaused = true
		o.authErr = auth.Err.Error()
	default:
		e.state.Attempts++
		e.state.LastError = truncate(derr.Error(), 512)
		delay := o.backoff(e.state.Attempts)
		e.state.RateLimited = false
		if errors.As(derr, &retry) {
			after := min(max(retry.After, 0), maxRetryAfter)
			if after > delay {
				delay = after
			}
			e.state.RateLimited = true
		} else {
			o.consecutiveFail++
			if o.consecutiveFail >= o.cfg.CircuitThreshold {
				cool := o.backoff(o.consecutiveFail - o.cfg.CircuitThreshold + 1)
				if !now.Before(o.circuitUntil) {
					o.cfg.Logf("cannot deliver (%d consecutive failures, last: %s): pausing %s; %d item(s) wait and are delivered as soon as the platform answers a heartbeat",
						o.consecutiveFail, e.state.LastError, cool.Round(time.Second), o.pendingCountLocked())
				}
				o.circuitUntil = now.Add(cool)
			}
		}
		e.state.NextAttempt = now.Add(delay)
		if err := o.writeState(o.pendingDir, e); err != nil {
			o.cfg.Logf("item %s: state not written: %v", e.meta.ID, err)
		}
	}
}

func safeDeliver(ctx context.Context, d Deliverer, del *Delivery) (v any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("deliverer panicked: %v", r)
		}
	}()
	return d.Deliver(ctx, del)
}

func (o *Outbox) pendingCountLocked() int {
	n := 0
	for _, e := range o.entries {
		if e.dead == nil {
			n++
		}
	}
	return n
}

// deadLetterLocked moves e to dead/ with its reason.
func (o *Outbox) deadLetterLocked(e *entry, perm *PermanentError, now time.Time) {
	dl := &DeadLetter{
		Meta:     e.meta,
		DeadAt:   now.UTC(),
		Status:   perm.Status,
		Reason:   truncate(perm.Reason, 1024),
		Attempts: e.state.Attempts + 1,
	}
	if len(perm.Problem) > 0 && json.Valid(perm.Problem) && len(perm.Problem) <= 64<<10 {
		dl.Problem = append(json.RawMessage(nil), perm.Problem...)
	}
	reason, _ := json.MarshalIndent(dl, "", "  ")
	if err := writeAtomic(o.tmpDir, o.deadDir, e.meta.ID+reasonExt, reason); err != nil {
		o.cfg.Logf("item %s: dead-letter reason not written: %v", e.meta.ID, err)
	}
	e.state.Attempts++
	e.state.LastError = dl.Reason
	if err := o.writeState(o.deadDir, e); err != nil {
		o.cfg.Logf("item %s: dead-letter state not written: %v", e.meta.ID, err)
	}
	if err := renameSync(filepath.Join(o.pendingDir, e.meta.ID+itemExt), filepath.Join(o.deadDir, e.meta.ID+itemExt)); err != nil {
		o.cfg.Logf("item %s: cannot move to the dead-letter folder: %v", e.meta.ID, err)
	}
	_ = removeFiles(filepath.Join(o.pendingDir, e.meta.ID+stateExt))
	e.dead = dl
	o.deadLetters++
	o.cfg.Logf("item %s (%s, report %s) refused by the platform and moved to %s: %s",
		e.meta.ID, e.meta.Kind, e.meta.ReportID, o.deadDir, perm.Error())
	o.finishLocked(e.meta.ID, Result{Dead: dl})
	if cb := o.cfg.OnDeadLetter; cb != nil {
		go cb(*dl)
	}
}

func renameSync(from, to string) error {
	if err := osRename(from, to); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(to)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(from))
}

// backoff is the jittered exponential delay for the n-th failure.
func (o *Outbox) backoff(n int) time.Duration {
	d := o.cfg.BackoffBase
	for i := 1; i < n && d < o.cfg.BackoffMax; i++ {
		d *= 2
	}
	d = min(d, o.cfg.BackoffMax)
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1)) //nolint:gosec // jitter, not a secret
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
