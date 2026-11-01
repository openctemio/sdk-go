package client

// Command lease epochs (api RFC-035 D6). A protocol v2 platform numbers the
// claims of a command (lease_epoch). The client keeps the epoch of the
// latest claim or start answer of each command it holds and echoes it in
// X-OpenCTEM-Lease-Epoch on complete and fail, so a sensor that lost the
// command (re-queued after its lease ran out and claimed again) cannot
// finish the new holder's run. Without a known epoch no header is sent and
// the platform fences by sensor and state, as before.

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// maxLeaseEntries bounds the epochs kept: a held command normally leaves
// the table on its complete, fail or release, but one the sensor never
// finishes (it crashed mid-way, the platform canceled it) would stay.
const maxLeaseEntries = 4096

type leaseEntry struct {
	epoch int
	at    time.Time
}

// leaseTable maps a command ID to the lease epoch it is held under, and
// keeps the commands whose lease was lost here (core lease watchdog).
type leaseTable struct {
	mu   sync.Mutex
	m    map[string]leaseEntry
	lost map[string]time.Time
}

// lostLeaseTTL is how long a lost command's results stay refused: longer
// than any outbox retry of them.
const lostLeaseTTL = 7 * 24 * time.Hour

// errLeaseLostResults is why the results of a lost job are not sent.
var errLeaseLostResults = errors.New("results not sent: the job's lease was lost while the platform could not be reached, and it was handed to another sensor")

// markLost records that cmdID's lease was lost here.
func (t *leaseTable) markLost(cmdID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.lost == nil {
		t.lost = map[string]time.Time{}
	}
	if len(t.lost) >= maxLeaseEntries {
		for id, at := range t.lost {
			if now.Sub(at) > lostLeaseTTL || len(t.lost) >= maxLeaseEntries {
				delete(t.lost, id)
			}
		}
	}
	t.lost[cmdID] = now
	delete(t.m, cmdID)
}

// isLost reports whether cmdID's lease was lost here.
func (t *leaseTable) isLost(cmdID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	at, ok := t.lost[cmdID]
	return ok && time.Since(at) <= lostLeaseTTL
}

// record keeps the epoch of a claim or start answer; an answer without one
// (a platform that predates leases) forgets what was known.
func (t *leaseTable) record(cmdID string, epoch int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if epoch <= 0 {
		delete(t.m, cmdID)
		return
	}
	if t.m == nil {
		t.m = map[string]leaseEntry{}
	}
	if _, ok := t.m[cmdID]; !ok && len(t.m) >= maxLeaseEntries {
		oldest, oldestAt := "", time.Time{}
		for id, e := range t.m {
			if oldest == "" || e.at.Before(oldestAt) {
				oldest, oldestAt = id, e.at
			}
		}
		delete(t.m, oldest)
	}
	t.m[cmdID] = leaseEntry{epoch: epoch, at: time.Now()}
}

// epoch is the epoch the command is held under; 0 when unknown.
func (t *leaseTable) epoch(cmdID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[cmdID].epoch
}

func (t *leaseTable) forget(cmdID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, cmdID)
}

// leaseHeader is the request header that echoes epoch; nil when unknown.
func leaseHeader(epoch int) http.Header {
	if epoch <= 0 {
		return nil
	}
	h := http.Header{}
	h.Set(protov2.HeaderLeaseEpoch, strconv.Itoa(epoch))
	return h
}

// leaseLostError says that a complete or fail sent under a lease epoch was
// refused because the command is no longer held under it. It unwraps to
// the platform's answer, so IsCommandGone and the error classifiers see the
// same thing as without the header.
type leaseLostError struct {
	epoch int
	err   error
}

func (e *leaseLostError) Error() string {
	return fmt.Sprintf("lease lost: the command is no longer held under lease epoch %d (re-queued and claimed again): %v", e.epoch, e.err)
}

func (e *leaseLostError) Unwrap() error { return e.err }

// leaseLost wraps err when it is the answer to a complete or fail sent
// under epoch that refuses it as no longer this sensor's: command-not-found
// (claimed by another sensor) or an invalid transition from a state the
// transition is allowed from (claimed again by this sensor). The platform
// does not name a lease loss in the problem, so this is the best reading.
func leaseLost(action string, epoch int, err error) error {
	if epoch <= 0 || err == nil {
		return err
	}
	var ce *controlError
	if !errors.As(err, &ce) || ce.v2.Problem == nil {
		return err
	}
	switch ce.problem() {
	case protov2.ProblemCommandNotFound:
	case protov2.ProblemInvalidTransition:
		state := ce.v2.Problem.State
		allowed := state == "running" || (action == protov2.FailAction && state == "acknowledged")
		if !allowed {
			return err
		}
	default:
		return err
	}
	return &leaseLostError{epoch: epoch, err: err}
}

// MarkLeaseLost records that the job cmdID lost its lease here (the sensor's
// lease watchdog stopped it): its results are not sent afterwards, bound or
// unbound, and nothing re-sends them. It implements core.LeaseLossRecorder.
func (c *Client) MarkLeaseLost(cmdID string) {
	if cmdID != "" {
		c.leases.markLost(cmdID)
	}
}
