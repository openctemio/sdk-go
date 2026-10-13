package core

import (
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

// Bounds of the command poller's claim backoff.
//
// A poll that only hands commands back (their hosts are busy here, no slot
// is free, the type is not allowed) changes nothing, yet each hand-back
// returns the command to the queue, the platform rings the doorbell again
// and the same command comes straight back: a claim/release loop as fast as
// the round trip. After such a poll the poller waits before the next one,
// doubling the wait (with jitter) while the polls stay fruitless, and lets
// the platform give the command to another sensor meanwhile. A command
// that ends here (the busy host may be free now) or a poll that starts a
// command ends the backoff.
const (
	// MinClaimBackoff is the wait after the first fruitless poll.
	MinClaimBackoff = time.Second
	// MaxClaimBackoff caps the wait between fruitless polls.
	MaxClaimBackoff = time.Minute
	// MaxPollRetryAfter caps a Retry-After the platform sends on a refused
	// poll (429/503), so a broken or hostile answer cannot stop the sensor.
	MaxPollRetryAfter = 5 * time.Minute
)

// RetryAfterHinter is an error that carries the platform's advised wait
// before the next request (a Retry-After header, a retry_after_seconds
// field). The API clients' errors implement it.
type RetryAfterHinter interface {
	RetryAfterHint() time.Duration
}

// retryAfterOf is the platform's advised wait in err, 0 when none.
func retryAfterOf(err error) time.Duration {
	var h RetryAfterHinter
	if err == nil || !errors.As(err, &h) {
		return 0
	}
	return min(max(h.RetryAfterHint(), 0), MaxPollRetryAfter)
}

// claimBackoff holds when the poller may poll again. Safe for concurrent
// use: commands end on their own goroutines.
type claimBackoff struct {
	mu   sync.Mutex
	step time.Duration
	// churnUntil: no poll before it after a fruitless poll; a command that
	// ends lifts it.
	churnUntil time.Time
	// platformUntil: no poll before it (the platform's Retry-After); only
	// time lifts it.
	platformUntil time.Time
	now           func() time.Time
	jitter        func(time.Duration) time.Duration
}

func newClaimBackoff() *claimBackoff {
	return &claimBackoff{now: time.Now, jitter: func(d time.Duration) time.Duration {
		if d <= 0 {
			return 0
		}
		return rand.N(d) // #nosec G404 -- jitter only spreads polls, not a secret
	}}
}

// wait is how long the poller must still wait before polling (0: poll now).
func (b *claimBackoff) wait() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	until := b.churnUntil
	if b.platformUntil.After(until) {
		until = b.platformUntil
	}
	return max(until.Sub(b.now()), 0)
}

// fruitless records a poll that started nothing and handed commands back;
// it returns the wait before the next poll.
func (b *claimBackoff) fruitless() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.step == 0 {
		b.step = MinClaimBackoff
	} else {
		b.step = min(b.step*2, MaxClaimBackoff)
	}
	// Jitter of up to half the step, so sensors that handed back the same
	// commands do not come back in step.
	d := b.step + b.jitter(b.step/2)
	b.churnUntil = b.now().Add(d)
	return d
}

// progressed ends the churn backoff: a command started or ended.
func (b *claimBackoff) progressed() {
	b.mu.Lock()
	b.step, b.churnUntil = 0, time.Time{}
	b.mu.Unlock()
}

// retryAfter records the platform's advised wait before the next poll.
func (b *claimBackoff) retryAfter(d time.Duration) {
	if d <= 0 {
		return
	}
	b.mu.Lock()
	if t := b.now().Add(d); t.After(b.platformUntil) {
		b.platformUntil = t
	}
	b.mu.Unlock()
}
