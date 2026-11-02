package adapt

import (
	"context"
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// SourcePacer paces the requests to one system of record a collector or an
// importer reads: a production inventory API (vCenter), a directory (a
// domain controller), a monitoring or log server. Unlike a scan target,
// such a source is shared infrastructure the organization depends on, so
// the pacer slows down on the first sign of load, not only on errors:
//
//   - every request waits for the pacer's token bucket (Wait);
//   - each answer is reported with its latency (Observe): 429, 503 and busy
//     answers (with their Retry-After) and failures (timeouts, resets,
//     5xx) halve the rate at once, at most once per window;
//   - once per window the median latency is compared with the source's
//     baseline (its fastest normal): a median above SourcePace.LatencyFactor
//     times the baseline halves the rate, a clean window adds a tenth of
//     the ceiling (additive increase, multiplicative decrease);
//   - a Retry-After holds every request until it passes (capped at
//     SourcePace.RetryAfterMax).
//
// The rate never goes above the ceiling the caller gives (the lowest of the
// limits a human or a policy set; Ceiling) and never below SourcePace.Floor
// (or the ceiling, when that is lower). One pacer serves every caller that
// reads the same source: it is safe for concurrent use.
type SourcePacer struct {
	b       SourcePaceBounds
	ceiling float64
	floor   float64

	// now is replaced in tests.
	now func() time.Time
	// OnChange, when set, receives every rate change (called without the
	// pacer's lock held).
	OnChange func(SourceChange)

	mu          sync.Mutex
	lim         *rate.Limiter
	rate        float64
	baseline    time.Duration
	windowStart time.Time
	samples     []time.Duration
	pushedBack  bool // the window already decreased
	notBefore   time.Time
}

// SourceSignal is what one answer said about the source.
type SourceSignal int

const (
	// SourceAnswered: the source answered (an application error such as
	// "no permission" included: it says nothing about load).
	SourceAnswered SourceSignal = iota + 1
	// SourceBusy: 429, 503 or a busy fault; RetryAfter when the source
	// sent one.
	SourceBusy
	// SourceFailed: a timeout, a reset or a server error.
	SourceFailed
)

// SourceChange is one move of a source's rate.
type SourceChange struct {
	From, To float64
	// Reason is ReasonCleanRun, ReasonSlow, ReasonBusy, ReasonFailed or
	// ReasonRetryAfter.
	Reason string
}

// Reasons of a SourceChange (with ReasonCleanRun and ReasonRetryAfter).
const (
	ReasonSlow   = "slow_answers"
	ReasonBusy   = "busy"
	ReasonFailed = "failed"
)

// NewSourcePacer returns the pacer of one source with the given ceiling
// (requests per second; 0 or less: SourcePace.DefaultCeiling).
func NewSourcePacer(ceiling float64) *SourcePacer {
	b := SourcePace
	if ceiling <= 0 {
		ceiling = b.DefaultCeiling
	}
	floor := min(b.Floor, ceiling)
	start := max(floor, ceiling*b.StartFraction)
	p := &SourcePacer{b: b, ceiling: ceiling, floor: floor, now: time.Now, rate: start}
	p.lim = rate.NewLimiter(rate.Limit(start), 1)
	return p
}

// Ceiling is the rate the pacer never exceeds.
func (p *SourcePacer) Ceiling() float64 { return p.ceiling }

// Rate is the current rate.
func (p *SourcePacer) Rate() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rate
}

// Wait blocks until a request may start: after a Retry-After the source
// asked for, then for the token bucket. It returns ctx's error when ctx
// ends first.
func (p *SourcePacer) Wait(ctx context.Context) error {
	p.mu.Lock()
	var ch []SourceChange
	p.advance(p.now(), &ch)
	wait := p.notBefore.Sub(p.now())
	lim := p.lim
	p.mu.Unlock()
	p.emit(ch)
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	return lim.Wait(ctx)
}

// Observe reports one answer: its signal, how long it took, and the
// Retry-After the source sent (0: none).
func (p *SourcePacer) Observe(sig SourceSignal, latency, retryAfter time.Duration) {
	p.mu.Lock()
	now := p.now()
	var ch []SourceChange
	p.advance(now, &ch)
	switch sig {
	case SourceAnswered:
		if len(p.samples) < p.b.MaxSamples {
			p.samples = append(p.samples, latency)
		}
	case SourceBusy:
		if retryAfter > 0 {
			if nb := now.Add(min(retryAfter, p.b.RetryAfterMax)); nb.After(p.notBefore) {
				p.notBefore = nb
				ch = append(ch, SourceChange{From: p.rate, To: p.rate, Reason: ReasonRetryAfter})
			}
		}
		p.decrease(ReasonBusy, &ch)
	case SourceFailed:
		p.decrease(ReasonFailed, &ch)
	}
	p.mu.Unlock()
	p.emit(ch)
}

// advance closes the windows that ended: each window with enough answers
// and no push-back either raises the rate or, when its answers were slow,
// lowers it. Called with p.mu held.
func (p *SourcePacer) advance(now time.Time, ch *[]SourceChange) {
	if p.windowStart.IsZero() {
		p.windowStart = now
		return
	}
	if now.Sub(p.windowStart) < p.b.Window {
		return
	}
	if !p.pushedBack && len(p.samples) >= p.b.MinSamples {
		median := medianOf(p.samples)
		if p.baseline == 0 {
			p.baseline = median
		}
		if slowAt := max(p.b.LatencyFloor, time.Duration(float64(p.baseline)*p.b.LatencyFactor)); median > slowAt {
			p.decrease(ReasonSlow, ch)
		} else {
			p.set(min(p.ceiling, p.rate+p.ceiling*p.b.IncreaseFraction), ReasonCleanRun, ch)
		}
		if median < p.baseline {
			p.baseline = median
		} else {
			p.baseline += time.Duration(float64(median-p.baseline) * p.b.BaselineDrift)
		}
	}
	p.windowStart, p.samples, p.pushedBack = now, p.samples[:0], false
}

// decrease halves the rate, once per window. Called with p.mu held.
func (p *SourcePacer) decrease(reason string, ch *[]SourceChange) {
	if p.pushedBack {
		return
	}
	p.pushedBack = true
	p.set(max(p.floor, p.rate*p.b.DecreaseFactor), reason, ch)
}

func (p *SourcePacer) set(r float64, reason string, ch *[]SourceChange) {
	if r == p.rate {
		return
	}
	*ch = append(*ch, SourceChange{From: p.rate, To: r, Reason: reason})
	p.rate = r
	p.lim.SetLimit(rate.Limit(r))
}

func (p *SourcePacer) emit(ch []SourceChange) {
	if p.OnChange == nil {
		return
	}
	for _, c := range ch {
		p.OnChange(c)
	}
}

func medianOf(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[len(s)/2]
}
