package adapt

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// GapThrottled: the host answered with rate limits (429 Too Many Requests,
// 503 Service Unavailable, or a Retry-After) in a tool's own output; what it
// answered there is the limit, not the application. The same reason string
// as pkg/webdiff's origin gap.
const GapThrottled = "throttled"

// ThrottleTally counts the push-back answers a tool's own output shows per
// target, for a tool that does its own networking in one run over a whole
// list (an HTTP probe sweep), where no per-request controller sits in the
// path. The run cannot slow down part-way, so the tally makes the push-back
// visible instead: each throttled target becomes a coverage gap (Gaps) and
// the longest Retry-After seen tells the caller how long to wait before the
// next run toward those hosts (RetryAfter).
//
// It keeps at most TargetRate.MaxHosts targets (further ones are counted in
// the total only) and is safe for concurrent use.
type ThrottleTally struct {
	mu         sync.Mutex
	hosts      map[string]*throttleCount
	order      []string
	total      int
	retryAfter time.Duration
}

type throttleCount struct {
	tooMany, unavailable int
	retryAfter           time.Duration
}

// IsThrottle reports whether an HTTP status is a rate-limit answer: 429, or
// 503 (overloaded or limiting). A Retry-After on any answer also counts
// (Observe).
func IsThrottle(status int) bool { return status == 429 || status == 503 }

// Observe records one answer from target: its HTTP status and its
// Retry-After (0 when absent; ParseRetryAfter reads the header). It reports
// whether the answer was a push-back. An empty target is ignored.
func (t *ThrottleTally) Observe(target string, status int, retryAfter time.Duration) bool {
	if target == "" || (!IsThrottle(status) && retryAfter <= 0) {
		return false
	}
	retryAfter = min(max(retryAfter, 0), TargetRate.RetryAfterMax)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.hosts == nil {
		t.hosts = map[string]*throttleCount{}
	}
	c, ok := t.hosts[target]
	if !ok {
		t.total++
		if len(t.hosts) >= TargetRate.MaxHosts {
			t.retryAfter = max(t.retryAfter, retryAfter)
			return true
		}
		c = &throttleCount{}
		t.hosts[target] = c
		t.order = append(t.order, target)
	}
	switch status {
	case 429:
		c.tooMany++
	case 503:
		c.unavailable++
	}
	c.retryAfter = max(c.retryAfter, retryAfter)
	t.retryAfter = max(t.retryAfter, retryAfter)
	return true
}

// Throttled reports whether target pushed back at least once.
func (t *ThrottleTally) Throttled(target string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.hosts[target]
	return ok
}

// Count is how many targets pushed back.
func (t *ThrottleTally) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

// RetryAfter is the longest Retry-After any target asked for (capped at
// TargetRate.RetryAfterMax; 0 when none did).
func (t *ThrottleTally) RetryAfter() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.retryAfter
}

// Gaps are the throttled targets as coverage gaps (GapThrottled; at most
// TargetRate.MaxGaps, in the order they were first seen) and how many there
// are in all. The detail counts the answers ("429=3 503=1 retry_after=30s");
// it never holds anything the target sent beyond those numbers.
func (t *ThrottleTally) Gaps() ([]Gap, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.total == 0 {
		return nil, 0
	}
	n := min(len(t.order), TargetRate.MaxGaps)
	gaps := make([]Gap, 0, n)
	for _, h := range t.order[:n] {
		gaps = append(gaps, Gap{Host: h, Reason: GapThrottled, Detail: t.hosts[h].detail()})
	}
	return gaps, t.total
}

// Summary counts the answers over every target: targets throttled, 429s,
// 503s and the longest Retry-After, for one log line per run.
func (t *ThrottleTally) Summary() (targets, tooMany, unavailable int, retryAfter time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.hosts {
		tooMany += c.tooMany
		unavailable += c.unavailable
	}
	return t.total, tooMany, unavailable, t.retryAfter
}

func (c *throttleCount) detail() string {
	var parts []string
	if c.tooMany > 0 {
		parts = append(parts, fmt.Sprintf("429=%d", c.tooMany))
	}
	if c.unavailable > 0 {
		parts = append(parts, fmt.Sprintf("503=%d", c.unavailable))
	}
	if c.retryAfter > 0 {
		parts = append(parts, fmt.Sprintf("retry_after=%s", c.retryAfter.Round(time.Second)))
	}
	return strings.Join(parts, " ")
}
