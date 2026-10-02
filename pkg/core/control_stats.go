package core

import (
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

// ControlStats is how the sensor's control channel is doing, carried on
// every heartbeat as "control" (api RFC-035 §5.5). It tells a sensor that is
// busy but alive from one that is gone, and says where a late heartbeat lost
// its time: waiting for the CPU (lag), building the report (build) or on the
// way to the platform (rtt).
type ControlStats struct {
	// IntervalSeconds is the heartbeat interval the sensor follows now: the
	// platform's advice, else its own setting.
	IntervalSeconds float64 `json:"interval_s"`
	// GapSeconds is the time since the previous delivered heartbeat, when
	// this one is sent (0 on the first).
	GapSeconds float64 `json:"gap_s,omitempty"`
	// LagMs is how late this heartbeat started against its schedule: the
	// time the sensor waited for the CPU.
	LagMs int64 `json:"lag_ms"`
	// BuildMs is the time spent building this heartbeat's report (load
	// snapshot, tool inventory, manifest).
	BuildMs int64 `json:"build_ms"`
	// RTTMs is the round trip of the previous delivered heartbeat.
	RTTMs int64 `json:"rtt_ms,omitempty"`
	// Failures is the heartbeats that failed since the previous delivered
	// one.
	Failures int `json:"failures,omitempty"`
}

// Heartbeat timing (api RFC-035 §5.1).
const (
	// HeartbeatRetryDelay is the delay before the next heartbeat after one
	// that failed (not for a rejected key, which backs off): the heartbeat
	// is not retried with its stale report, the next one comes sooner. It
	// is jittered by ±20% so sensors cut off together do not come back in
	// step.
	HeartbeatRetryDelay = 10 * time.Second
	// manifestSyncTimeout bounds the manifest registration and policy read
	// a heartbeat may do before it is sent.
	manifestSyncTimeout = 15 * time.Second
)

// controlTracker measures the heartbeat loop for ControlStats.
type controlTracker struct {
	mu       sync.Mutex
	lastOK   time.Time
	lastRTT  time.Duration
	failures int
	lag      time.Duration
	interval time.Duration
}

// fired records how late the heartbeat timer fired against due.
func (c *controlTracker) fired(due, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lag = max(now.Sub(due), 0)
}

// stats is the ControlStats of a heartbeat sent at sent after build of
// building; interval is the one followed when none was delivered yet.
func (c *controlTracker) stats(sent time.Time, build, interval time.Duration) *ControlStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.interval > 0 {
		interval = c.interval
	}
	s := &ControlStats{
		IntervalSeconds: interval.Seconds(),
		LagMs:           c.lag.Milliseconds(),
		BuildMs:         build.Milliseconds(),
		RTTMs:           c.lastRTT.Milliseconds(),
		Failures:        c.failures,
	}
	if !c.lastOK.IsZero() {
		s.GapSeconds = math.Round(sent.Sub(c.lastOK).Seconds()*1000) / 1000
	}
	return s
}

// delivered records a heartbeat the platform answered; next is the interval
// followed from now on.
func (c *controlTracker) delivered(sent time.Time, rtt, next time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastOK, c.lastRTT, c.failures, c.lag = sent, rtt, 0, 0
	if next > 0 {
		c.interval = next
	}
}

// failed records a heartbeat that did not reach the platform.
func (c *controlTracker) failed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	c.lag = 0
}

// retryDelay is the delay before the heartbeat after a failed one: at most
// next, about HeartbeatRetryDelay.
func retryDelay(next time.Duration) time.Duration {
	d := HeartbeatRetryDelay
	d += time.Duration((rand.Float64()*0.4 - 0.2) * float64(d)) //nolint:gosec // jitter, not a secret
	return min(next, d)
}
