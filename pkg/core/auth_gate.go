package core

import (
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Backoff after the platform rejects the sensor's API key. A rejected key does
// not start working by itself: the operator has to re-activate the sensor or
// give it a new key. Until then the sensor checks back rarely instead of
// sending a heartbeat and a poll every interval.
const (
	// DefaultAuthBackoffBase is the delay before the first re-check after a
	// rejected heartbeat. It doubles on every further rejection.
	DefaultAuthBackoffBase = 30 * time.Second
	// DefaultAuthBackoffMax caps the delay between re-checks.
	DefaultAuthBackoffMax = 10 * time.Minute
)

// httpStatusError is implemented by errors that carry an HTTP status, such as
// *client.HTTPError. pkg/core cannot import pkg/client, so it classifies
// errors through this interface.
type httpStatusError interface {
	HTTPStatusCode() int
}

// AuthFailureStatus returns the HTTP status (401 or 403) when err, or an error
// it wraps, says the platform rejected the sensor's credentials, and 0
// otherwise.
func AuthFailureStatus(err error) int {
	var se httpStatusError
	if errors.As(err, &se) {
		switch code := se.HTTPStatusCode(); code {
		case http.StatusUnauthorized, http.StatusForbidden:
			return code
		}
	}
	return 0
}

// keyNotReceivedMessage is the API's 401 message for a request that carried
// no API key at all.
const keyNotReceivedMessage = "API key required"

// AuthFailureAdvice explains a rejected request (AuthFailureStatus(err) != 0)
// in one actionable sentence: the HTTP status, the key's non-secret prefix
// (keyHint, see APIKeyHint) and what to do. A 401 saying "API key required"
// although the sensor sent its key means the key never reached the API:
// API_URL points at the web UI, or at a proxy that strips the Authorization
// header, rather than at the API.
func AuthFailureAdvice(err error, keyHint string) string {
	status := AuthFailureStatus(err)
	if status == http.StatusUnauthorized && strings.Contains(err.Error(), keyNotReceivedMessage) {
		return fmt.Sprintf("the platform answered HTTP 401 %q although the sensor sent its API key (%s): "+
			"the key never reached the API. API_URL probably points at the OpenCTEM web UI or at a proxy "+
			"that strips the Authorization header; set API_URL to the API host and restart the sensor",
			keyNotReceivedMessage, keyHint)
	}
	return fmt.Sprintf("the platform rejected the API key (HTTP %d, key %s): the key is wrong, revoked or expired, "+
		"or the sensor was disabled, deleted or given a new key. Create or regenerate a key under "+
		"Settings → Sensors, set API_KEY to it and restart the sensor", status, keyHint)
}

// APIKeyHint returns the non-secret prefix of an API key for log lines: at
// most 8 characters (e.g. "rda_" and 4 more) and never more than half of the
// key, followed by an ellipsis.
func APIKeyHint(key string) string {
	if key == "" {
		return "(none)"
	}
	n := min(8, len(key)/2)
	return key[:n] + "…"
}

// APIKeyHinter is implemented by a Pusher that can name its API key in log
// lines without revealing it (*client.Client does).
type APIKeyHinter interface {
	APIKeyHint() string
}

// AuthGateConfig configures an AuthGate. Zero values use the defaults.
type AuthGateConfig struct {
	// BackoffBase is the first re-check delay after a rejection.
	BackoffBase time.Duration
	// BackoffMax caps the re-check delay.
	BackoffMax time.Duration
	// Logger receives the state changes. Nil logs to stderr with timestamps.
	Logger *log.Logger
}

// AuthGate tracks whether the platform accepts the sensor's heartbeats. The
// heartbeat loop reports every outcome to it (Observe). While the key is
// rejected the gate turns the heartbeat interval into a capped exponential
// backoff and tells the command poller to stop polling (Rejected); the first
// accepted heartbeat lifts it. It logs without verbose mode, but only once
// per backoff step or change of state, never once per request. Safe for
// concurrent use.
type AuthGate struct {
	base, max time.Duration
	logf      func(format string, args ...any)
	jitter    func(d time.Duration) time.Duration

	mu          sync.Mutex
	rejected    bool
	step        int
	unreachable bool
	failures    int
}

// NewAuthGate creates an AuthGate. A nil config uses the defaults.
func NewAuthGate(cfg *AuthGateConfig) *AuthGate {
	if cfg == nil {
		cfg = &AuthGateConfig{}
	}
	g := &AuthGate{base: cfg.BackoffBase, max: cfg.BackoffMax}
	if g.base <= 0 {
		g.base = DefaultAuthBackoffBase
	}
	if g.max <= 0 {
		g.max = DefaultAuthBackoffMax
	}
	if g.max < g.base {
		g.max = g.base
	}
	lg := cfg.Logger
	if lg == nil {
		lg = log.New(os.Stderr, "", log.LstdFlags)
	}
	g.logf = func(format string, args ...any) { lg.Printf("[connection] "+format, args...) }
	g.jitter = func(d time.Duration) time.Duration {
		// ±20%, so many sensors rejected at once (e.g. a revoked shared
		// key) do not re-check in lockstep. Not security relevant.
		f := 0.8 + 0.4*rand.Float64() //nolint:gosec // jitter, not a secret
		return time.Duration(float64(d) * f)
	}
	return g
}

// Rejected reports whether the last heartbeat (or poll) was rejected for
// authentication. The command poller does not poll while it is true.
func (g *AuthGate) Rejected() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.rejected
}

// Observe records the outcome of one heartbeat (or, for a poller without a
// heartbeat to share a gate with, one poll). keyHint names the key in the
// log line (see APIKeyHint). It returns the delay before the next heartbeat
// when the gate overrides the normal interval (a rejected key), or 0 when the
// caller keeps its own interval.
func (g *AuthGate) Observe(err error, keyHint string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()

	if err == nil {
		if g.rejected {
			g.logf("platform accepted the API key again: heartbeats and job polling resumed")
		} else if g.unreachable {
			g.logf("platform reachable again after %d failed request(s)", g.failures)
		}
		g.rejected, g.step, g.unreachable, g.failures = false, 0, false, 0
		return 0
	}

	if status := AuthFailureStatus(err); status != 0 {
		g.unreachable, g.failures = false, 0
		g.rejected = true
		g.step++
		delay := g.delayFor(g.step)
		g.logf("%s. Not polling for jobs; next check in %s (attempt %d)",
			AuthFailureAdvice(err, keyHint), delay.Round(time.Second), g.step)
		return delay
	}

	// Network or server trouble: keep the normal interval (the platform may
	// be back any moment) but say so without verbose mode, on the first
	// failure and then at 2, 4, 8, ... consecutive failures.
	g.failures++
	if !g.unreachable {
		g.unreachable = true
		g.logf("cannot reach the platform: %v; retrying", err)
	} else if g.failures&(g.failures-1) == 0 {
		g.logf("platform still unreachable after %d attempts: %v", g.failures, err)
	}
	return 0
}

// MarkRejected records an authentication failure seen outside the heartbeat
// (a command poll). It stops polling until the next accepted heartbeat but
// leaves the backoff to the heartbeat loop. It logs only on the change of
// state.
func (g *AuthGate) MarkRejected(err error, keyHint string) {
	if AuthFailureStatus(err) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.rejected {
		return
	}
	g.rejected = true
	g.logf("%s. Not polling for jobs until a heartbeat is accepted", AuthFailureAdvice(err, keyHint))
}

// delayFor returns the jittered backoff for the n-th consecutive rejection.
func (g *AuthGate) delayFor(n int) time.Duration {
	d := g.base
	for i := 1; i < n && d < g.max; i++ {
		d *= 2
	}
	return min(g.jitter(min(d, g.max)), g.max)
}
