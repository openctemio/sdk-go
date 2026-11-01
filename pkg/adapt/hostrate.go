package adapt

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/ctis/edgeprotect"
)

// HostRate is one task's per-host rate controller: additive increase,
// multiplicative decrease (AIMD) on each destination host, with a breaker
// per host. Its state belongs to one task: a forwarder creates it and drops
// it with the task. A task that joins the sensor-wide SensorRate (Share)
// also shares the host's rate with the sensor's other tasks, and the
// Retry-After and edge-block cooldowns with its own tenant's tasks only:
// nothing a host taught one tenant's task reaches another tenant's.
//
// Signals: a connection or an answer is health; 429 and 503 (with their
// Retry-After) are congestion; a reset, a timeout, a refused connection on
// a port that answered before and a failed TLS handshake are failures; a run
// of 403 answers after other answers is a block. The rate never goes above
// the ceiling the caller gives (Ceiling of every limit) and never below
// TargetRate.Floor (or the ceiling, when that is lower).
//
// A host the controller cannot cover (the breaker refused connections to
// it, it kept pushing back at the floor, or it blocked the scan) is a
// coverage gap: the task completes and reports it (Gaps), it is not read
// as "no findings".
type HostRate struct {
	b       TargetRateBounds
	ceiling float64
	floor   float64

	// now and jitter are replaced in tests.
	now    func() time.Time
	jitter func() float64
	// OnChange, when set, receives every rate or breaker change (called
	// without the controller's lock held).
	OnChange func(Change)

	mu       sync.Mutex
	hosts    map[string]*hostState
	overflow *hostState

	// shared is the sensor-wide state the task joined (Share; nil: the
	// task paces itself alone), tenant the organization of its job.
	shared *SensorRate
	tenant string
}

// Share makes the task share target state with every other task of the
// sensor (SensorRate): the host's rate (fair share per tenant), the
// tenant's Retry-After and cooldowns. tenant is the organization of the
// task's job ("" on a sensor of one organization). Call it before the
// first Acquire.
func (c *HostRate) Share(s *SensorRate, tenant string) {
	c.mu.Lock()
	c.shared, c.tenant = s, tenant
	c.mu.Unlock()
}

// Signal is what one connection or answer said about its host.
type Signal int

const (
	// Connected: a connection was established.
	Connected Signal = iota + 1
	// Answered: the host answered (an HTTP response other than 403, 429
	// or 503, or a tunnel that ended cleanly after the host sent data).
	Answered
	// Congested: 429 or 503 (Event.RetryAfter set when the host sent one).
	Congested
	// Forbidden: a 403 answer.
	Forbidden
	// Failed: a reset, a timeout, a refused connection on a port that
	// answered before, or a failed TLS handshake (Event.Reason says which).
	Failed
)

// Event is one signal about a host.
type Event struct {
	Signal     Signal
	Reason     string
	RetryAfter time.Duration
	// Edge is the edge protection verdict of the answer (zero: none was
	// made). On a Forbidden event whose verdict stops the request (a
	// vendor challenge or block page) the host is a block from its first
	// answer: the vendor marker is evidence a bare 403 is not.
	Edge edgeprotect.Verdict
}

// Reasons of an Event and of a Change.
const (
	ReasonTimeout    = "timeout"
	ReasonReset      = "reset"
	ReasonRefused    = "refused"
	ReasonTLS        = "tls_handshake"
	ReasonHTTP429    = "http_429"
	ReasonHTTP503    = "http_503"
	ReasonBlocked    = "blocked"
	ReasonCleanRun   = "clean_window"
	ReasonSlowStart  = "slow_start"
	ReasonOpened     = "breaker_open"
	ReasonHalfOpen   = "breaker_half_open"
	ReasonClosed     = "breaker_closed"
	ReasonGaveUp     = "breaker_gave_up"
	ReasonRetryAfter = "retry_after"
)

// Gap reasons: why a host's coverage is incomplete.
const (
	// GapBreakerOpen: the host stopped answering and the breaker refused
	// connections to it (or gave it up).
	GapBreakerOpen = "breaker_open"
	// GapRateFloor: the host kept pushing back at the lowest rate, or asked
	// to wait longer than a connection can be held.
	GapRateFloor = "rate_floor"
	// GapBlocked: the host answered with a block (a run of 403s).
	GapBlocked = "blocked"
	// GapProxyUnavailable: the job's proxy pool could not carry a
	// connection toward the host (every endpoint down or refusing our
	// credentials, or the proxy's rules refused the destination), so part
	// of the host was never scanned. It says nothing about the host.
	GapProxyUnavailable = "proxy_unavailable"
)

// Gap is one host whose coverage is incomplete, and why.
type Gap struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
	// Edge and Vendor say that an edge protection (a WAF or CDN) stopped the
	// task: Edge is "challenged" or "blocked" (edgeprotect.State), Vendor the
	// vendor. Additive: older receivers ignore them and still see Reason
	// "blocked".
	Edge   string `json:"edge,omitempty"`
	Vendor string `json:"vendor,omitempty"`
	// Cause and Cert say what a recheck of a breaker_open host found
	// (pkg/tlsprobe): Cause is one of the GapCause values, Cert a problem of
	// the certificate the host served (GapCert values, "" when it is fine or
	// none was seen). Additive: older receivers ignore them and still see
	// Reason "breaker_open".
	Cause string `json:"cause,omitempty"`
	Cert  string `json:"cert,omitempty"`
}

// Gap causes: what a recheck of a host the breaker gave up found.
const (
	// GapCauseHTTPReset: the host accepts the connection (and completes the
	// TLS handshake) but resets or closes it on every HTTP request. The
	// host is up; it refuses the scanner's requests (it may block the
	// scanner's address, or its backend is down).
	GapCauseHTTPReset = "http_reset"
	// GapCauseReset: the host accepts connections, then resets them; which
	// layer (the TLS handshake or the HTTP request) was not seen.
	GapCauseReset = "reset"
	// GapCauseTLSFailed: the host accepts the connection but the TLS
	// handshake fails.
	GapCauseTLSFailed = "tls_failed"
	// GapCauseRefused: the host refuses the connection (the port is closed).
	GapCauseRefused = "refused"
	// GapCauseNoAnswer: no answer at all (filtered, down, or no path).
	GapCauseNoAnswer = "no_answer"
	// GapCauseAnswered: the host answered the recheck; it failed the tool's
	// requests only for a while.
	GapCauseAnswered = "answered"
)

// Certificate problems a recheck saw (Gap.Cert).
const (
	GapCertExpired      = "expired"
	GapCertNotYetValid  = "not_yet_valid"
	GapCertNameMismatch = "name_mismatch"
	GapCertSelfSigned   = "self_signed"
)

// Change is one move of a host's rate or breaker.
type Change struct {
	Host   string  `json:"host"`
	From   float64 `json:"from"`
	To     float64 `json:"to"`
	Reason string  `json:"reason"`
}

// Summary is a task's target-rate outcome, for its result and its log.
type Summary struct {
	Ceiling float64 `json:"ceiling"`
	Floor   float64 `json:"floor"`
	Start   float64 `json:"start"`
	// Min is the lowest rate any host reached; Final the lowest rate a
	// host ended at.
	Min   float64 `json:"min"`
	Final float64 `json:"final"`
	Hosts int     `json:"hosts"`
	// Throttled hosts were slowed at least once; Unreachable hosts were
	// given up by their breaker.
	Throttled   int `json:"hosts_throttled"`
	Unreachable int `json:"hosts_unreachable"`
	// Gaps lists at most TargetRate.MaxGaps hosts; GapsTotal counts all.
	Gaps      []Gap `json:"gaps,omitempty"`
	GapsTotal int   `json:"gaps_total,omitempty"`
}

// ErrHostUnavailable is the error of a connection the breaker refused.
var ErrHostUnavailable = errors.New("adapt: host is backed off")

type breaker int

const (
	closed breaker = iota
	open
	halfOpen
	down
)

type hostState struct {
	name      string
	lim       *rate.Limiter
	rate      float64
	ssthresh  float64
	slowStart bool

	windowEnd    time.Time
	lastDecrease time.Time
	oks, bad     int

	fails       int
	brk         breaker
	trips       int
	openUntil   time.Time
	probeAt     time.Time
	probing     bool
	notBefore   time.Time
	floorStrike int
	answered    bool
	run403      int
	openPorts   []int

	min       float64
	throttled bool
	gap       string
	gapDetail string
	gapEdge   string
	gapVendor string
	gapCause  string
	// tripReason is the failure reason of the breaker's last trip.
	tripReason string
}

// NewHostRate returns the controller of one task with the given ceiling
// (Ceiling of every limit that applies; zero or less: the default).
func NewHostRate(ceiling float64) *HostRate {
	b := TargetRate
	if ceiling <= 0 {
		ceiling = b.DefaultCeiling
	}
	return &HostRate{b: b, ceiling: ceiling, floor: math.Min(b.Floor, ceiling),
		now: time.Now, jitter: rand.Float64, hosts: map[string]*hostState{}}
}

// Ceiling is the rate the controller never exceeds.
func (c *HostRate) Ceiling() float64 { return c.ceiling }

func (c *HostRate) start() float64 {
	return math.Max(c.floor, c.ceiling*c.b.StartFraction)
}

// state returns host's state (created on first use; past MaxHosts every
// new host shares one state). Called with c.mu held.
func (c *HostRate) state(host string, now time.Time) *hostState {
	if h, ok := c.hosts[host]; ok {
		return h
	}
	if len(c.hosts) >= c.b.MaxHosts {
		if c.overflow == nil {
			c.overflow = c.newState("*", now)
		}
		return c.overflow
	}
	h := c.newState(host, now)
	c.hosts[host] = h
	return h
}

func (c *HostRate) newState(host string, now time.Time) *hostState {
	r := c.start()
	return &hostState{name: host, rate: r, ssthresh: c.ceiling, slowStart: r < c.ceiling, min: r,
		lim: rate.NewLimiter(rate.Limit(r), 1), windowEnd: now.Add(c.b.Window)}
}

// Acquire waits until a connection (or a request) to host may start, bounded
// by ctx. It returns ErrHostUnavailable when the host's breaker is open or
// the host asked to wait longer than TargetRate.HoldMax.
func (c *HostRate) Acquire(ctx context.Context, host string) error {
	c.mu.Lock()
	now := c.now()
	h := c.state(host, now)
	var ch []Change
	c.advance(h, now, &ch)
	switch h.brk {
	case down:
		c.lose(h, GapBreakerOpen, "the host stopped answering")
		c.mu.Unlock()
		c.emit(ch)
		return fmt.Errorf("%w: %s gave up after %d breaker trips", ErrHostUnavailable, host, h.trips)
	case open:
		if now.Before(h.openUntil) {
			c.lose(h, GapBreakerOpen, "the host stopped answering")
			c.mu.Unlock()
			c.emit(ch)
			return fmt.Errorf("%w: %s breaker open for %s", ErrHostUnavailable, host, h.openUntil.Sub(now).Round(time.Second))
		}
		h.brk, h.probing, h.probeAt = halfOpen, true, now
		ch = append(ch, Change{Host: h.name, From: h.rate, To: h.rate, Reason: ReasonHalfOpen})
	case halfOpen:
		if h.probing && now.Sub(h.probeAt) < c.b.ProbeTimeout {
			c.lose(h, GapBreakerOpen, "the host stopped answering")
			c.mu.Unlock()
			c.emit(ch)
			return fmt.Errorf("%w: %s breaker half-open, probe in flight", ErrHostUnavailable, host)
		}
		h.probing, h.probeAt = true, now
	}
	wait := h.notBefore.Sub(now)
	shared, tenant := c.shared, c.tenant
	if shared != nil {
		cool, nb := shared.admit(tenant, host, c.ceiling)
		if !cool.until.IsZero() {
			if cool.edge.State.Stops() {
				c.setEdgeGap(h, cool.edge)
			} else {
				c.setGap(h, GapBlocked, cool.detail)
			}
			c.mu.Unlock()
			c.emit(ch)
			return fmt.Errorf("%w: %s blocked the scan (%s); left alone for %s", ErrHostUnavailable, host, cool, cool.until.Sub(now).Round(time.Second))
		}
		if d := nb.Sub(now); d > wait {
			wait = d
		}
	}
	if wait > c.b.HoldMax {
		c.lose(h, GapRateFloor, "the host asked to wait "+wait.Round(time.Second).String())
		c.mu.Unlock()
		c.emit(ch)
		return fmt.Errorf("%w: %s asked to retry after %s", ErrHostUnavailable, host, wait.Round(time.Second))
	}
	lim := h.lim
	c.mu.Unlock()
	c.emit(ch)
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	if err := lim.Wait(ctx); err != nil {
		return err
	}
	if shared != nil {
		return shared.wait(ctx, tenant, host)
	}
	return nil
}

// Report feeds one signal about host to the controller.
func (c *HostRate) Report(host string, e Event) {
	c.mu.Lock()
	now := c.now()
	h := c.state(host, now)
	var ch []Change
	c.advance(h, now, &ch)
	switch e.Signal {
	case Connected:
		// A connection after failures is evidence enough to close a
		// half-open breaker; it does not clear the failure count (a host
		// that accepts and then resets every connection still trips).
		h.oks++
		c.close(h, &ch)
	case Answered:
		h.oks++
		h.fails, h.run403, h.answered = 0, 0, true
		c.close(h, &ch)
		if c.shared != nil {
			c.shared.answered(c.tenant, host)
		}
	case Congested:
		// The host is alive, only busy: a probe that got this closes the
		// breaker, and the rate comes down.
		h.bad++
		h.fails = 0
		c.close(h, &ch)
		if e.RetryAfter > 0 {
			nb := now.Add(min(e.RetryAfter, c.b.RetryAfterMax))
			if nb.After(h.notBefore) {
				h.notBefore = nb
			}
		}
		c.decrease(h, now, e.Reason, &ch)
		if c.shared != nil {
			c.shared.congested(c.tenant, host, e.RetryAfter)
		}
	case Forbidden:
		h.fails = 0
		c.close(h, &ch)
		if e.Edge.State.Stops() {
			// A vendor challenge or block page: the edge, not the service,
			// answered, and it will keep answering. No run of 403s is
			// needed, and none is expected of a first request.
			h.run403 = 0
			h.bad++
			c.setEdgeGap(h, e.Edge)
			c.decrease(h, now, ReasonBlocked, &ch)
			c.trip(h, now, ReasonBlocked, &ch)
			if c.shared != nil {
				c.shared.block(c.tenant, host, e.Edge, "")
			}
			break
		}
		if !h.answered {
			break
		}
		h.run403++
		if h.run403 >= c.b.BlockRun {
			h.run403 = 0
			h.bad++
			detail := fmt.Sprintf("%d consecutive 403 answers", c.b.BlockRun)
			c.setGap(h, GapBlocked, detail)
			c.decrease(h, now, ReasonBlocked, &ch)
			c.trip(h, now, ReasonBlocked, &ch)
			if c.shared != nil {
				c.shared.block(c.tenant, host, edgeprotect.Verdict{}, detail)
			}
		}
	case Failed:
		h.bad++
		h.fails++
		c.decrease(h, now, e.Reason, &ch)
		if h.brk == halfOpen || (h.brk == closed && h.fails >= c.b.BreakerFailures) {
			c.trip(h, now, e.Reason, &ch)
		}
	}
	c.mu.Unlock()
	c.emit(ch)
}

// ReportDial feeds the outcome of a connection attempt to host:port. A
// failure counts only on a port that accepted a connection before in this
// task: a closed or filtered port of a host is not push-back (a port scan
// meets thousands of them). Cancellation is not a signal.
func (c *HostRate) ReportDial(host string, port int, err error) {
	if err == nil {
		c.mu.Lock()
		h := c.state(host, c.now())
		if !slices.Contains(h.openPorts, port) && len(h.openPorts) < c.b.MaxOpenPorts {
			h.openPorts = append(h.openPorts, port)
		}
		c.mu.Unlock()
		c.Report(host, Event{Signal: Connected})
		return
	}
	reason := FailureReason(err)
	if reason == "" {
		return
	}
	c.mu.Lock()
	h := c.state(host, c.now())
	known := slices.Contains(h.openPorts, port)
	c.mu.Unlock()
	if known {
		c.Report(host, Event{Signal: Failed, Reason: reason})
	}
}

// ReportHTTP feeds one HTTP answer of host (status and its Retry-After
// header value).
func (c *HostRate) ReportHTTP(host string, status int, retryAfter string) {
	switch status {
	case http.StatusTooManyRequests:
		c.Report(host, Event{Signal: Congested, Reason: ReasonHTTP429, RetryAfter: ParseRetryAfter(retryAfter, c.now())})
	case http.StatusServiceUnavailable:
		c.Report(host, Event{Signal: Congested, Reason: ReasonHTTP503, RetryAfter: ParseRetryAfter(retryAfter, c.now())})
	case http.StatusForbidden:
		c.Report(host, Event{Signal: Forbidden})
	default:
		c.Report(host, Event{Signal: Answered})
	}
}

// ReportResponse is ReportHTTP with the edge verdict of the answer: a
// challenge or block page of a vendor's edge (verdict.State.Stops) is a block
// whatever its status (a challenge is sometimes a 503), and from the first
// answer. Without such a verdict it behaves as ReportHTTP.
func (c *HostRate) ReportResponse(host string, status int, retryAfter string, v edgeprotect.Verdict) {
	if v.State.Stops() {
		c.Report(host, Event{Signal: Forbidden, Reason: ReasonBlocked, Edge: v})
		return
	}
	c.ReportHTTP(host, status, retryAfter)
}

// advance closes the windows that ended before now: a window with health
// and no push-back raises the rate. Called with c.mu held.
func (c *HostRate) advance(h *hostState, now time.Time, ch *[]Change) {
	if now.Before(h.windowEnd) {
		return
	}
	if h.oks > 0 && h.bad == 0 && h.brk == closed {
		from := h.rate
		reason := ReasonCleanRun
		if h.slowStart {
			h.rate = math.Min(h.rate*2, h.ssthresh)
			reason = ReasonSlowStart
			if h.rate >= h.ssthresh {
				h.slowStart = false
			}
		} else {
			h.rate += c.ceiling * c.b.IncreaseFraction
		}
		c.set(h, from, reason, ch)
		if h.rate >= c.ceiling {
			h.floorStrike = 0
		}
	}
	h.oks, h.bad = 0, 0
	// Windows with no traffic do not stack up increases.
	h.windowEnd = now.Add(c.b.Window)
}

// decrease halves the rate, at most once per window. A push-back at the
// floor is a strike; FloorStrikes of them make the host a gap.
func (c *HostRate) decrease(h *hostState, now time.Time, reason string, ch *[]Change) {
	if !h.lastDecrease.IsZero() && now.Sub(h.lastDecrease) < c.b.Window {
		return
	}
	h.lastDecrease = now
	h.throttled = true
	h.slowStart = false
	if h.rate <= c.floor {
		h.floorStrike++
		if h.floorStrike >= c.b.FloorStrikes {
			c.setGap(h, GapRateFloor, fmt.Sprintf("pushed back %d times at %.3g/s (%s)", h.floorStrike, c.floor, reason))
		}
	}
	from := h.rate
	h.rate *= c.b.DecreaseFactor
	h.ssthresh = math.Max(c.floor, h.rate)
	c.set(h, from, reason, ch)
}

// set clamps the rate to [floor, ceiling], applies it and records the
// change.
func (c *HostRate) set(h *hostState, from float64, reason string, ch *[]Change) {
	h.rate = math.Max(c.floor, math.Min(c.ceiling, h.rate))
	h.min = math.Min(h.min, h.rate)
	if h.rate == from {
		return
	}
	h.lim.SetLimit(rate.Limit(h.rate))
	*ch = append(*ch, Change{Host: h.name, From: from, To: h.rate, Reason: reason})
}

// trip opens the host's breaker (or gives the host up).
func (c *HostRate) trip(h *hostState, now time.Time, reason string, ch *[]Change) {
	if h.brk == down || h.brk == open {
		// Answers of connections opened before the breaker opened do not
		// trip it again.
		return
	}
	h.trips++
	h.fails, h.probing = 0, false
	h.tripReason = reason
	if h.trips >= c.b.BreakerMaxTrips {
		h.brk = down
		c.setGap(h, GapBreakerOpen, fmt.Sprintf("given up after %d breaker trips (%s)", h.trips, reason))
		if h.gap == GapBreakerOpen {
			h.gapCause = gapCauseOf(reason)
		}
		*ch = append(*ch, Change{Host: h.name, From: h.rate, To: 0, Reason: ReasonGaveUp})
		return
	}
	d := c.b.BreakerOpen << (h.trips - 1)
	if d > c.b.BreakerOpenMax || d <= 0 {
		d = c.b.BreakerOpenMax
	}
	d = time.Duration(float64(d) * (1 + c.b.BreakerJitter*(2*c.jitter()-1)))
	h.brk, h.openUntil = open, now.Add(d)
	*ch = append(*ch, Change{Host: h.name, From: h.rate, To: 0, Reason: ReasonOpened + " (" + reason + ")"})
}

// close closes a half-open breaker after an answer.
func (c *HostRate) close(h *hostState, ch *[]Change) {
	if h.brk != halfOpen {
		return
	}
	h.brk, h.probing = closed, false
	*ch = append(*ch, Change{Host: h.name, From: h.rate, To: h.rate, Reason: ReasonClosed})
}

// lose records a connection the controller refused: the host's coverage is
// incomplete.
func (c *HostRate) lose(h *hostState, reason, detail string) {
	c.setGap(h, reason, detail)
	if reason == GapBreakerOpen && h.gap == GapBreakerOpen && h.gapCause == "" {
		h.gapCause = gapCauseOf(h.tripReason)
	}
}

// gapRank orders gap reasons: a host keeps its strongest one.
func gapRank(r string) int {
	switch r {
	case GapBlocked:
		return 4
	case GapBreakerOpen:
		return 3
	case GapProxyUnavailable:
		return 2
	case GapRateFloor:
		return 1
	}
	return 0
}

// MarkGap records that part of host's coverage is missing for a reason the
// controller did not see itself (GapProxyUnavailable: the path failed, not
// the host). The host keeps its strongest gap; its rate and breaker do not
// move.
func (c *HostRate) MarkGap(host, reason, detail string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setGap(c.state(host, c.now()), reason, detail)
}

// setEdgeGap makes the host a blocked gap that names the edge: it also sets
// the edge members on a blocked gap an earlier run of plain 403s made.
func (c *HostRate) setEdgeGap(h *hostState, v edgeprotect.Verdict) {
	c.setGap(h, GapBlocked, fmt.Sprintf("%s %s (%s)", v.Vendor, v.State, v.Signal))
	if h.gap == GapBlocked && h.gapEdge == "" {
		h.gapEdge, h.gapVendor = string(v.State), v.Vendor
		h.gapDetail = fmt.Sprintf("%s %s (%s)", v.Vendor, v.State, v.Signal)
	}
}

func (c *HostRate) setGap(h *hostState, reason, detail string) {
	if gapRank(reason) > gapRank(h.gap) {
		h.gap, h.gapDetail, h.gapCause = reason, detail, ""
	}
}

// gapCauseOf is the Gap.Cause of a host given up for failures of reason:
// a reset says the host accepted the connections (it is up and refuses
// them), a timeout that nothing answered, a refusal that the port is
// closed. Any other reason names no cause.
func gapCauseOf(reason string) string {
	switch reason {
	case ReasonReset:
		return GapCauseReset
	case ReasonTimeout:
		return GapCauseNoAnswer
	case ReasonRefused:
		return GapCauseRefused
	}
	return ""
}

func (c *HostRate) emit(ch []Change) {
	if len(ch) == 0 || c.OnChange == nil {
		return
	}
	for _, x := range ch {
		c.OnChange(x)
	}
}

// Rate is host's current rate (the start rate for a host not seen yet).
func (c *HostRate) Rate(host string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h, ok := c.hosts[host]; ok {
		return h.rate
	}
	return c.start()
}

// Summary is the task's target-rate outcome so far.
func (c *HostRate) Summary() Summary {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Summary{Ceiling: c.ceiling, Floor: c.floor, Start: c.start(), Min: c.start(), Final: c.start()}
	states := make([]*hostState, 0, len(c.hosts)+1)
	for _, h := range c.hosts {
		states = append(states, h)
	}
	if c.overflow != nil {
		states = append(states, c.overflow)
	}
	slices.SortFunc(states, func(a, b *hostState) int { return strings.Compare(a.name, b.name) })
	first := true
	for _, h := range states {
		s.Hosts++
		if first || h.min < s.Min {
			s.Min = h.min
		}
		if first || h.rate < s.Final {
			s.Final = h.rate
		}
		first = false
		if h.throttled {
			s.Throttled++
		}
		if h.brk == down {
			s.Unreachable++
		}
		if h.gap != "" {
			s.GapsTotal++
			if len(s.Gaps) < c.b.MaxGaps {
				s.Gaps = append(s.Gaps, Gap{Host: h.name, Reason: h.gap, Detail: h.gapDetail, Edge: h.gapEdge, Vendor: h.gapVendor, Cause: h.gapCause})
			}
		}
	}
	return s
}

// Gaps are the hosts whose coverage is incomplete (at most
// TargetRate.MaxGaps) and how many there are in all.
func (c *HostRate) Gaps() ([]Gap, int) {
	s := c.Summary()
	return s.Gaps, s.GapsTotal
}

// ParseRetryAfter reads a Retry-After value (delta seconds or an HTTP
// date), capped at TargetRate.RetryAfterMax; zero when absent or
// unreadable.
func ParseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		if n <= 0 {
			return 0
		}
		d = time.Duration(min(n, int(TargetRate.RetryAfterMax/time.Second))) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	if d <= 0 {
		return 0
	}
	return min(d, TargetRate.RetryAfterMax)
}
