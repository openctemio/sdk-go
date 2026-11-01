package adapt

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/ctis/edgeprotect"
)

// SensorRate is what every task of one sensor shares about a target host
// (one per process: Process). A task's HostRate joins it with Share; the
// task then still paces itself (its ceiling, slow start, breaker and gaps
// are its own) and, on top of that:
//
//   - takes its connections from the host's sensor-wide rate: all tasks
//     toward one host share one rate, so two tools scanning the same host
//     do not add up. The rate is AIMD like a task's (halved on 429 and 503
//     and on a block, raised on clean windows), never above the highest
//     ceiling of the tasks using the host, never below TargetRate.Floor.
//     Inside a host the rate is split evenly between the tenants asking for
//     it (fair share on a shared sensor): one tenant's scans cannot take
//     another's share of a target;
//   - honors a Retry-After any task of the same tenant got from the host;
//   - leaves a host alone after an edge block (a vendor block or challenge
//     page, or a run of 403 answers): SharedRate.CooldownBase, doubling on
//     each further block up to CooldownMax. During the cooldown every
//     connection of the tenant toward the host is refused before it is
//     dialed (so no other proxy endpoint is ever tried for it) and the host
//     is a coverage gap with the edge's reason, never "no findings".
//
// Retry-After and cooldowns are kept per (tenant, host): what a target told
// one tenant's scans never reaches another tenant's task. Only the pace of
// the host is shared between tenants (fair share).
//
// The zero value is not usable; create it with NewSensorRate.
type SensorRate struct {
	b  TargetRateBounds
	sb SharedRateBounds

	// now and sleep are replaced in tests.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error

	mu      sync.Mutex
	hosts   map[string]*sharedHost
	sweepAt time.Time
}

type sharedHost struct {
	rate         float64
	ceiling      float64
	windowEnd    time.Time
	lastDecrease time.Time
	oks, bad     int
	last         time.Time
	tenants      map[string]*tenantShare
}

type tenantShare struct {
	lim     *rate.Limiter
	ceiling float64
	last    time.Time
	// notBefore is the latest Retry-After of the host to this tenant.
	notBefore time.Time
	// coolUntil ends the cooldown after an edge block; blocks counts the
	// blocks that doubled it (reset once the host answers after it).
	coolUntil time.Time
	blocks    int
	edge      edgeprotect.Verdict
	detail    string
}

// cooldown is a refusal SensorRate.admit returns.
type cooldown struct {
	until  time.Time
	edge   edgeprotect.Verdict
	detail string
}

// NewSensorRate returns an empty sensor-wide state.
func NewSensorRate() *SensorRate {
	return &SensorRate{b: TargetRate, sb: SharedRate, now: time.Now, sleep: sleepCtx, hosts: map[string]*sharedHost{}}
}

var processRate = sync.OnceValue(NewSensorRate)

// Process is the process's SensorRate: the one every task forwarder of the
// sensor shares.
func Process() *SensorRate { return processRate() }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// share returns the host's and the tenant's state, created on first use
// (nil, nil when the bounds leave no room: the task paces itself alone).
// Called with s.mu held.
func (s *SensorRate) share(tenant, host string, now time.Time, create bool) (*sharedHost, *tenantShare) {
	s.sweep(now)
	h := s.hosts[host]
	if h == nil {
		if !create || len(s.hosts) >= s.sb.MaxHosts {
			return nil, nil
		}
		h = &sharedHost{windowEnd: now.Add(s.b.Window), tenants: map[string]*tenantShare{}}
		s.hosts[host] = h
	}
	t := h.tenants[tenant]
	if t == nil {
		if !create || len(h.tenants) >= s.sb.MaxTenantsPerHost {
			return h, nil
		}
		t = &tenantShare{lim: rate.NewLimiter(rate.Inf, 1)}
		h.tenants[tenant] = t
	}
	return h, t
}

// sweep drops what nobody needs any more, at most once a minute: tenants
// idle past HostIdle whose Retry-After and cooldown (and its doubling
// memory, CooldownMax after it ends) passed, then hosts left with no
// tenant. Called with s.mu held.
func (s *SensorRate) sweep(now time.Time) {
	if now.Before(s.sweepAt) {
		return
	}
	s.sweepAt = now.Add(time.Minute)
	for name, h := range s.hosts {
		for tn, t := range h.tenants {
			if now.Sub(t.last) > s.sb.HostIdle && now.After(t.notBefore) && now.After(t.coolUntil.Add(s.sb.CooldownMax)) {
				delete(h.tenants, tn)
			}
		}
		if len(h.tenants) == 0 && now.Sub(h.last) > s.sb.HostIdle {
			delete(s.hosts, name)
		}
	}
}

// admit records that tenant's task with the given ceiling asks for host.
// It returns the cooldown that refuses the connection (zero: none) and
// the time the host's Retry-After to the tenant ends.
func (s *SensorRate) admit(tenant, host string, ceiling float64) (cooldown, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	h, t := s.share(tenant, host, now, true)
	if t == nil {
		return cooldown{}, time.Time{}
	}
	h.last, t.last, t.ceiling = now, now, ceiling
	s.reshape(h, now)
	if now.Before(t.coolUntil) {
		return cooldown{until: t.coolUntil, edge: t.edge, detail: t.detail}, t.notBefore
	}
	return cooldown{}, t.notBefore
}

// reshape sets the host's ceiling (the highest of its active tenants'),
// closes its window and gives each active tenant an even share of its
// rate. Called with s.mu held.
func (s *SensorRate) reshape(h *sharedHost, now time.Time) {
	active, ceiling := 0, 0.0
	for _, t := range h.tenants {
		if now.Sub(t.last) <= s.sb.ShareIdle {
			active++
			ceiling = math.Max(ceiling, t.ceiling)
		}
	}
	if active == 0 {
		return
	}
	if h.ceiling == 0 {
		h.rate = ceiling // a new host: each task's own slow start paces it
	}
	h.ceiling = ceiling
	s.advance(h, now)
	h.rate = math.Max(math.Min(s.b.Floor, h.ceiling), math.Min(h.ceiling, h.rate))
	share := rate.Limit(h.rate / float64(active))
	for _, t := range h.tenants {
		if t.lim.Limit() != share {
			t.lim.SetLimitAt(now, share)
		}
	}
}

// advance closes the host's windows that ended: a window with answers and
// no push-back raises its rate by IncreaseFraction of its ceiling. Called
// with s.mu held.
func (s *SensorRate) advance(h *sharedHost, now time.Time) {
	if now.Before(h.windowEnd) {
		return
	}
	if h.oks > 0 && h.bad == 0 {
		h.rate = math.Min(h.ceiling, h.rate+h.ceiling*s.b.IncreaseFraction)
	}
	h.oks, h.bad = 0, 0
	h.windowEnd = now.Add(s.b.Window)
}

// decrease halves the host's rate, at most once per window. Called with
// s.mu held.
func (s *SensorRate) decrease(h *sharedHost, now time.Time) {
	h.bad++
	if !h.lastDecrease.IsZero() && now.Sub(h.lastDecrease) < s.b.Window {
		return
	}
	h.lastDecrease = now
	h.rate = math.Max(math.Min(s.b.Floor, h.ceiling), h.rate*s.b.DecreaseFactor)
}

// wait takes one connection from the tenant's share of the host's rate,
// bounded by ctx.
func (s *SensorRate) wait(ctx context.Context, tenant, host string) error {
	s.mu.Lock()
	now := s.now()
	h, t := s.share(tenant, host, now, false)
	if t == nil {
		s.mu.Unlock()
		return nil
	}
	s.reshape(h, now)
	r := t.lim.ReserveN(now, 1)
	d := r.DelayFrom(now)
	s.mu.Unlock()
	if d <= 0 {
		return nil
	}
	if err := s.sleep(ctx, d); err != nil {
		s.mu.Lock()
		r.CancelAt(s.now())
		s.mu.Unlock()
		return err
	}
	return nil
}

// answered records a healthy answer of host: it counts toward the host's
// clean window and, once a cooldown ended, forgets the blocks that
// doubled it.
func (s *SensorRate) answered(tenant, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	h, t := s.share(tenant, host, now, false)
	if h == nil {
		return
	}
	s.advance(h, now)
	h.oks++
	if t != nil && t.blocks > 0 && !now.Before(t.coolUntil) {
		t.blocks = 0
	}
}

// congested records a 429 or 503 of host (with its Retry-After, zero when
// none): the host's rate comes down for every tenant, the Retry-After holds
// every task of this tenant.
func (s *SensorRate) congested(tenant, host string, retryAfter time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	h, t := s.share(tenant, host, now, true)
	if h == nil {
		return
	}
	s.advance(h, now)
	s.decrease(h, now)
	if t != nil && retryAfter > 0 {
		if nb := now.Add(min(retryAfter, s.b.RetryAfterMax)); nb.After(t.notBefore) {
			t.notBefore = nb
		}
	}
}

// block records an edge block of host seen by a task of tenant (v: the
// vendor's verdict, zero for a run of plain 403 answers): the host is left
// alone by the tenant's tasks for the cooldown. Answers that arrive during
// a cooldown (connections opened before it) do not lengthen it.
func (s *SensorRate) block(tenant, host string, v edgeprotect.Verdict, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	h, t := s.share(tenant, host, now, true)
	if h == nil {
		return
	}
	s.advance(h, now)
	s.decrease(h, now)
	if t == nil || now.Before(t.coolUntil) {
		return
	}
	t.blocks++
	t.coolUntil = now.Add(s.cooldownFor(t.blocks))
	t.edge, t.detail = v, detail
}

// cooldownFor is the cooldown after the n-th block in a row.
func (s *SensorRate) cooldownFor(n int) time.Duration {
	d := s.sb.CooldownBase
	for i := 1; i < n && d < s.sb.CooldownMax; i++ {
		d *= 2
	}
	return min(d, s.sb.CooldownMax)
}

// Cooldown is when tenant's cooldown of host ends (zero: none now).
func (s *SensorRate) Cooldown(tenant, host string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	h := s.hosts[host]
	if h == nil {
		return time.Time{}
	}
	if t := h.tenants[tenant]; t != nil && now.Before(t.coolUntil) {
		return t.coolUntil
	}
	return time.Time{}
}

// String describes a cooldown for an error and a gap.
func (c cooldown) String() string {
	if c.edge.State.Stops() {
		return fmt.Sprintf("%s %s (%s)", c.edge.Vendor, c.edge.State, c.edge.Signal)
	}
	return c.detail
}
