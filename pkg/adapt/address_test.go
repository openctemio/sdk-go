package adapt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/contract/edgeprotect"
)

// challenge is a vendor's challenge page: an answer that stops the request.
var challenge = edgeprotect.Verdict{State: edgeprotect.Challenged, Vendor: "example-edge", Signal: "header"}

// addrOK fails the test when the address refuses or holds a connection.
func addrOK(t *testing.T, c *HostRate, addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := c.AcquireAddr(ctx, addr); err != nil {
		t.Fatalf("the address %s refused or held a connection: %v", addr, err)
	}
}

// SECURITY: whatever is reported for an address (a vendor's challenge or
// block page, 429 and 503 with a long Retry-After, a run of them, resets,
// timeouts, the canary's push-back), the address only gets slower: it is
// never refused, never held, never a gap, its breaker never opens and no
// cooldown starts. Its rate stays at or above the floor and recovers.
func TestAddressSignalsOnlyLowerItsRate(t *testing.T) {
	addr := "192.0.2.10"
	signals := map[string]Event{
		"challenge page":              {Signal: Forbidden, Reason: ReasonBlocked, Edge: challenge},
		"429 with a long Retry-After": {Signal: Congested, Reason: ReasonHTTP429, RetryAfter: 5 * time.Minute},
		"503":                         {Signal: Congested, Reason: ReasonHTTP503},
		"TLS handshake failure":       {Signal: Failed, Reason: ReasonTLS},
		"timeout":                     {Signal: Failed, Reason: ReasonTimeout},
		"canary 429":                  {Signal: Congested, Reason: ReasonHTTP429, RetryAfter: 5 * time.Minute, Probe: true},
		"canary 403":                  {Signal: Forbidden, Probe: true},
		"canary reset":                {Signal: Failed, Reason: ReasonReset, Probe: true},
	}
	for name, e := range signals {
		t.Run(name, func(t *testing.T) {
			c, clk := testCtl(t, 20)
			shared := NewSensorRate()
			c.Share(shared, "tenant-a")
			c.ReportAddr(addr, Event{Signal: Connected})
			before := c.Rate(addr)
			for range 60 {
				*clk = clk.Add(TargetRate.Window)
				c.ReportAddr(addr, e)
			}
			s := c.Summary()
			if s.CircuitOpens != 0 || s.GapsTotal != 0 || s.Unreachable != 0 || s.Hosts != 0 {
				t.Fatalf("a signal for an address did more than lower its rate: %+v", s)
			}
			if got := c.Rate(addr); got >= before || got != s.Floor {
				t.Fatalf("the address's rate was not lowered to the floor: before %.3g, now %.3g", before, got)
			}
			addrOK(t, c, addr)
			if until := shared.Cooldown("tenant-a", addr); !until.IsZero() {
				t.Fatalf("a cooldown of the address started, until %v", until)
			}
			// Clean windows raise it again.
			for range 4 {
				c.ReportAddr(addr, Event{Signal: Answered})
				*clk = clk.Add(TargetRate.Window)
			}
			c.ReportAddr(addr, Event{Signal: Answered})
			if got := c.Rate(addr); got <= s.Floor {
				t.Fatalf("the address's rate did not recover: %.3g", got)
			}
		})
	}
}

// A bare 403 of the tool's is an answer about one path, and a reset of one
// of the tool's connections at an address that accepts connections refuses
// one request: neither slows the address (as neither slows a host), and
// neither opens anything however many there are.
func TestRefusalsOfSingleRequestsDoNotSlowTheAddress(t *testing.T) {
	c, clk := testCtl(t, 20)
	addr := "192.0.2.10"
	c.ReportAddr(addr, Event{Signal: Connected})
	before := c.Rate(addr)
	for range 3 * TargetRate.BlockRun {
		*clk = clk.Add(TargetRate.Window)
		c.ReportAddrResponse(addr, 403, "", edgeprotect.Verdict{})
		c.ReportAddr(addr, Event{Signal: Failed, Reason: ReasonReset})
	}
	if got := c.Rate(addr); got < before {
		t.Fatalf("plain 403 answers and resets lowered the address's rate from %.3g to %.3g", before, got)
	}
	addrOK(t, c, addr)
	if s := c.Summary(); s.CircuitOpens != 0 || s.GapsTotal != 0 {
		t.Fatalf("summary %+v", s)
	}
	// A reset from an address that never accepted a connection is a failure.
	c2, clk2 := testCtl(t, 20)
	first := c2.Rate(addr)
	*clk2 = clk2.Add(TargetRate.Window)
	c2.ReportAddr(addr, Event{Signal: Failed, Reason: ReasonReset})
	if got := c2.Rate(addr); got >= first {
		t.Fatalf("a reset from an address that never accepted a connection did not lower its rate: %.3g", got)
	}
}

// SECURITY: one name of a shared address cannot deny the other names of
// that address. A challenge page from hostile.example.com blocks that name
// (its breaker, the tenant's cooldown of that name) and nothing else:
// victim.example.com, reached at the same address, gets its connections in
// the same task and in the tenant's next task on the sensor.
func TestBlockOfOneNameLeavesTheOtherNamesOfItsAddress(t *testing.T) {
	const addr, hostile, victim, tenant = "192.0.2.10", "hostile.example.com", "victim.example.com", "tenant-a"
	shared := NewSensorRate()
	task := func() *HostRate {
		c := NewHostRate(20)
		c.Share(shared, tenant)
		return c
	}
	reach := func(c *HostRate, name string) error {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := c.Acquire(ctx, name); err != nil {
			return err
		}
		return c.AcquireAddr(ctx, addr)
	}
	c := task()
	for _, n := range []string{hostile, victim} {
		if err := reach(c, n); err != nil {
			t.Fatal(err)
		}
	}
	// One answer of the hostile name: the forwarder reports it to the name
	// and to the address.
	c.ReportResponse(hostile, 403, "", challenge)
	c.ReportAddrResponse(addr, 403, "", challenge)
	if err := c.Acquire(t.Context(), hostile); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("the name that was challenged is not backed off: %v", err)
	}
	for i := range 5 {
		if err := reach(c, victim); err != nil {
			t.Fatalf("request %d of the healthy name was refused in the same task: %v", i+1, err)
		}
		c.Report(victim, Event{Signal: Answered})
		c.ReportAddr(addr, Event{Signal: Answered})
	}
	s := c.Summary()
	if s.GapsTotal != 1 || s.Gaps[0].Host != hostile || s.Gaps[0].Reason != GapBlocked {
		t.Fatalf("gaps %+v", s.Gaps)
	}
	if until := shared.Cooldown(tenant, addr); !until.IsZero() {
		t.Fatalf("one name's answer started a cooldown of the address until %v", until)
	}
	if until := shared.Cooldown(tenant, victim); !until.IsZero() {
		t.Fatalf("one name's answer started a cooldown of another name until %v", until)
	}
	if shared.Cooldown(tenant, hostile).IsZero() {
		t.Fatal("the challenged name has no cooldown")
	}
	// The tenant's next task on the sensor.
	next := task()
	for i := range 5 {
		if err := reach(next, victim); err != nil {
			t.Fatalf("request %d of the healthy name was refused in the next task: %v", i+1, err)
		}
	}
	if err := next.Acquire(t.Context(), hostile); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("the challenged name is not in its cooldown in the next task: %v", err)
	}
	if g := next.Summary(); g.GapsTotal != 1 || g.Gaps[0].Host != hostile {
		t.Fatalf("gaps of the next task %+v", g.Gaps)
	}
}

// A Retry-After one name sent holds that name and not the address: another
// name reached there is neither held nor refused.
func TestRetryAfterOfOneNameDoesNotHoldItsAddress(t *testing.T) {
	const addr, slow, other = "192.0.2.10", "slow.example.com", "other.example.com"
	c := NewHostRate(20)
	c.Share(NewSensorRate(), "tenant-a")
	c.ReportResponse(slow, 429, "300", edgeprotect.Verdict{})
	c.ReportAddrResponse(addr, 429, "300", edgeprotect.Verdict{})
	if err := c.Acquire(t.Context(), slow); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("the name that asked to wait is not held: %v", err)
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := c.Acquire(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := c.AcquireAddr(ctx, addr); err != nil {
		t.Fatalf("the address held or refused another name: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("another name waited %s for one name's Retry-After", d)
	}
}

// A target that names the address is a host with its own breaker; the
// names reached at that address take only its rate, whatever that breaker
// says, and their answers never open it.
func TestAddressThatIsAlsoATargetKeepsItsBreakerToItself(t *testing.T) {
	c, _ := testCtl(t, 20)
	addr := "192.0.2.10"
	c.ReportResponse(addr, 403, "", challenge) // the address target itself is blocked
	if err := c.Acquire(t.Context(), addr); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("the address target is not backed off: %v", err)
	}
	addrOK(t, c, addr) // a name dialed there is not
	// And the other way round: what names are answered does not open the
	// address target's breaker.
	c2, clk2 := testCtl(t, 20)
	if err := c2.Acquire(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	for range 3 * TargetRate.ThrottleRun {
		*clk2 = clk2.Add(TargetRate.ThrottleSpacing)
		c2.ReportAddrResponse(addr, 429, "300", edgeprotect.Verdict{})
		c2.ReportAddrResponse(addr, 403, "", challenge)
		c2.ReportAddr(addr, Event{Signal: Failed, Reason: ReasonTimeout})
	}
	*clk2 = clk2.Add(TargetRate.Window)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := c2.Acquire(ctx, addr); err != nil {
		t.Fatalf("answers of names opened or held the address target: %v", err)
	}
	if s := c2.Summary(); s.CircuitOpens != 0 || s.GapsTotal != 0 || s.Hosts != 1 {
		t.Fatalf("summary %+v", s)
	}
}

// Rate limits the canary is answered with become a throttled gap that is
// an observation: one may be a blip, ObservedRun in a row are reported.
// The host is not stopped: its breaker stays closed and the tool's
// connections go out.
func TestCanaryRateLimitsAreAnObservedThrottleGap(t *testing.T) {
	host := "a.example.com"
	for _, reason := range []string{ReasonHTTP429, ReasonHTTP503} {
		t.Run(reason, func(t *testing.T) {
			c, clk := testCtl(t, 20)
			c.Report(host, Event{Signal: Connected})
			c.Report(host, Event{Signal: Answered, Probe: true})
			limit := Event{Signal: Congested, Reason: reason, RetryAfter: time.Minute, Probe: true}
			c.Report(host, limit)
			if s := c.Summary(); s.GapsTotal != 0 {
				t.Fatalf("one rate-limit answer made a gap: %+v", s.Gaps)
			}
			// An ordinary answer between them starts the run again.
			c.Report(host, Event{Signal: Answered, Probe: true})
			*clk = clk.Add(TargetRate.Window)
			c.Report(host, limit)
			if s := c.Summary(); s.GapsTotal != 0 {
				t.Fatalf("rate-limit answers with an ordinary answer between them made a gap: %+v", s.Gaps)
			}
			for range TargetRate.ObservedRun - 1 {
				*clk = clk.Add(TargetRate.Window)
				c.Report(host, limit)
			}
			s := c.Summary()
			if s.GapsTotal != 1 || s.Gaps[0].Host != host || s.Gaps[0].Reason != GapThrottled || !s.Gaps[0].Observed {
				t.Fatalf("gaps %+v", s.Gaps)
			}
			if s.CircuitOpens != 0 || s.Unreachable != 0 {
				t.Fatalf("the observation opened the breaker: %+v", s)
			}
			if hs := s.HostStats[0]; hs.CanaryPushback != TargetRate.ObservedRun+1 || hs.CircuitOpens != 0 {
				t.Fatalf("host stat %+v", hs)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if err := c.Acquire(ctx, host); err != nil {
				t.Fatalf("the observed host was refused or held: %v", err)
			}
		})
	}
	t.Run("a breaker that opens later is not an observation", func(t *testing.T) {
		c, clk := testCtl(t, 20)
		c.Report(host, Event{Signal: Connected})
		for range TargetRate.ObservedRun {
			*clk = clk.Add(TargetRate.Window)
			c.Report(host, Event{Signal: Congested, Reason: ReasonHTTP429, Probe: true})
		}
		for range TargetRate.CorroborateFailures {
			*clk = clk.Add(time.Second)
			c.Report(host, Event{Signal: Failed, Reason: ReasonReset})
		}
		s := c.Summary()
		if s.CircuitOpens != 1 || s.GapsTotal != 1 || s.Gaps[0].Reason != GapThrottled || s.Gaps[0].Observed {
			t.Fatalf("summary %+v", s)
		}
	})
}

// The budget of a command travels on a context to a path with no scan
// options; an invalid one is never put there.
func TestHostBudgetOnAContext(t *testing.T) {
	if _, ok := HostBudgetFrom(t.Context()); ok {
		t.Fatal("a budget on an empty context")
	}
	if _, ok := HostBudgetFrom(WithHostBudget(t.Context(), HostBudget{})); ok {
		t.Fatal("an invalid budget was put on the context")
	}
	want := ResolveBudget(PacingGentle, nil, BudgetCeiling{})
	got, ok := HostBudgetFrom(WithHostBudget(t.Context(), want))
	if !ok || got.RPS != want.RPS || got.Inflight != want.Inflight {
		t.Fatalf("got %+v, %v", got, ok)
	}
}
