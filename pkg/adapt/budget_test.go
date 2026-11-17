package adapt

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestResolveBudget(t *testing.T) {
	gentle := &JobBudget{Level: "gentle"}
	cases := []struct {
		name    string
		level   Pacing
		job     *JobBudget
		ceiling BudgetCeiling
		want    HostBudget
	}{
		{"no job, no ceiling: Standard", DefaultPacing, nil, BudgetCeiling{},
			HostBudget{Level: "standard", RPS: 20, Inflight: 8, Source: BudgetFromSensor}},
		{"a zero level reads as the default", Pacing{}, nil, BudgetCeiling{},
			HostBudget{Level: "standard", RPS: 20, Inflight: 8, Source: BudgetFromSensor}},
		{"a lower signed level wins", DefaultPacing, gentle, BudgetCeiling{},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, Source: BudgetFromJob}},
		{"lower signed numbers win", DefaultPacing, &JobBudget{RPS: 3, Inflight: 1}, BudgetCeiling{},
			HostBudget{Level: LevelCustom, RPS: 3, Inflight: 1, Source: BudgetFromJob}},
		{"one signed number keeps the level's other", DefaultPacing, &JobBudget{RPS: 10}, BudgetCeiling{},
			HostBudget{Level: LevelCustom, RPS: 10, Inflight: 8, Source: BudgetFromJob}},
		{"a signed Fast applies under the hard ceiling", DefaultPacing, &JobBudget{Level: "fast"}, BudgetCeiling{},
			HostBudget{Level: "fast", RPS: 100, Inflight: 25, Source: BudgetFromJob}},
		{"a signed budget above the hard ceiling is clamped", DefaultPacing, &JobBudget{Level: "custom", RPS: 5000, Inflight: 900}, BudgetCeiling{},
			HostBudget{Level: LevelCustom, RPS: 200, Inflight: 50, Source: BudgetFromJob, Clamped: []BudgetClamp{
				{Key: "rps", Asked: 5000, To: 200, By: ClampByCeiling}, {Key: "inflight", Asked: 900, To: 50, By: ClampByCeiling}}}},
		{"the operator's ceiling clamps a signed Fast", DefaultPacing, &JobBudget{Level: "fast"}, BudgetCeiling{RPS: 30, Inflight: 10},
			HostBudget{Level: LevelCustom, RPS: 30, Inflight: 10, Source: BudgetFromJob, Clamped: []BudgetClamp{
				{Key: "rps", Asked: 100, To: 30, By: ClampByCeiling}, {Key: "inflight", Asked: 25, To: 10, By: ClampByCeiling}}}},
		{"the operator's ceiling clamps the sensor's own level", DefaultPacing, nil, BudgetCeiling{RPS: 5, Inflight: 2},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, Source: BudgetFromSensor, Clamped: []BudgetClamp{
				{Key: "rps", Asked: 20, To: 5, By: ClampByCeiling}, {Key: "inflight", Asked: 8, To: 2, By: ClampByCeiling}}}},
		{"an operator's ceiling above the hard one is the hard one", PacingFast, &JobBudget{Level: "custom", RPS: 900, Inflight: 60}, BudgetCeiling{RPS: 100000, Inflight: 100000},
			HostBudget{Level: LevelCustom, RPS: 200, Inflight: 50, Source: BudgetFromJob, Clamped: []BudgetClamp{
				{Key: "rps", Asked: 900, To: 200, By: ClampByCeiling}, {Key: "inflight", Asked: 60, To: 50, By: ClampByCeiling}}}},
		{"a lower signed budget under a ceiling stays", DefaultPacing, gentle, BudgetCeiling{RPS: 10, Inflight: 4},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, Source: BudgetFromJob}},
		{"an invalid job budget is not read", DefaultPacing, &JobBudget{Level: "ludicrous", RPS: 9000}, BudgetCeiling{},
			HostBudget{Level: "standard", RPS: 20, Inflight: 8, Source: BudgetFromSensor}},
		{"negative numbers are not read", DefaultPacing, &JobBudget{RPS: -1, Inflight: 4}, BudgetCeiling{},
			HostBudget{Level: "standard", RPS: 20, Inflight: 8, Source: BudgetFromSensor}},
		{"the operator's own level is the default", PacingFast, nil, BudgetCeiling{},
			HostBudget{Level: "fast", RPS: 100, Inflight: 25, Source: BudgetFromSensor}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveBudget(tc.level, tc.job, tc.ceiling)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
			// SECURITY: whatever a job says, nothing passes the ceiling.
			c := tc.ceiling.effective()
			if got.RPS > c.RPS || got.Inflight > c.Inflight || got.RPS > HardBudgetCeiling.RPS || got.Inflight > HardBudgetCeiling.Inflight {
				t.Fatalf("budget %+v is above the ceiling %+v", got, c)
			}
		})
	}
}

func TestJobBudgetValidate(t *testing.T) {
	ok := []JobBudget{{Level: "gentle"}, {Level: "standard"}, {Level: "fast"}, {RPS: 5}, {Inflight: 2}, {Level: "custom", RPS: 7, Inflight: 3}, {Level: "gentle", RPS: 1}}
	for _, j := range ok {
		if err := j.Validate(); err != nil {
			t.Errorf("%+v refused: %v", j, err)
		}
	}
	bad := []JobBudget{{}, {Level: "turbo"}, {RPS: -1}, {Inflight: MaxJobBudget + 1}, {Level: "custom"}, {Level: "custom", RPS: 5}}
	for _, j := range bad {
		if err := j.Validate(); err == nil {
			t.Errorf("%+v accepted", j)
		}
	}
}

func TestToolPace(t *testing.T) {
	std := DefaultBudget()
	gentle := ResolveBudget(DefaultPacing, &JobBudget{Level: "gentle"}, BudgetCeiling{})
	custom := ResolveBudget(DefaultPacing, &JobBudget{RPS: 3, Inflight: 1}, BudgetCeiling{})
	cases := []struct {
		name     string
		b        HostBudget
		hosts    int
		enforced bool
		want     ToolPace
	}{
		{"standard, one host", std, 1, true, ToolPace{Rate: 20, Inflight: 8, HostInflight: 8, Hosts: 1}},
		{"standard, three hosts, enforced", std, 3, true, ToolPace{Rate: 60, Inflight: 24, HostInflight: 8, Hosts: 3}},
		{"standard, forty hosts, enforced: eight at once", std, 40, true, ToolPace{Rate: 160, Inflight: 64, HostInflight: 8, Hosts: 25}},
		{"standard, forty hosts, not enforced: one host's budget", std, 40, false, ToolPace{Rate: 20, Inflight: 8, HostInflight: 8, Hosts: 25}},
		{"gentle, ten hosts, enforced: four at once", gentle, 10, true, ToolPace{Rate: 20, Inflight: 8, HostInflight: 2, Hosts: 10}},
		{"custom below gentle", custom, 2, true, ToolPace{Rate: 6, Inflight: 2, HostInflight: 1, Hosts: 2}},
		{"zero hosts reads as one", std, 0, true, ToolPace{Rate: 20, Inflight: 8, HostInflight: 8, Hosts: 1}},
	}
	for _, tc := range cases {
		if got := tc.b.ToolPace(tc.hosts, tc.enforced); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestSweepPace(t *testing.T) {
	std := DefaultBudget()
	cases := []struct {
		name              string
		hosts, maxPerHost int
		enforced          bool
		rate, inflight    int
	}{
		{"one host with 500 URLs runs at that host's budget", 1, 500, true, 20, 8},
		{"two hosts: their budgets in all", 2, 1, true, 40, 16},
		{"many hosts: the sweep rate", 1000, 1, true, 50, 25},
		{"many hosts, not enforced, no host dominates: the sweep rate", 1000, 3, false, 50, 25},
		{"not enforced and one host dominates: one host's budget", 1000, 400, false, 20, 8},
	}
	for _, tc := range cases {
		got := std.SweepPace(tc.hosts, tc.maxPerHost, tc.enforced)
		if got.Rate != tc.rate || got.Inflight != tc.inflight {
			t.Errorf("%s: got %d/s and %d in flight, want %d and %d", tc.name, got.Rate, got.Inflight, tc.rate, tc.inflight)
		}
	}
}

func TestBudgetPacingKeepsEveryRateUnderTheBudget(t *testing.T) {
	for _, b := range []HostBudget{DefaultBudget(),
		ResolveBudget(DefaultPacing, &JobBudget{Level: "gentle"}, BudgetCeiling{}),
		ResolveBudget(DefaultPacing, &JobBudget{Level: "fast"}, BudgetCeiling{}),
		ResolveBudget(DefaultPacing, &JobBudget{RPS: 1, Inflight: 1}, BudgetCeiling{}),
		ResolveBudget(DefaultPacing, &JobBudget{Level: "custom", RPS: 150, Inflight: 40}, BudgetCeiling{})} {
		p := b.Pacing()
		if p.TargetRPS != b.RPS || p.TargetInflight != b.Inflight || p.StartRPS > b.RPS || p.StartRPS < 1 || p.Name != b.Level {
			t.Errorf("budget %+v maps to pacing %+v", b, p)
		}
	}
	if p := (HostBudget{}).Pacing(); p != DefaultPacing {
		t.Errorf("a zero budget maps to %+v, want the default level", p)
	}
}

func TestHostKeyGroupsOneHostWhateverTheSchemePortOrPath(t *testing.T) {
	targets := []string{"http://a.example.com/x", "https://A.example.com:8443/y?z=1", "a.example.com:22", "a.example.com.",
		"https://b.example.com/", "192.0.2.7", "http://192.0.2.7:8080/"}
	groups := GroupHosts(targets)
	if len(groups) != 3 || len(groups[0]) != 4 || len(groups[1]) != 1 || len(groups[2]) != 2 {
		t.Fatalf("groups %v", groups)
	}
	if hosts, most := CountHosts(targets); hosts != 3 || most != 4 {
		t.Fatalf("CountHosts = %d, %d", hosts, most)
	}
	if hosts, most := CountHosts(nil); hosts != 1 || most != 1 {
		t.Fatalf("CountHosts(nil) = %d, %d", hosts, most)
	}
}

// A run of push-back answers with no ordinary answer between them halves
// the rate, then opens the host's breaker; the host is a throttled gap
// whose detail counts the signals, and the summary counts the back-offs.
func TestThrottleRunOpensTheBreakerAndCountsTheSignals(t *testing.T) {
	c, clk := testCtl(t, 20)
	c.SetBudget(DefaultBudget())
	host := "a.example.com"
	c.Report(host, Event{Signal: Answered})
	for i := range TargetRate.ThrottleRun {
		*clk = clk.Add(TargetRate.Window)
		reason := ReasonHTTP429
		if i%2 == 1 {
			reason = ReasonHTTP503
		}
		c.Report(host, Event{Signal: Congested, Reason: reason, RetryAfter: 3 * time.Second})
	}
	if err := c.Acquire(t.Context(), host); err == nil {
		t.Fatal("the breaker is not open after a run of push-back answers")
	}
	s := c.Summary()
	if s.Budget == nil || s.Budget.RPS != 20 || s.Budget.Level != "standard" {
		t.Fatalf("summary budget %+v", s.Budget)
	}
	if s.Backoffs < 3 || s.CircuitOpens != 1 || len(s.HostStats) != 1 {
		t.Fatalf("summary %+v", s)
	}
	hs := s.HostStats[0]
	if hs.Host != host || hs.HTTP429 != 3 || hs.HTTP503 != 2 || hs.RetryAfterSeconds != 3 || hs.CircuitOpens != 1 || hs.Min >= 5 {
		t.Fatalf("host stat %+v", hs)
	}
	if len(s.Gaps) != 1 || s.Gaps[0].Reason != GapThrottled {
		t.Fatalf("gaps %+v", s.Gaps)
	}
	for _, want := range []string{"throttled by target:", "429=3", "503=2", "retry_after=3s", "circuit_opens=1"} {
		if !strings.Contains(s.Gaps[0].Detail, want) {
			t.Fatalf("gap detail %q lacks %q", s.Gaps[0].Detail, want)
		}
	}
}

// Push-back answers of one burst count once, an ordinary HTTP answer ends
// the run, and bytes on a tunnel nobody read do not.
func TestThrottleRunCounting(t *testing.T) {
	t.Run("a burst counts once", func(t *testing.T) {
		c, _ := testCtl(t, 20)
		for range 50 {
			c.Report("h", Event{Signal: Congested, Reason: ReasonHTTP429})
		}
		if s := c.Summary(); s.CircuitOpens != 0 || s.Backoffs != 1 {
			t.Fatalf("one burst: %+v", s)
		}
	})
	t.Run("an ordinary answer ends the run", func(t *testing.T) {
		c, clk := testCtl(t, 20)
		for range 3 * TargetRate.ThrottleRun {
			*clk = clk.Add(TargetRate.ThrottleSpacing)
			c.Report("h", Event{Signal: Congested, Reason: ReasonHTTP429})
			c.Report("h", Event{Signal: Answered})
		}
		if s := c.Summary(); s.CircuitOpens != 0 {
			t.Fatalf("a host that also answers was opened: %+v", s)
		}
	})
	t.Run("an opaque answer does not end the run", func(t *testing.T) {
		c, clk := testCtl(t, 20)
		for range TargetRate.ThrottleRun {
			*clk = clk.Add(TargetRate.ThrottleSpacing)
			c.Report("h", Event{Signal: Congested, Reason: ReasonHTTP429})
			c.Report("h", Event{Signal: Answered, Opaque: true})
		}
		if s := c.Summary(); s.CircuitOpens != 1 || len(s.Gaps) != 1 || s.Gaps[0].Reason != GapThrottled {
			t.Fatalf("summary %+v", s)
		}
	})
}

// The breaker stays open at least as long as the host asked (Retry-After),
// then one request probes it and an ordinary answer closes it: the host
// recovers, slowly, from the lowered rate.
func TestThrottleBreakerHonorsRetryAfterAndRecovers(t *testing.T) {
	c, clk := testCtl(t, 20)
	host := "a.example.com"
	c.Report(host, Event{Signal: Answered})
	for range TargetRate.ThrottleRun {
		*clk = clk.Add(TargetRate.Window)
		c.Report(host, Event{Signal: Congested, Reason: ReasonHTTP429, RetryAfter: 60 * time.Second})
	}
	*clk = clk.Add(30 * time.Second) // past the breaker's own 15 s, inside the Retry-After
	if err := c.Acquire(t.Context(), host); err == nil {
		t.Fatal("a connection went out inside the host's Retry-After")
	}
	*clk = clk.Add(31 * time.Second)
	if err := c.Acquire(t.Context(), host); err != nil {
		t.Fatalf("no probe after the Retry-After: %v", err)
	}
	c.Report(host, Event{Signal: Answered})
	low := c.Rate(host)
	if low > 20*TargetRate.DecreaseFactor {
		t.Fatalf("rate after the back-off is %v", low)
	}
	for range 30 {
		clean(c, clk, host)
	}
	if got := c.Rate(host); got != 20 {
		t.Fatalf("the rate did not recover to the budget: %v", got)
	}
	var steps []float64
	c2, clk2 := testCtl(t, 20)
	c2.Report(host, Event{Signal: Congested, Reason: ReasonHTTP429})
	for range 4 {
		clean(c2, clk2, host)
		steps = append(steps, c2.Rate(host))
	}
	// The window of the push-back raises nothing; then additive increase:
	// a tenth of the ceiling per clean window.
	if !slices.Equal(steps, []float64{2.5, 4.5, 6.5, 8.5}) {
		t.Fatalf("recovery steps %v", steps)
	}
}

// A reset or a timeout of the canary's request is a failure that lowers the
// rate (unlike the reset of one tool request), and from a host that served
// the canary before it is throttling, not an unreachable host.
func TestProbeFailuresLowerTheRateAndAreThrottling(t *testing.T) {
	c, clk := testCtl(t, 20)
	host := "a.example.com"
	c.Report(host, Event{Signal: Connected})
	c.Report(host, Event{Signal: Answered})
	before := c.Rate(host)
	// A tool request reset by the host does not lower the rate.
	c.Report(host, Event{Signal: Failed, Reason: ReasonReset})
	if c.Rate(host) != before {
		t.Fatal("a refused tool request lowered the rate")
	}
	for i := range TargetRate.BreakerFailures {
		*clk = clk.Add(TargetRate.Window)
		reason := ReasonReset
		if i%2 == 1 {
			reason = ReasonTimeout
		}
		c.Report(host, Event{Signal: Failed, Reason: reason, Probe: true})
	}
	s := c.Summary()
	if s.CircuitOpens != 1 || len(s.Gaps) != 1 || s.Gaps[0].Reason != GapThrottled {
		t.Fatalf("summary %+v", s)
	}
	if hs := s.HostStats[0]; hs.Resets != 4 || hs.Timeouts != 2 || hs.Backoffs < 3 {
		t.Fatalf("host stat %+v", hs)
	}
	// A host that never answered stays unreachable (breaker_open).
	c2, clk2 := testCtl(t, 20)
	for range TargetRate.BreakerFailures {
		*clk2 = clk2.Add(TargetRate.Window)
		c2.Report("dead.example.com", Event{Signal: Failed, Reason: ReasonTimeout, Probe: true})
	}
	_ = c2.Acquire(t.Context(), "dead.example.com")
	if s := c2.Summary(); len(s.Gaps) != 1 || s.Gaps[0].Reason != GapBreakerOpen {
		t.Fatalf("a host that never answered: %+v", s.Gaps)
	}
}

// The canary's request forbidden by a host that served it before is a block
// after ThrottleRun of them; a host whose root is forbidden from the first
// request on is not (the canary reports that as an ordinary answer).
func TestProbeForbiddenIsABlock(t *testing.T) {
	c, clk := testCtl(t, 20)
	c.Report("h", Event{Signal: Answered})
	for range TargetRate.ThrottleRun {
		*clk = clk.Add(TargetRate.Window)
		c.Report("h", Event{Signal: Forbidden, Probe: true})
	}
	if s := c.Summary(); len(s.Gaps) != 1 || s.Gaps[0].Reason != GapBlocked || s.CircuitOpens != 1 {
		t.Fatalf("summary %+v", s)
	}
}
