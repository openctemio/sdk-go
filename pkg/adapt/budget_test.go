package adapt

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/contract/edgeprotect"
)

// The LOWEST limit wins, for each number on its own: the sensor's level,
// the job's signed budget, the operator's ceiling, the built-in hard
// ceiling. A job can only lower what a host gets.
func TestResolveBudget(t *testing.T) {
	gentle := &JobBudget{Level: "gentle"}
	won := func(rps, inflight string) BudgetWon { return BudgetWon{RPS: rps, Inflight: inflight} }
	cases := []struct {
		name    string
		level   Pacing
		job     *JobBudget
		ceiling BudgetCeiling
		want    HostBudget
	}{
		{"no job, no ceiling: Standard", DefaultPacing, nil, BudgetCeiling{},
			HostBudget{Level: "standard", RPS: 20, Inflight: 8, WonBy: won(LimitSensorLevel, LimitSensorLevel)}},
		{"a signed Fast on a Standard sensor stays Standard", DefaultPacing, &JobBudget{Level: "fast"}, BudgetCeiling{},
			HostBudget{Level: "standard", RPS: 20, Inflight: 8, WonBy: won(LimitSensorLevel, LimitSensorLevel), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 100, To: 20, By: LimitSensorLevel, Source: LimitJob},
				{Key: "inflight", Asked: 25, To: 8, By: LimitSensorLevel, Source: LimitJob}}}},
		{"a signed Gentle on a Fast sensor is Gentle", PacingFast, gentle, BudgetCeiling{},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, WonBy: won(LimitJob, LimitJob), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 100, To: 5, By: LimitJob, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 25, To: 2, By: LimitJob, Source: LimitSensorLevel}}}},
		{"a ceiling below the level wins", DefaultPacing, nil, BudgetCeiling{RPS: 5, Inflight: 2},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, WonBy: won(LimitOperatorCeiling, LimitOperatorCeiling), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 20, To: 5, By: LimitOperatorCeiling, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 8, To: 2, By: LimitOperatorCeiling, Source: LimitSensorLevel}}}},
		{"an unknown level (a zero Pacing) runs Gentle", Pacing{}, nil, BudgetCeiling{},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, WonBy: won(LimitSensorLevel, LimitSensorLevel)}},
		{"an unknown level in a job's budget runs Gentle", PacingFast, &JobBudget{Level: "ludicrous", RPS: 9000}, BudgetCeiling{},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, WonBy: won(LimitJob, LimitJob), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 100, To: 5, By: LimitJob, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 25, To: 2, By: LimitJob, Source: LimitSensorLevel}}}},
		{"negative numbers in a job's budget run Gentle", DefaultPacing, &JobBudget{RPS: -1, Inflight: 4}, BudgetCeiling{},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, WonBy: won(LimitJob, LimitJob), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 20, To: 5, By: LimitJob, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 8, To: 2, By: LimitJob, Source: LimitSensorLevel}}}},
		{"lower signed numbers win", DefaultPacing, &JobBudget{RPS: 3, Inflight: 1}, BudgetCeiling{},
			HostBudget{Level: LevelCustom, RPS: 3, Inflight: 1, WonBy: won(LimitJob, LimitJob), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 20, To: 3, By: LimitJob, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 8, To: 1, By: LimitJob, Source: LimitSensorLevel}}}},
		{"each number has its own winner", DefaultPacing, &JobBudget{RPS: 10}, BudgetCeiling{Inflight: 4},
			HostBudget{Level: LevelCustom, RPS: 10, Inflight: 4, WonBy: won(LimitJob, LimitOperatorCeiling), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 20, To: 10, By: LimitJob, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 8, To: 4, By: LimitOperatorCeiling, Source: LimitSensorLevel}}}},
		{"a signed number above the level changes nothing", DefaultPacing, &JobBudget{RPS: 5000}, BudgetCeiling{},
			HostBudget{Level: "standard", RPS: 20, Inflight: 8, WonBy: won(LimitSensorLevel, LimitSensorLevel), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 5000, To: 20, By: LimitSensorLevel, Source: LimitJob}}}},
		{"the operator's ceiling beats a Fast sensor and a signed Fast", PacingFast, &JobBudget{Level: "fast"}, BudgetCeiling{RPS: 30, Inflight: 10},
			HostBudget{Level: LevelCustom, RPS: 30, Inflight: 10, WonBy: won(LimitOperatorCeiling, LimitOperatorCeiling), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 100, To: 30, By: LimitOperatorCeiling, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 25, To: 10, By: LimitOperatorCeiling, Source: LimitSensorLevel},
				{Key: "rps", Asked: 100, To: 30, By: LimitOperatorCeiling, Source: LimitJob},
				{Key: "inflight", Asked: 25, To: 10, By: LimitOperatorCeiling, Source: LimitJob}}}},
		{"an operator's ceiling above the hard one is the hard one", Pacing{Name: "lab", TargetRPS: 900, TargetInflight: 60}, nil, BudgetCeiling{RPS: 100000, Inflight: 100000},
			HostBudget{Level: LevelCustom, RPS: 200, Inflight: 50, WonBy: won(LimitHardCeiling, LimitHardCeiling), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 900, To: 200, By: LimitHardCeiling, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 60, To: 50, By: LimitHardCeiling, Source: LimitSensorLevel}}}},
		{"a lower signed budget under a ceiling stays", DefaultPacing, gentle, BudgetCeiling{RPS: 10, Inflight: 4},
			HostBudget{Level: "gentle", RPS: 5, Inflight: 2, WonBy: won(LimitJob, LimitJob), Clamped: []BudgetClamp{
				{Key: "rps", Asked: 20, To: 5, By: LimitJob, Source: LimitSensorLevel},
				{Key: "inflight", Asked: 8, To: 2, By: LimitJob, Source: LimitSensorLevel}}}},
		{"the operator's own level applies when nothing is lower", PacingFast, nil, BudgetCeiling{},
			HostBudget{Level: "fast", RPS: 100, Inflight: 25, WonBy: won(LimitSensorLevel, LimitSensorLevel)}},
		{"a tie goes to the sensor's level", DefaultPacing, &JobBudget{Level: "standard"}, BudgetCeiling{RPS: 20, Inflight: 8},
			HostBudget{Level: "standard", RPS: 20, Inflight: 8, WonBy: won(LimitSensorLevel, LimitSensorLevel)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveBudget(tc.level, tc.job, tc.ceiling)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// SECURITY: whatever the level, the job and the ceiling say, the budget is
// never above any of them: no job raises what a host gets above the
// sensor's level, and nothing passes the operator's or the hard ceiling.
func TestResolveBudgetNeverExceedsAnyLimit(t *testing.T) {
	levels := []Pacing{PacingGentle, PacingStandard, PacingFast, {}, {Name: "lab", TargetRPS: 5000, TargetInflight: 500}}
	jobs := []*JobBudget{nil, {Level: "gentle"}, {Level: "standard"}, {Level: "fast"}, {RPS: 1}, {Inflight: 1}, {RPS: 99999, Inflight: 99999},
		{Level: "custom", RPS: 150, Inflight: 40}, {Level: "nope"}, {RPS: -5}, {}}
	ceilings := []BudgetCeiling{{}, {RPS: 1, Inflight: 1}, {RPS: 30}, {Inflight: 3}, {RPS: 100000, Inflight: 100000}, {RPS: -1, Inflight: -1}}
	for _, l := range levels {
		for _, j := range jobs {
			for _, c := range ceilings {
				b := ResolveBudget(l, j, c)
				if !b.Valid() || b.WonBy.RPS == "" || b.WonBy.Inflight == "" {
					t.Fatalf("level %+v job %+v ceiling %+v: %+v", l, j, c, b)
				}
				lr, li := l.TargetRPS, l.TargetInflight
				if lr <= 0 || li <= 0 {
					lr, li = PacingGentle.TargetRPS, PacingGentle.TargetInflight
				}
				if b.RPS > lr || b.Inflight > li {
					t.Fatalf("job %+v raised the budget above the sensor's level %+v: %+v", j, l, b)
				}
				if b.RPS > HardCeilingRPS || b.Inflight > HardCeilingInflight {
					t.Fatalf("above the hard ceiling: %+v", b)
				}
				if (c.RPS > 0 && b.RPS > c.RPS) || (c.Inflight > 0 && b.Inflight > c.Inflight) {
					t.Fatalf("above the operator's ceiling %+v: %+v", c, b)
				}
				if j != nil && j.Validate() == nil {
					jr, ji := j.numbers()
					if (jr > 0 && b.RPS > jr) || (ji > 0 && b.Inflight > ji) {
						t.Fatalf("above the job's own budget %+v: %+v", j, b)
					}
				}
			}
		}
	}
}

// A setting of the scan above the budget is recorded with what was asked
// and what applies; the same key is recorded once.
func TestBudgetClampRecordsAskedAndApplied(t *testing.T) {
	b := DefaultBudget()
	b.Clamp("rate_limit", 150, 20)
	b.Clamp("concurrency", 8, 8) // not above: nothing to record
	b.Clamp("rate_limit", 150, 20)
	want := []BudgetClamp{{Key: "rate_limit", Asked: 150, To: 20, By: LimitHostBudget}}
	if !reflect.DeepEqual(b.Clamped, want) {
		t.Fatalf("clamped %+v", b.Clamped)
	}
	var none *HostBudget
	none.Clamp("rate_limit", 150, 20) // a nil budget records nothing and does not panic
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
		name           string
		hosts          int
		enforced       bool
		rate, inflight int
	}{
		{"one host with 500 URLs runs at that host's budget", 1, true, 20, 8},
		{"two hosts: their budgets in all", 2, true, 40, 16},
		{"many hosts: the sweep rate", 1000, true, 50, 25},
		// Without a forwarder nothing counts per address, and the names of
		// a list may all be one server: one host's budget, whatever the list.
		{"many hosts, not enforced: one host's budget", 1000, false, 20, 8},
		{"two hosts, not enforced: one host's budget", 2, false, 20, 8},
	}
	for _, tc := range cases {
		got := std.SweepPace(tc.hosts, tc.enforced)
		if got.Rate != tc.rate || got.Inflight != tc.inflight {
			t.Errorf("%s: got %d/s and %d in flight, want %d and %d", tc.name, got.Rate, got.Inflight, tc.rate, tc.inflight)
		}
	}
}

func TestBudgetPacingKeepsEveryRateUnderTheBudget(t *testing.T) {
	lab := Pacing{Name: "lab", TargetRPS: 150, TargetInflight: 40}
	for _, b := range []HostBudget{DefaultBudget(),
		ResolveBudget(DefaultPacing, &JobBudget{Level: "gentle"}, BudgetCeiling{}),
		ResolveBudget(PacingFast, nil, BudgetCeiling{}),
		ResolveBudget(DefaultPacing, &JobBudget{RPS: 1, Inflight: 1}, BudgetCeiling{}),
		ResolveBudget(lab, nil, BudgetCeiling{})} {
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

// SECURITY: a host that answers only the canary with push-back is slowed
// and never stopped: whatever the canary is answered (429 with a long
// Retry-After, 503, a refusal, resets), the breaker stays closed, the
// tool's connections are never refused or held and no cooldown starts.
// Rate limits (429, 503) are reported as an observed throttle (a gap that
// stops nothing); a refusal or resets of the canary alone are no gap.
func TestCanaryPushbackAloneNeverOpensTheBreaker(t *testing.T) {
	signals := map[string]Event{
		"429 with a long Retry-After": {Signal: Congested, Reason: ReasonHTTP429, RetryAfter: 5 * time.Minute, Probe: true},
		"503":                         {Signal: Congested, Reason: ReasonHTTP503, Probe: true},
		"403 after it was served":     {Signal: Forbidden, Probe: true},
		"reset":                       {Signal: Failed, Reason: ReasonReset, Probe: true},
		"timeout":                     {Signal: Failed, Reason: ReasonTimeout, Probe: true},
	}
	for name, e := range signals {
		t.Run(name, func(t *testing.T) {
			c, clk := testCtl(t, 20)
			shared := NewSensorRate()
			c.Share(shared, "tenant-a")
			host := "a.example.com"
			c.Report(host, Event{Signal: Connected})
			c.Report(host, Event{Signal: Answered, Probe: true})
			before := c.Rate(host)
			for range 50 {
				*clk = clk.Add(TargetRate.Window)
				c.Report(host, e)
			}
			s := c.Summary()
			if s.CircuitOpens != 0 || s.Unreachable != 0 {
				t.Fatalf("canary push-back alone opened the breaker: %+v", s)
			}
			if e.Signal == Congested {
				if s.GapsTotal != 1 || s.Gaps[0].Reason != GapThrottled || !s.Gaps[0].Observed {
					t.Fatalf("the canary's rate limits are not an observed throttle: %+v", s.Gaps)
				}
			} else if s.GapsTotal != 0 {
				t.Fatalf("canary push-back alone made a gap: %+v", s.Gaps)
			}
			if s.Backoffs == 0 || c.Rate(host) >= before || c.Rate(host) != s.Floor {
				t.Fatalf("the rate was not lowered to the floor: before %.3g, now %.3g, %+v", before, c.Rate(host), s)
			}
			// The tool's next connection goes out, without waiting for the
			// canary's Retry-After.
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if err := c.Acquire(ctx, host); err != nil {
				t.Fatalf("a tool connection was refused or held: %v", err)
			}
			if until := shared.Cooldown("tenant-a", host); !until.IsZero() {
				t.Fatalf("the canary alone started a cooldown until %v", until)
			}
		})
	}
}

// The canary's push-back together with failures of the tool's own
// connections opens the breaker, and the outcome records that evidence.
// The tool's failures alone (fewer than BreakerFailures of them) do not.
func TestCanaryPushbackWithConnectionFailuresOpensTheBreaker(t *testing.T) {
	host := "a.example.com"
	t.Run("the tool's resets alone do not", func(t *testing.T) {
		c, _ := testCtl(t, 20)
		c.Report(host, Event{Signal: Connected})
		for range TargetRate.CorroborateFailures + 1 {
			c.Report(host, Event{Signal: Failed, Reason: ReasonReset})
		}
		if s := c.Summary(); s.CircuitOpens != 0 {
			t.Fatalf("resets alone opened the breaker: %+v", s)
		}
	})
	for _, order := range []string{"canary first", "resets first"} {
		t.Run(order, func(t *testing.T) {
			c, clk := testCtl(t, 20)
			c.Report(host, Event{Signal: Connected})
			c.Report(host, Event{Signal: Answered, Probe: true})
			push := func() {
				c.Report(host, Event{Signal: Congested, Reason: ReasonHTTP429, Probe: true})
			}
			resets := func() {
				for range TargetRate.CorroborateFailures {
					*clk = clk.Add(time.Second)
					c.Report(host, Event{Signal: Failed, Reason: ReasonReset})
				}
			}
			if order == "canary first" {
				push()
				resets()
			} else {
				resets()
				push()
			}
			s := c.Summary()
			if s.CircuitOpens != 1 || len(s.Gaps) != 1 || s.Gaps[0].Reason != GapThrottled {
				t.Fatalf("summary %+v", s)
			}
			if hs := s.HostStats[0]; hs.OpenedBy != EvidenceCanaryAndConnection || hs.HTTP429 != 1 || hs.Resets != TargetRate.CorroborateFailures {
				t.Fatalf("host stat %+v", hs)
			}
			if !strings.Contains(s.Gaps[0].Detail, "opened_by="+EvidenceCanaryAndConnection) {
				t.Fatalf("gap detail %q", s.Gaps[0].Detail)
			}
			if err := c.Acquire(t.Context(), host); !errors.Is(err, ErrHostUnavailable) {
				t.Fatalf("the breaker is not open: %v", err)
			}
		})
	}
	t.Run("evidence further apart than the window does not", func(t *testing.T) {
		c, clk := testCtl(t, 20)
		c.Report(host, Event{Signal: Connected})
		c.Report(host, Event{Signal: Answered, Probe: true})
		c.Report(host, Event{Signal: Congested, Reason: ReasonHTTP429, Probe: true})
		*clk = clk.Add(TargetRate.CorroborateWindow + time.Second)
		for range TargetRate.CorroborateFailures {
			c.Report(host, Event{Signal: Failed, Reason: ReasonReset})
		}
		if s := c.Summary(); s.CircuitOpens != 0 {
			t.Fatalf("stale canary push-back opened the breaker: %+v", s)
		}
	})
	t.Run("an ordinary answer to the canary ends its push-back", func(t *testing.T) {
		c, _ := testCtl(t, 20)
		c.Report(host, Event{Signal: Connected})
		c.Report(host, Event{Signal: Congested, Reason: ReasonHTTP429, Probe: true})
		c.Report(host, Event{Signal: Answered, Probe: true})
		for range TargetRate.CorroborateFailures {
			c.Report(host, Event{Signal: Failed, Reason: ReasonReset})
		}
		if s := c.Summary(); s.CircuitOpens != 0 {
			t.Fatalf("summary %+v", s)
		}
	})
}

// Push-back read on the tool's own HTTP answers opens the breaker as
// before, and the outcome says so.
func TestToolEvidenceIsRecorded(t *testing.T) {
	c, clk := testCtl(t, 20)
	for range TargetRate.ThrottleRun {
		*clk = clk.Add(TargetRate.ThrottleSpacing)
		c.ReportHTTP("h", 429, "")
	}
	if s := c.Summary(); s.CircuitOpens != 1 || s.HostStats[0].OpenedBy != EvidenceToolHTTP {
		t.Fatalf("summary %+v", s)
	}
	c2, clk2 := testCtl(t, 20)
	c2.ReportDial("h", 443, nil)
	for range TargetRate.BreakerFailures {
		*clk2 = clk2.Add(TargetRate.Window)
		c2.Report("h", Event{Signal: Failed, Reason: ReasonTimeout})
	}
	if s := c2.Summary(); s.CircuitOpens != 1 || s.HostStats[0].OpenedBy != EvidenceToolConnection {
		t.Fatalf("summary %+v", s)
	}
}

// Names that are reached at one address share that address's rate: what
// one name is answered slows the address for both, and only slows it. The
// name that was pushed back opens its own breaker; the other name and the
// address stay reachable, and the address is not listed as a host or a gap
// of its own.
func TestAddressStateIsSharedByItsNames(t *testing.T) {
	c, clk := testCtl(t, 20)
	addr := "192.0.2.10"
	for _, n := range []string{"a.example.com", "b.example.com"} {
		if err := c.Acquire(t.Context(), n); err != nil {
			t.Fatal(err)
		}
		if err := c.AcquireAddr(t.Context(), addr); err != nil {
			t.Fatal(err)
		}
	}
	before := c.Rate(addr)
	for range TargetRate.ThrottleRun {
		*clk = clk.Add(TargetRate.Window)
		c.ReportHTTP("a.example.com", 429, "")
		c.ReportAddrResponse(addr, 429, "", edgeprotect.Verdict{})
	}
	if err := c.Acquire(t.Context(), "a.example.com"); !errors.Is(err, ErrHostUnavailable) {
		t.Fatalf("the breaker of the name that was pushed back is not open: %v", err)
	}
	if got := c.Rate(addr); got >= before {
		t.Fatalf("the address was not slowed: %.3g, before %.3g", got, before)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := c.AcquireAddr(ctx, addr); err != nil {
		t.Fatalf("the address refused a connection: %v", err)
	}
	if err := c.Acquire(ctx, "b.example.com"); err != nil {
		t.Fatalf("b's own state should be healthy: %v", err)
	}
	s := c.Summary()
	if s.Hosts != 2 || s.GapsTotal != 1 || s.Gaps[0].Host != "a.example.com" {
		t.Fatalf("the address shows as a host or a gap: %+v", s)
	}
	stat := (*HostStat)(nil)
	for i := range s.HostStats {
		if s.HostStats[i].Host == addr {
			stat = &s.HostStats[i]
		}
	}
	if stat == nil || !stat.Address || stat.CircuitOpens != 0 || stat.Backoffs == 0 {
		t.Fatalf("host stats %+v", s.HostStats)
	}
	// A target that names the address is a host.
	if err := c.Acquire(ctx, addr); err != nil {
		t.Fatal(err)
	}
	if s := c.Summary(); s.Hosts != 3 {
		t.Fatalf("hosts %d", s.Hosts)
	}
}
