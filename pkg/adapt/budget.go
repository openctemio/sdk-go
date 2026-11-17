package adapt

import "fmt"

// HostBudget is what one target host may get from one job, whatever tool
// runs and however many of the job's targets name that host: requests per
// second and requests in flight. A host is the politeness host of a target
// in canonical form (HostKey): a name or an address without scheme, port or
// path, so http://a.example.com/x, https://a.example.com:8443 and
// a.example.com:22 share one budget, and so do two spellings of one host.
// Where the address a name is reached at is known (a confined task's
// forwarder), names that resolve to one address also share that address's
// budget.
//
// Where it comes from (ResolveBudget): the LOWEST limit wins, for each of
// the two numbers on its own:
//
//   - the sensor's level (DefaultPacing, Standard, unless the sensor's own
//     operator set another);
//   - the job's signed budget (JobBudget), when the job carries one;
//   - the operator's ceiling on the sensor (BudgetCeiling);
//   - the built-in hard ceiling (HardCeilingRPS, HardCeilingInflight).
//
// A job can therefore only lower what a host gets. Only the sensor's own
// operator raises it (the sensor's level, within the ceilings).
//
// Who enforces it, and how far, is in docs/host-budget.md. In short: a
// confined task's forwarder paces every connection, every request it reads
// and every request it can tell apart on a tunnel it passes through, per
// host and per address, under RPS (HostRate), and holds at most Inflight
// connections to a host open; each tool's flags are derived from the same
// budget (Pacing, ToolPace) and are the enforcement for what the forwarder
// cannot count (requests packed into one TLS record, the streams in flight
// on one HTTP/2 connection) and for a task without a forwarder, where a
// tool whose rate flag is global to its process runs at one host's budget
// in all (ToolPace with enforced false).
type HostBudget struct {
	// Level is the pacing level the budget follows ("gentle", "standard",
	// "fast"), or "custom" when its numbers are not a level's.
	Level string `json:"level"`
	// RPS is the most requests per second toward one host.
	RPS int `json:"rps"`
	// Inflight is the most requests in flight toward one host.
	Inflight int `json:"inflight"`
	// WonBy names, for each number, the limit that set it (the lowest).
	WonBy BudgetWon `json:"won_by"`
	// Clamped lists every value that was asked for and did not apply
	// because a lower limit won (empty: none): the sensor's level or the
	// job's budget above another limit (ResolveBudget), and a rate or
	// concurrency setting of the scan above the budget (Clamp).
	Clamped []BudgetClamp `json:"clamped,omitempty"`
}

// BudgetWon names the limit that set each number of a budget.
type BudgetWon struct {
	RPS      string `json:"rps"`
	Inflight string `json:"inflight"`
}

// The limits of a budget, as BudgetWon and BudgetClamp.By name them.
const (
	// LimitSensorLevel: the sensor's own pacing level.
	LimitSensorLevel = "sensor_level"
	// LimitJob: the budget of the job's signed statement.
	LimitJob = "job"
	// LimitOperatorCeiling: the ceiling of the sensor's local policy.
	LimitOperatorCeiling = "operator_ceiling"
	// LimitHardCeiling: the built-in hard ceiling.
	LimitHardCeiling = "hard_ceiling"
	// LimitHostBudget: the resolved budget itself, which lowered a rate or
	// concurrency setting of the scan (HostBudget.Clamp).
	LimitHostBudget = "host_budget"
)

// LevelCustom is the Level of a budget whose numbers are not a level's.
const LevelCustom = "custom"

// BudgetClamp is one value that was asked for and did not apply.
type BudgetClamp struct {
	// Key is "rps" or "inflight" for a number of the budget, or the name of
	// the scan's setting that was lowered ("rate_limit", "concurrency",
	// "threads", a tool's rate key).
	Key string `json:"key"`
	// Asked is the value that was asked for, To the value that applies.
	Asked int `json:"asked"`
	To    int `json:"to"`
	// By is the limit that won (a Limit constant). For a budget number
	// Source says who asked: LimitSensorLevel or LimitJob.
	By     string `json:"by"`
	Source string `json:"source,omitempty"`
}

// Clamp records that a setting of the scan (key: its settings key) asked
// for more than the budget allows and was lowered to to. A key recorded
// before is replaced. It does nothing when asked is not above to.
func (b *HostBudget) Clamp(key string, asked, to int) {
	if b == nil || asked <= to {
		return
	}
	c := BudgetClamp{Key: key, Asked: asked, To: to, By: LimitHostBudget}
	for i := range b.Clamped {
		if b.Clamped[i].Key == key && b.Clamped[i].By == LimitHostBudget {
			b.Clamped[i] = c
			return
		}
	}
	b.Clamped = append(b.Clamped, c)
}

// JobBudget is the budget a job carries in its signed statement
// (jobsig.Statement.Pacing). A zero number takes the level's; a job without
// a level and without numbers carries no budget. It can only lower what a
// host gets on the sensor that runs it (ResolveBudget).
type JobBudget struct {
	Level    string `json:"level,omitempty"`
	RPS      int    `json:"target_rps,omitempty"`
	Inflight int    `json:"target_inflight,omitempty"`
}

// MaxJobBudget bounds the numbers a job's budget may name: nonsense is
// refused when the statement is verified, long before any ceiling.
const MaxJobBudget = 100_000

// Validate checks a job's budget: a known level (or none) and numbers from
// 0 to MaxJobBudget, with at least one of them set.
func (j JobBudget) Validate() error {
	if _, ok := PacingFor(j.Level); !ok && j.Level != LevelCustom {
		return fmt.Errorf("unknown pacing level %q", j.Level)
	}
	if j.RPS < 0 || j.RPS > MaxJobBudget || j.Inflight < 0 || j.Inflight > MaxJobBudget {
		return fmt.Errorf("pacing numbers must be from 0 to %d", MaxJobBudget)
	}
	if j.Level == "" && j.RPS == 0 && j.Inflight == 0 {
		return fmt.Errorf("an empty pacing budget")
	}
	if j.Level == LevelCustom && (j.RPS == 0 || j.Inflight == 0) {
		return fmt.Errorf("a custom pacing budget names target_rps and target_inflight")
	}
	return nil
}

// numbers are the two limits the job's budget names (0: it names none for
// that number). A budget that does not validate reads as Gentle: a
// statement with one is refused when it is verified, and should one reach
// here all the same it never runs faster than the lowest level.
func (j JobBudget) numbers() (rps, inflight int) {
	if j.Validate() != nil {
		return PacingGentle.TargetRPS, PacingGentle.TargetInflight
	}
	if p, ok := PacingFor(j.Level); ok && j.Level != "" {
		rps, inflight = p.TargetRPS, p.TargetInflight
	}
	if j.RPS > 0 {
		rps = j.RPS
	}
	if j.Inflight > 0 {
		inflight = j.Inflight
	}
	return rps, inflight
}

// BudgetCeiling is the most any job may get per host on this sensor: the
// operator's ceiling. A zero field is "not set".
type BudgetCeiling struct {
	RPS      int
	Inflight int
}

// The built-in hard ceiling: 200 requests/s and 50 in flight per host. It
// is the most an operator's ceiling can be and the ceiling when the
// operator set none. Constants: nothing in the process can move them.
const (
	HardCeilingRPS      = 200
	HardCeilingInflight = 50
)

// HardBudgetCeiling is the built-in hard ceiling as a BudgetCeiling.
func HardBudgetCeiling() BudgetCeiling {
	return BudgetCeiling{RPS: HardCeilingRPS, Inflight: HardCeilingInflight}
}

// ResolveBudget is the budget of one job: for each number, the LOWEST of
// the sensor's level, the job's signed budget (when it carries one), the
// operator's ceiling (when set) and the built-in hard ceiling. WonBy names
// the limit that set each number (on a tie the first in that order), and
// Clamped lists the sensor's level and the job's budget where a lower
// limit won over them.
//
// A job can only lower: a signed Fast on a Standard sensor runs Standard.
// The sensor's operator raises the level (within the ceilings) when the
// hosts are the operator's own.
//
// job must come from the job's verified statement, never from its unsigned
// payload. A level that is not a level (a zero Pacing) runs Gentle.
func ResolveBudget(level Pacing, job *JobBudget, ceiling BudgetCeiling) HostBudget {
	if level.TargetRPS <= 0 || level.TargetInflight <= 0 {
		level = PacingGentle
	}
	type limit struct {
		name          string
		rps, inflight int // 0: this limit names none
	}
	limits := []limit{{LimitSensorLevel, level.TargetRPS, level.TargetInflight}}
	if job != nil {
		rps, inflight := job.numbers()
		limits = append(limits, limit{LimitJob, rps, inflight})
	}
	limits = append(limits,
		limit{LimitOperatorCeiling, max(ceiling.RPS, 0), max(ceiling.Inflight, 0)},
		limit{LimitHardCeiling, HardCeilingRPS, HardCeilingInflight})
	var b HostBudget
	for _, l := range limits {
		if l.rps > 0 && (b.RPS == 0 || l.rps < b.RPS) {
			b.RPS, b.WonBy.RPS = l.rps, l.name
		}
		if l.inflight > 0 && (b.Inflight == 0 || l.inflight < b.Inflight) {
			b.Inflight, b.WonBy.Inflight = l.inflight, l.name
		}
	}
	// What the sensor's level and the job asked for and did not get.
	for _, l := range limits[:len(limits)-2] {
		if l.rps > b.RPS {
			b.Clamped = append(b.Clamped, BudgetClamp{Key: "rps", Asked: l.rps, To: b.RPS, By: b.WonBy.RPS, Source: l.name})
		}
		if l.inflight > b.Inflight {
			b.Clamped = append(b.Clamped, BudgetClamp{Key: "inflight", Asked: l.inflight, To: b.Inflight, By: b.WonBy.Inflight, Source: l.name})
		}
	}
	b.Level = levelOf(b.RPS, b.Inflight)
	return b
}

// levelOf names the level whose per-host numbers are rps and inflight, or
// LevelCustom.
func levelOf(rps, inflight int) string {
	for _, p := range []Pacing{PacingGentle, PacingStandard, PacingFast} {
		if p.TargetRPS == rps && p.TargetInflight == inflight {
			return p.Name
		}
	}
	return LevelCustom
}

// DefaultBudget is the budget of a job that carries none on a sensor whose
// operator set nothing: Standard.
func DefaultBudget() HostBudget { return ResolveBudget(DefaultPacing, nil, BudgetCeiling{}) }

// Valid reports whether b names a budget (a zero HostBudget does not).
func (b HostBudget) Valid() bool { return b.RPS > 0 && b.Inflight > 0 }

// Pacing is the pacing level a tool adapter maps to its flags under the
// budget: the level the budget follows (for a custom budget, the fastest
// level that is not above it), with its per-host numbers replaced by the
// budget's and every other rate lowered to stay under them.
func (b HostBudget) Pacing() Pacing {
	if !b.Valid() {
		return DefaultPacing
	}
	p := PacingGentle
	for _, l := range []Pacing{PacingStandard, PacingFast} {
		if l.TargetRPS <= b.RPS {
			p = l
		}
	}
	p.Name = b.Level
	p.TargetRPS, p.TargetInflight = b.RPS, b.Inflight
	p.StartRPS = max(1, min(p.StartRPS, b.RPS))
	return p
}

// ToolPace is a budget as the numbers a tool's flags take for one run over
// hosts distinct hosts.
type ToolPace struct {
	// Rate is the run's request rate in all (a tool's global rate flag).
	Rate int
	// Inflight is the run's requests in flight in all (a tool's worker or
	// thread flag).
	Inflight int
	// HostInflight is the most requests in flight toward one host (a
	// tool's per-host concurrency flag, where it has one).
	HostInflight int
	// Hosts is how many hosts the run works at once (a tool's bulk flag).
	Hosts int
}

// ToolPace maps the budget to a run over hosts distinct hosts.
//
// enforced says that something outside the tool holds each host to the
// budget (a confined task's forwarder). The run may then work up to the
// level's ParallelHosts hosts at once, each at the budget: Rate is RPS
// times those hosts. Without it the tool's own flags are all there is, and
// a rate flag that is global to the process cannot be split per host: the
// whole run then gets one host's budget, so no host can receive more
// whatever the tool does with its list.
func (b HostBudget) ToolPace(hosts int, enforced bool) ToolPace {
	p := b.Pacing()
	n := 1
	if enforced {
		n = p.JobHosts(hosts)
	}
	return ToolPace{Rate: p.TargetRPS * n, Inflight: p.TargetInflight * n, HostInflight: p.TargetInflight, Hosts: p.BulkHosts(hosts)}
}

// SweepPace maps the budget to a tool that sends a few requests to each of
// many hosts (an HTTP probe over a list): the level's sweep rate and
// workers, never more than the budgets of the hosts the run names in all.
// A list of one host's URLs therefore runs at that host's budget, not at
// the sweep rate. enforced is as in ToolPace: without it the whole run gets
// one host's budget, whatever the list. A list cannot be read for the
// addresses its names share, so only something in the path (the forwarder,
// which counts per address) makes the sweep rate safe.
func (b HostBudget) SweepPace(hosts int, enforced bool) ToolPace {
	p := b.Pacing()
	n := 1
	if enforced {
		n = max(hosts, 1)
	}
	rate, inflight := p.TargetRPS, p.TargetInflight
	if n > 1 {
		rate = min(p.SweepRPS, saturatingMul(p.TargetRPS, n))
		inflight = min(p.SweepInflight, saturatingMul(p.TargetInflight, n))
	}
	return ToolPace{Rate: max(rate, 1), Inflight: max(inflight, 1), HostInflight: p.TargetInflight, Hosts: n}
}

func saturatingMul(a, b int) int {
	if a > 0 && b > MaxJobBudget*MaxJobBudget/a {
		return MaxJobBudget * MaxJobBudget
	}
	return a * b
}

// GroupHosts groups targets by HostKey, in the order each host first
// appears; a target that names no host is its own group.
func GroupHosts(targets []string) [][]string {
	idx := map[string]int{}
	var out [][]string
	for _, t := range targets {
		k := HostKey(t)
		if k == "" {
			out = append(out, []string{t})
			continue
		}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], t)
	}
	return out
}

// CountHosts is how many distinct hosts targets name (at least 1), and
// the most targets any one of them has.
func CountHosts(targets []string) (hosts, maxPerHost int) {
	groups := GroupHosts(targets)
	for _, g := range groups {
		maxPerHost = max(maxPerHost, len(g))
	}
	return max(len(groups), 1), max(maxPerHost, 1)
}
