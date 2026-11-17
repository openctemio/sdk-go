package adapt

import (
	"fmt"

	"github.com/openctemio/contract/politeness"
)

// HostBudget is what one target host may get from one job, whatever tool
// runs and however many of the job's targets name that host: requests per
// second and requests in flight. A host is the politeness host of a target
// (HostKey): a name or an address without scheme, port or path, so
// http://a.example.com/x, https://a.example.com:8443 and a.example.com:22
// share one budget.
//
// Where it comes from (ResolveBudget), lowest wins:
//
//   - the sensor's level (DefaultPacing, Standard, unless the sensor's own
//     operator set another);
//   - the job's signed budget (JobBudget), when the job carries one;
//   - the operator's ceiling on the sensor (BudgetCeiling), which no job
//     passes.
//
// Who enforces it: a confined task's forwarder paces every connection and
// request it reads per host under RPS (HostRate) and holds at most Inflight
// connections to a host open; each tool's flags are derived from the same
// budget (Pacing, ToolPace), so a tool does not queue behind the forwarder.
// Without a forwarder the derived flags are the enforcement, and a tool
// whose rate flag is global to its process runs at one host's budget in
// all (ToolPace with enforced false).
type HostBudget struct {
	// Level is the pacing level the budget follows ("gentle", "standard",
	// "fast"), or "custom" when its numbers are not a level's.
	Level string `json:"level"`
	// RPS is the most requests per second toward one host.
	RPS int `json:"rps"`
	// Inflight is the most requests in flight toward one host.
	Inflight int `json:"inflight"`
	// Source says who set the budget: BudgetFromSensor (the sensor's level;
	// also a job that carries none) or BudgetFromJob (the signed job).
	Source string `json:"source"`
	// Clamped lists what was lowered and why (empty: nothing was).
	Clamped []BudgetClamp `json:"clamped,omitempty"`
}

// Budget sources.
const (
	BudgetFromSensor = "sensor"
	BudgetFromJob    = "job"
)

// LevelCustom is the Level of a budget whose numbers are not a level's.
const LevelCustom = "custom"

// BudgetClamp is one value ResolveBudget lowered.
type BudgetClamp struct {
	// Key is "rps" or "inflight".
	Key string `json:"key"`
	// Asked is the value that was asked for, To the value that applies.
	Asked int `json:"asked"`
	To    int `json:"to"`
	// By is what lowered it: ClampByCeiling.
	By string `json:"by"`
}

// ClampByCeiling: the operator's ceiling on the sensor lowered the value.
const ClampByCeiling = "sensor_ceiling"

// JobBudget is the budget a job carries in its signed statement
// (jobsig.Statement.Pacing). A zero number takes the level's; a job without
// a level and without numbers carries no budget.
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

// BudgetCeiling is the most any job may get per host on this sensor: the
// operator's hard ceiling. A zero field is "not set".
type BudgetCeiling struct {
	RPS      int
	Inflight int
}

// HardBudgetCeiling is the ceiling when the operator set none, and the
// most an operator's ceiling can be: 200 requests/s and 50 in flight per
// host. It never adapts and nothing a job says moves it.
var HardBudgetCeiling = BudgetCeiling{RPS: 200, Inflight: 50}

// effective is the ceiling with unset or too-high fields at the hard one.
func (c BudgetCeiling) effective() BudgetCeiling {
	if c.RPS <= 0 || c.RPS > HardBudgetCeiling.RPS {
		c.RPS = HardBudgetCeiling.RPS
	}
	if c.Inflight <= 0 || c.Inflight > HardBudgetCeiling.Inflight {
		c.Inflight = HardBudgetCeiling.Inflight
	}
	return c
}

// ResolveBudget is the budget of one job: the sensor's level, replaced by
// the job's signed budget when it carries one (lower or higher), and never
// above the operator's ceiling. Every value the ceiling lowered is listed
// in Clamped. job must come from the job's verified statement, never from
// its unsigned payload.
func ResolveBudget(level Pacing, job *JobBudget, ceiling BudgetCeiling) HostBudget {
	if level.TargetRPS <= 0 || level.TargetInflight <= 0 {
		level = DefaultPacing
	}
	b := HostBudget{Level: level.Name, RPS: level.TargetRPS, Inflight: level.TargetInflight, Source: BudgetFromSensor}
	if job != nil && job.Validate() == nil {
		if p, ok := PacingFor(job.Level); ok && job.Level != "" {
			b.Level, b.RPS, b.Inflight = p.Name, p.TargetRPS, p.TargetInflight
		}
		if job.RPS > 0 {
			b.RPS = job.RPS
		}
		if job.Inflight > 0 {
			b.Inflight = job.Inflight
		}
		b.Source = BudgetFromJob
	}
	c := ceiling.effective()
	if b.RPS > c.RPS {
		b.Clamped = append(b.Clamped, BudgetClamp{Key: "rps", Asked: b.RPS, To: c.RPS, By: ClampByCeiling})
		b.RPS = c.RPS
	}
	if b.Inflight > c.Inflight {
		b.Clamped = append(b.Clamped, BudgetClamp{Key: "inflight", Asked: b.Inflight, To: c.Inflight, By: ClampByCeiling})
		b.Inflight = c.Inflight
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
// the sweep rate. maxPerHost is the most targets any one host has in the
// list. enforced is as in ToolPace; without it the sweep rate applies only
// to a list no host dominates (each host's targets, probed twice at once,
// stay under its budget), else the whole run gets one host's budget.
func (b HostBudget) SweepPace(hosts, maxPerHost int, enforced bool) ToolPace {
	p := b.Pacing()
	n := max(hosts, 1)
	if !enforced && saturatingMul(max(maxPerHost, 1), sweepRequestsPerTarget) > p.TargetRPS {
		n = 1
	}
	rate, inflight := p.TargetRPS, p.TargetInflight
	if n > 1 {
		rate = min(p.SweepRPS, saturatingMul(p.TargetRPS, n))
		inflight = min(p.SweepInflight, saturatingMul(p.TargetInflight, n))
	}
	return ToolPace{Rate: max(rate, 1), Inflight: max(inflight, 1), HostInflight: p.TargetInflight, Hosts: n}
}

// sweepRequestsPerTarget is how many requests a sweep sends per target at
// most (the probe and one retry).
const sweepRequestsPerTarget = 2

func saturatingMul(a, b int) int {
	if a > 0 && b > MaxJobBudget*MaxJobBudget/a {
		return MaxJobBudget * MaxJobBudget
	}
	return a * b
}

// HostKey is the host a target's budget is counted under: the politeness
// host of the target (contract politeness.HostOf), which drops the scheme,
// the port and the path. Empty when the target names no host.
func HostKey(target string) string { return politeness.HostOf(target) }

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
