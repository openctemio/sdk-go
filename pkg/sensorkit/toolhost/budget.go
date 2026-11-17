package toolhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// The per-host budget of a task (adapt.HostBudget, RunOptions.HostBudget).
//
// A confined task: its forwarder paces every connection, every request it
// reads and every further request it can tell apart on a tunnel it passes
// through, per host and per address, under the budget's rate, and holds at
// most the budget's connections to a host open (egress/hostbudget.go,
// egress/tunnel.go). What it cannot count (requests packed into one TLS
// record, the streams in flight on one HTTP/2 connection) is bounded in
// bytes there and held by the tool's own flags, which its adapter derives
// from the same budget. A canary request per host
// (adapt.Canary) feeds the same controller with what the host answers, for
// the HTTPS connections the forwarder only passes through; it travels the
// forwarder's own dial path (Forwarder.DialTarget).
//
// A task whose network is not confined: nothing is in the path, so the
// tool's own flags are the only enforcement, nothing reads what a host
// answers and there is no canary (there is no way out the runtime shares
// with the tool: a request of the runtime's own would leave by another
// route than the tool's, and it could slow nothing). The outcome states the
// budget and says the pacing is limited (adapt.PacingLimitedNoForwarder).

// taskCanary is the canary of one confined task.
type taskCanary struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// ErrNoHostBudget is the refusal of a tool that connects to its targets
// and was started without a per-host budget.
var ErrNoHostBudget = errors.New("the tool connects to its targets and was started without a per-host budget")

// requireBudget refuses a task of a tool whose manifest says it connects
// to its targets (network targets) when the caller gave no valid budget.
// It is checked for every tool the host starts, whatever path started it:
// a tool compiled into the sensor, an adapter the operator installed, a
// retest. A tool of another network class sends nothing to the hosts of
// its targets and needs none.
func requireBudget(m tool.Manifest, o RunOptions) *tool.Error {
	if m.Permissions.Network != tool.NetTargets {
		return nil
	}
	if o.HostBudget == nil || !o.HostBudget.Valid() {
		return refusedErr("%s: %v", m.Name, ErrNoHostBudget)
	}
	return nil
}

// budgetOf is the budget the task's forwarder, canary and rate key are
// held to (nil: the tool does not connect to its targets, or it probes
// ports and is paced in packets per second, RunOptions.PortProbes).
func budgetOf(m tool.Manifest, o RunOptions) *adapt.HostBudget {
	if o.HostBudget == nil || !o.HostBudget.Valid() || m.Permissions.Network != tool.NetTargets || o.PortProbes {
		return nil
	}
	// The task's own copy: what the tool host lowers is recorded on it
	// (capBudgetRate), never on the caller's.
	b := *o.HostBudget
	b.Clamped = slices.Clone(b.Clamped)
	return &b
}

// startCanary starts the canary of a confined task: for each host a target
// names by an http or https URL whose connections the forwarder passes
// through unread. It returns nil when the task has no budget, no forwarder
// or no such host.
//
// The request is the canary's own, fixed one (adapt.Canary): the job's
// identification headers, User-Agent rotation and query marker are not put
// on it. Hosts of the task that are reached at one address get one canary
// between them (the first that names the address); what it is answered is
// reported to the address too, so it slows them all.
func (h *Host) startCanary(ctx context.Context, p *prepared, eg *taskEgress) *taskCanary {
	if p.budget == nil || p.task.IsRetest() || eg == nil {
		return nil
	}
	values := make([]string, 0, len(p.task.Targets))
	for _, t := range p.task.Targets {
		values = append(values, t.Value)
	}
	targets, unwatched := adapt.CanaryTargets(values)
	// Only where the forwarder cannot read the answers itself: a connection
	// it guards (a web scope, path limits, an identification it adds) is
	// read request by request, and a request outside those limits is never
	// the canary's to send.
	kept := targets[:0]
	watched := map[string]bool{}
	for _, t := range targets {
		host, port, ok := originOf(t.URL)
		if !ok || !eg.fw.Opaque(host, port) {
			unwatched++
			continue
		}
		t.Addrs = eg.fw.PinnedAddrs(host)
		shared := false
		for _, a := range t.Addrs {
			shared = shared || watched[a]
		}
		if shared {
			// Another name of this address is watched already: one canary
			// per address, however many names the job has for it.
			unwatched++
			continue
		}
		for _, a := range t.Addrs {
			watched[a] = true
		}
		kept = append(kept, t)
	}
	targets = kept
	if len(targets) == 0 {
		return nil
	}
	send, release := adapt.CanaryDo(eg.fw.DialTarget, nil)
	c := &taskCanary{done: make(chan struct{})}
	cctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c.cancel = cancel
	cn := adapt.NewCanary(eg.fw.TargetRate(), send)
	go func() {
		defer close(c.done)
		defer release()
		cn.Run(cctx, targets, unwatched)
	}()
	return c
}

// originOf is the host and port of an origin URL.
func originOf(raw string) (string, int, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", 0, false
	}
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if ps := u.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil {
			return "", 0, false
		}
		port = n
	}
	return u.Hostname(), port, true
}

// end stops the canary and waits for it (bounded).
func (c *taskCanary) end() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		c.cancel()
		select {
		case <-c.done:
		case <-time.After(forwarderStopGrace):
		}
	})
}

// unconfinedBudget puts the budget of a task that ran without a forwarder
// in out: the numbers its tool's flags were derived from, and that nothing
// else enforced them (adapt.PacingLimitedNoForwarder). It returns the log
// lines of that outcome. With a forwarder (eg set) the forwarder reports.
func unconfinedBudget(p *prepared, eg *taskEgress, out *Outcome) []LogLine {
	if p.budget == nil || eg != nil {
		return nil
	}
	s := adapt.LimitedSummary(*p.budget, adapt.PacingLimitedNoForwarder)
	out.TargetRate = &s
	recordPacing(&s)
	return budgetLines(&s)
}

func rateChangeLine(c adapt.Change) LogLine {
	return LogLine{Level: "info", Msg: fmt.Sprintf("target rate %s: %.3g/s -> %.3g/s (%s)", c.Host, c.From, c.To, c.Reason),
		Fields: map[string]any{"target_rate": c.To, "host": c.Host, "reason": c.Reason}}
}

// budgetLines are the log lines of a task's budget outcome: the budget in
// force (and what the sensor's ceiling lowered), the back-off and breaker
// counts, and one line per host that was slowed (bounded). They carry
// counts and host names only, never anything a host sent.
func budgetLines(s *adapt.Summary) []LogLine {
	if s == nil || s.Budget == nil {
		return nil
	}
	b := s.Budget
	fields := map[string]any{"host_budget_level": b.Level, "host_budget_rps": b.RPS, "host_budget_inflight": b.Inflight,
		"host_budget_rps_won_by": b.WonBy.RPS, "host_budget_inflight_won_by": b.WonBy.Inflight,
		"backoffs": s.Backoffs, "circuit_opens": s.CircuitOpens}
	msg := fmt.Sprintf("host budget %s: %d requests/s (set by %s) and %d in flight (set by %s) per host; %d back-off(s), %d breaker opening(s)",
		b.Level, b.RPS, b.WonBy.RPS, b.Inflight, b.WonBy.Inflight, s.Backoffs, s.CircuitOpens)
	if s.Canary != nil {
		fields["canary_hosts"], fields["canary_probes"], fields["canary_pushback"] = s.Canary.Hosts, s.Canary.Probes, s.Canary.Pushback
		msg += fmt.Sprintf("; canary watched %d host(s), %d request(s), %d pushed back", s.Canary.Hosts, s.Canary.Probes, s.Canary.Pushback)
	}
	lines := []LogLine{{Level: "info", Msg: msg, Fields: fields}}
	if s.Limited != "" {
		lines = append(lines, LogLine{Level: "warn",
			Msg:    "pacing limited: the tool ran without the task forwarder, so only its own flags held the host budget; nothing read what the hosts answered (no back-off, no canary)",
			Fields: map[string]any{"pacing_limited": s.Limited}})
	}
	for _, c := range b.Clamped {
		who := c.Key
		if c.Source != "" {
			who = c.Source + " " + c.Key
		}
		lines = append(lines, LogLine{Level: "warn",
			Msg:    fmt.Sprintf("host budget: %s asked %d, %d applies (the lower limit is %s)", who, c.Asked, c.To, c.By),
			Fields: map[string]any{"host_budget_clamped": c.Key, "asked": c.Asked, "to": c.To, "by": c.By, "source": c.Source}})
	}
	for i, hs := range s.HostStats {
		if i == maxEgressLogLines {
			break
		}
		lines = append(lines, LogLine{Level: "warn",
			Msg: fmt.Sprintf("target %s pushed back: %d back-off(s), %d breaker opening(s), ended at %.3g/s", hs.Host, hs.Backoffs, hs.CircuitOpens, hs.Rate),
			Fields: map[string]any{"host": hs.Host, "backoffs": hs.Backoffs, "circuit_opens": hs.CircuitOpens, "http_429": hs.HTTP429,
				"http_503": hs.HTTP503, "resets": hs.Resets, "timeouts": hs.Timeouts, "retry_after_seconds": hs.RetryAfterSeconds, "opened_by": hs.OpenedBy}})
	}
	return lines
}

// paceLines are the log lines that say the task's rate setting was changed:
// by the per-host budget, by the local policy.
func (p *prepared) paceLines() []LogLine {
	var out []LogLine
	if p.budgetLine != nil {
		out = append(out, *p.budgetLine)
	}
	if p.rateLine != nil {
		out = append(out, *p.rateLine)
	}
	return out
}

// capBudgetRate lowers the tool's rate key (safety.rate_param) to the
// budget of the task's hosts, and sets it when the task left it unset, so a
// tool described only by its manifest runs under the budget too. enforced
// says the task's forwarder holds each host to the budget
// (adapt.HostBudget.ToolPace). A value the task asked for above the budget
// is recorded on the budget (adapt.HostBudget.Clamp: the run's
// target_rate.budget.clamped), and it returns a log line when it changed
// the rate.
func capBudgetRate(m tool.Manifest, cfg json.RawMessage, b *adapt.HostBudget, targets []tool.Target, enforced bool) (json.RawMessage, *LogLine, error) {
	if b == nil || m.Safety == nil || m.Safety.RateParam == "" {
		return cfg, nil, nil
	}
	values := map[string]any{}
	if len(cfg) > 0 {
		if err := json.Unmarshal(cfg, &values); err != nil {
			return nil, nil, err
		}
	}
	key := m.Safety.RateParam
	// A rate of at least one request a second is a rate. Anything else
	// under the key (zero, a negative number, a fraction under one, a
	// string, null) is not: many tools read such a value as "no limit", so
	// it never stays in the configuration. It is replaced like an unset
	// key, by the tool's default or the budget, whichever is lower.
	asked := 0
	raw, present := values[key]
	if f, ok := raw.(float64); ok && f >= 1 {
		asked = int(min(f, 1e9))
	}
	unusable := present && asked == 0
	requested := asked
	if requested == 0 {
		requested = toolDefaultRate(m, key)
	}
	list := make([]string, 0, len(targets))
	for _, t := range targets {
		list = append(list, t.Value)
	}
	hosts, _ := adapt.CountHosts(list)
	limit := max(b.ToolPace(hosts, enforced).Rate, 1)
	if requested > 0 && requested <= limit && !unusable {
		return cfg, nil, nil
	}
	to := limit
	if requested > 0 && requested <= limit {
		to = requested // the tool's default, written out in place of the unusable value
	} else {
		b.Clamp(key, asked, limit)
	}
	values[key] = to
	out, err := json.Marshal(values)
	if err != nil {
		return nil, nil, err
	}
	limit = to
	line := &LogLine{Level: "info", Msg: fmt.Sprintf("the host budget set %s to %d (asked %d)", key, limit, requested),
		Fields: map[string]any{"source": "runtime", "rate_param": key, "requested": requested, "capped": limit, "host_budget_level": b.Level}}
	return out, line, nil
}

// confines reports whether be confines the network of a tool with m's
// network class: its forwarder is then in every connection's path.
func confines(be executor.Backend, m tool.Manifest) bool {
	return m.Permissions.Network != tool.NetNone && be.Status().NetworkEnforced
}

// PacingTotals counts, for this process, what the per-host budget did: the
// tasks that ran under one, the tasks among them whose pacing was limited
// (no forwarder in the path), the times a host's rate was lowered and a
// host's breaker opened, the hosts reported as throttled or blocked gaps,
// and the values that were asked for and did not apply because a lower
// limit won. Numbers only: no host, tenant or job is named, so they are
// safe to export as process metrics.
type PacingTotals struct {
	Tasks         uint64
	Limited       uint64
	Backoffs      uint64
	CircuitOpens  uint64
	ThrottledGaps uint64
	Clamped       uint64
}

var pacingTotals struct {
	tasks, limited, backoffs, opens, gaps, clamped atomic.Uint64
}

// Pacing returns the process's pacing totals.
func Pacing() PacingTotals {
	t := &pacingTotals
	return PacingTotals{Tasks: t.tasks.Load(), Limited: t.limited.Load(), Backoffs: t.backoffs.Load(), CircuitOpens: t.opens.Load(),
		ThrottledGaps: t.gaps.Load(), Clamped: t.clamped.Load()}
}

// recordPacing adds one task's outcome to the totals.
func recordPacing(s *adapt.Summary) {
	if s == nil || s.Budget == nil {
		return
	}
	t := &pacingTotals
	t.tasks.Add(1)
	if s.Limited != "" {
		t.limited.Add(1)
	}
	t.backoffs.Add(uint64(max(s.Backoffs, 0)))
	t.opens.Add(uint64(max(s.CircuitOpens, 0)))
	t.clamped.Add(uint64(len(s.Budget.Clamped)))
	for _, g := range s.Gaps {
		if g.Reason == adapt.GapThrottled || g.Reason == adapt.GapBlocked {
			t.gaps.Add(1)
		}
	}
}
