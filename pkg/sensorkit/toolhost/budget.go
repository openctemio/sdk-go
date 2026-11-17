package toolhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

// The per-host budget of a task (adapt.HostBudget, RunOptions.HostBudget).
//
// A confined task: its forwarder paces every connection (and every request
// it reads) per host under the budget's rate and holds at most the
// budget's connections to a host open, whatever the tool's flags say.
// A canary request per host (adapt.Canary) feeds the same controller with
// what the host answers, for the HTTPS connections the forwarder only
// passes through.
//
// A task whose network is not confined: no forwarder is in the path, so the
// tool's own flags (derived from the same budget by its adapter) are the
// enforcement. The canary still runs, against a controller of its own:
// when every host of the task has its breaker open, the tool is stopped,
// what it delivered is kept (the run is partial) and the hosts are
// coverage gaps.

// errThrottleStop is the cause a task is stopped with when its targets
// throttle the scan.
var errThrottleStop = errors.New("toolhost: the task's targets throttle the scan")

// taskCanary is the canary of one task.
type taskCanary struct {
	rate   *adapt.HostRate
	own    bool // rate is the canary's own (no forwarder)
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once

	// stop receives once when every host of an unconfined task has its
	// breaker open (nil for a confined task: its forwarder refuses the
	// connections instead).
	stop chan string

	mu      sync.Mutex
	hosts   int
	open    map[string]bool
	stopped bool
	changes []adapt.Change
	moreCh  int
}

// budgetOf is the task's budget (nil: the caller set none, or the tool does
// not connect to its targets).
func budgetOf(m tool.Manifest, o RunOptions) *adapt.HostBudget {
	if o.HostBudget == nil || !o.HostBudget.Valid() || m.Permissions.Network != tool.NetTargets {
		return nil
	}
	return o.HostBudget
}

// startCanary starts the task's canary: for each host a target names by an
// http or https URL whose connections nothing reads (no forwarder, or one
// that passes them through). It returns nil when the task has no budget or
// no such host.
func (h *Host) startCanary(ctx context.Context, p *prepared, eg *taskEgress) *taskCanary {
	b := p.budget
	if b == nil || p.task.IsRetest() {
		return nil
	}
	values := make([]string, 0, len(p.task.Targets))
	for _, t := range p.task.Targets {
		values = append(values, t.Value)
	}
	targets, unwatched := adapt.CanaryTargets(values)
	c := &taskCanary{done: make(chan struct{}), open: map[string]bool{}}
	c.hosts, _ = adapt.CountHosts(values)
	var dial func(ctx context.Context, host string, port int) (net.Conn, error)
	if eg != nil {
		c.rate = eg.fw.TargetRate()
		// Only where the forwarder cannot read the answers itself: a
		// connection it guards (a web scope, path limits, identification)
		// is read request by request, and a request outside those limits is
		// never the canary's to send.
		kept := targets[:0]
		for _, t := range targets {
			if host, port, ok := originOf(t.URL); ok && eg.fw.Opaque(host, port) {
				kept = append(kept, t)
			} else {
				unwatched++
			}
		}
		targets = kept
		dial = eg.fw.DialTarget
	} else {
		if p.task.WebScope != nil || len(p.task.Limits) > 0 {
			// Limits the canary cannot check without a forwarder.
			return nil
		}
		c.rate, c.own = adapt.NewHostRate(float64(b.RPS)), true
		c.rate.SetBudget(*b)
		c.stop = make(chan string, 1)
		c.rate.OnChange = c.change
		dial = func(ctx context.Context, host string, port int) (net.Conn, error) {
			return h.dialAdmitted(ctx, host, port)
		}
	}
	if len(targets) == 0 {
		// Nothing to watch: an unconfined task still states its budget.
		close(c.done)
		c.cancel = func() {}
		if !c.own {
			return nil
		}
		return c
	}
	send, release := adapt.CanaryDo(dial)
	id := p.task.Identity
	do := func(req *http.Request) (*http.Response, error) {
		req.Header.Set("User-Agent", useragent.String())
		if id != nil {
			for k, v := range id.Headers {
				req.Header.Set(k, v)
			}
			if ua := id.UserAgentFor(req.URL.Hostname()); ua != "" {
				req.Header.Set("User-Agent", ua)
			}
			if id.Query != nil && id.Query.Name != "" {
				q := req.URL.Query()
				q.Set(id.Query.Name, id.Query.Value)
				req.URL.RawQuery = q.Encode()
			}
		}
		return send(req)
	}
	cctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c.cancel = cancel
	cn := adapt.NewCanary(c.rate, do, nil)
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

// dialAdmitted dials a target of an unconfined task for its canary: only
// at an address the policy admitted for the host (the addresses the task's
// targets were admitted at), never one a later lookup returns.
func (h *Host) dialAdmitted(ctx context.Context, host string, port int) (net.Conn, error) {
	var addrs []string
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		addrs = []string{ip.String()}
	} else {
		for _, a := range h.admittedAddrs(ctx, host) {
			addrs = append(addrs, a.String())
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("toolhost: no admitted address for the canary's host")
	}
	d := &net.Dialer{Timeout: adapt.CanaryPace.Timeout}
	var last error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a, strconv.Itoa(port)))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// change follows the breakers of an unconfined task's hosts: when every
// host of the task is open (or given up), the tool is stopped.
func (c *taskCanary) change(ch adapt.Change) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.changes) < adapt.TargetRate.MaxChanges {
		c.changes = append(c.changes, ch)
	} else {
		c.moreCh++
	}
	switch {
	case ch.Reason == adapt.ReasonGaveUp, strings.HasPrefix(ch.Reason, adapt.ReasonOpened):
		c.open[ch.Host] = true
	case ch.Reason == adapt.ReasonClosed:
		delete(c.open, ch.Host)
	}
	if !c.stopped && c.hosts > 0 && len(c.open) >= c.hosts {
		c.stopped = true
		c.stop <- "every target host throttled or blocked the scan"
	}
}

// stopC is the channel that says the tool must stop (nil: never).
func (c *taskCanary) stopC() <-chan string {
	if c == nil {
		return nil
	}
	return c.stop
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

// finish ends the canary and, for an unconfined task, puts its controller's
// outcome in out (a confined task's forwarder reports the shared one). It
// returns the log lines of that outcome.
func (c *taskCanary) finish(out *Outcome) []LogLine {
	if c == nil {
		return nil
	}
	c.end()
	if !c.own {
		return nil
	}
	s := c.rate.Summary()
	out.TargetRate = &s
	recordPacing(&s)
	var lines []LogLine
	c.mu.Lock()
	for _, ch := range c.changes {
		lines = append(lines, rateChangeLine(ch))
	}
	if c.moreCh > 0 {
		lines = append(lines, LogLine{Level: "info", Msg: fmt.Sprintf("target rate changed %d more times", c.moreCh)})
	}
	c.mu.Unlock()
	return append(lines, budgetLines(&s)...)
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
		"host_budget_source": b.Source, "backoffs": s.Backoffs, "circuit_opens": s.CircuitOpens}
	msg := fmt.Sprintf("host budget %s: %d requests/s and %d in flight per host (from the %s); %d back-off(s), %d breaker opening(s)",
		b.Level, b.RPS, b.Inflight, b.Source, s.Backoffs, s.CircuitOpens)
	if s.Canary != nil {
		fields["canary_hosts"], fields["canary_probes"], fields["canary_pushback"] = s.Canary.Hosts, s.Canary.Probes, s.Canary.Pushback
		msg += fmt.Sprintf("; canary watched %d host(s), %d request(s), %d pushed back", s.Canary.Hosts, s.Canary.Probes, s.Canary.Pushback)
	}
	lines := []LogLine{{Level: "info", Msg: msg, Fields: fields}}
	for _, c := range b.Clamped {
		lines = append(lines, LogLine{Level: "warn",
			Msg:    fmt.Sprintf("host budget %s lowered from %d to %d by the sensor's ceiling", c.Key, c.Asked, c.To),
			Fields: map[string]any{"host_budget_clamped": c.Key, "asked": c.Asked, "to": c.To, "by": c.By}})
	}
	for i, hs := range s.HostStats {
		if i == maxEgressLogLines {
			break
		}
		lines = append(lines, LogLine{Level: "warn",
			Msg: fmt.Sprintf("target %s pushed back: %d back-off(s), %d breaker opening(s), ended at %.3g/s", hs.Host, hs.Backoffs, hs.CircuitOpens, hs.Rate),
			Fields: map[string]any{"host": hs.Host, "backoffs": hs.Backoffs, "circuit_opens": hs.CircuitOpens, "http_429": hs.HTTP429,
				"http_503": hs.HTTP503, "resets": hs.Resets, "timeouts": hs.Timeouts, "retry_after_seconds": hs.RetryAfterSeconds}})
	}
	return lines
}

// capBudgetRate lowers the tool's rate key (safety.rate_param) to the
// budget of the task's hosts, and sets it when the task left it unset, so a
// tool described only by its manifest runs under the budget too. enforced
// says the task's forwarder holds each host to the budget
// (adapt.HostBudget.ToolPace). It returns a log line when it changed the
// rate.
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
	requested := 0
	if f, ok := values[key].(float64); ok && f > 0 {
		requested = int(f)
	}
	if requested == 0 {
		requested = toolDefaultRate(m, key)
	}
	list := make([]string, 0, len(targets))
	for _, t := range targets {
		list = append(list, t.Value)
	}
	hosts, _ := adapt.CountHosts(list)
	limit := b.ToolPace(hosts, enforced).Rate
	if requested > 0 && requested <= limit {
		return cfg, nil, nil
	}
	values[key] = limit
	out, err := json.Marshal(values)
	if err != nil {
		return nil, nil, err
	}
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
// tasks that ran under one, the times a host's rate was lowered and a
// host's breaker opened, the hosts reported as throttled or blocked gaps,
// the tools stopped because their hosts throttled the scan, and the budget
// values the sensor's ceiling lowered. Numbers only: no host, tenant or job
// is named, so they are safe to export as process metrics.
type PacingTotals struct {
	Tasks         uint64
	Backoffs      uint64
	CircuitOpens  uint64
	ThrottledGaps uint64
	ThrottleStops uint64
	Clamped       uint64
}

var pacingTotals struct {
	tasks, backoffs, opens, gaps, stops, clamped atomic.Uint64
}

// Pacing returns the process's pacing totals.
func Pacing() PacingTotals {
	t := &pacingTotals
	return PacingTotals{Tasks: t.tasks.Load(), Backoffs: t.backoffs.Load(), CircuitOpens: t.opens.Load(),
		ThrottledGaps: t.gaps.Load(), ThrottleStops: t.stops.Load(), Clamped: t.clamped.Load()}
}

// recordPacing adds one task's outcome to the totals.
func recordPacing(s *adapt.Summary) {
	if s == nil || s.Budget == nil {
		return
	}
	t := &pacingTotals
	t.tasks.Add(1)
	t.backoffs.Add(uint64(max(s.Backoffs, 0)))
	t.opens.Add(uint64(max(s.CircuitOpens, 0)))
	t.clamped.Add(uint64(len(s.Budget.Clamped)))
	for _, g := range s.Gaps {
		if g.Reason == adapt.GapThrottled || g.Reason == adapt.GapBlocked {
			t.gaps.Add(1)
		}
	}
}
