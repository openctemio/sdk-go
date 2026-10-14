package toolhost

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/internal/absname"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// HostResolver is a policy that returns the addresses it admitted for a
// host (*core.LocalPolicy does): a confined task's forwarder dials a
// target at those addresses only. Without one, the host is resolved when
// the task starts.
type HostResolver interface {
	AdmittedAddrs(ctx context.Context, host string) ([]netip.Addr, error)
}

// MaxEgressRecords is how many forwarder records an Outcome keeps.
const MaxEgressRecords = 1000

// maxEgressLogLines bounds the refusal lines a task logs.
const maxEgressLogLines = 20

// taskEgress is a confined task's forwarder (api RFC-060): its two unix
// sockets live in a task directory the sandbox hides from every task.
type taskEgress struct {
	fw         *egress.Forwarder
	dir        string
	proxy, dns string
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	once       sync.Once

	// changes are the first rate changes (adapt.TargetRate.MaxChanges);
	// moreChanges counts the rest.
	chMu        sync.Mutex
	changes     []adapt.Change
	moreChanges int
}

// startEgress starts the forwarder of a task whose backend confines the
// network. A tool with network "none" gets none (no way out at all); a
// backend that does not confine gets none (nil, the task runs as before).
func (h *Host) startEgress(ctx context.Context, be executor.Backend, p *prepared) (*taskEgress, error) {
	if !be.Status().NetworkEnforced || p.m.Permissions.Network == tool.NetNone {
		return nil, nil
	}
	scope := h.taskScope(ctx, p.m, p.task)
	dir, err := executor.NewTaskDir("egress-")
	if err != nil {
		return nil, err
	}
	ceiling := h.rateCeiling(p)
	e := &taskEgress{dir: dir, proxy: filepath.Join(dir, "proxy.sock"), dns: filepath.Join(dir, "dns.sock"),
		fw: egress.New(scope, egress.Limits{Rate: ceiling, PerHostRate: ceiling})}
	e.fw.Upstream = egress.UpstreamDNS("")
	e.fw.SearchDomains = egress.SearchDomains("")
	// The job's recorder when the caller set one (the command poller does),
	// so the result's reach summary covers the tool's connections too.
	e.fw.Reach = reach.FromContext(ctx)
	if e.fw.Reach == nil {
		e.fw.Reach = reach.NewRecorder()
	}
	e.fw.TargetRate().OnChange = e.change
	pl, err := net.Listen("unix", e.proxy)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("toolhost: forwarder: %w", err)
	}
	dl, err := net.Listen("unix", e.dns)
	if err != nil {
		_ = pl.Close()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("toolhost: forwarder: %w", err)
	}
	fctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	e.cancel = cancel
	e.wg.Add(2)
	go func() { defer e.wg.Done(); _ = e.fw.Serve(fctx, pl) }()
	go func() { defer e.wg.Done(); _ = e.fw.ServeDNSStream(fctx, dl) }()
	return e, nil
}

// proxyPath and dnsPath are the forwarder's sockets ("" without one).
func (e *taskEgress) proxyPath() string {
	if e == nil {
		return ""
	}
	return e.proxy
}

func (e *taskEgress) dnsPath() string {
	if e == nil {
		return ""
	}
	return e.dns
}

// stop ends the forwarder (once; later calls only read) and returns what
// it recorded.
func (e *taskEgress) stop() ([]egress.Record, int) {
	if e == nil {
		return nil, 0
	}
	e.once.Do(func() {
		e.cancel()
		e.wg.Wait()
		_ = os.RemoveAll(e.dir)
	})
	recs, dropped := e.fw.Records()
	if len(recs) > MaxEgressRecords {
		dropped += len(recs) - MaxEgressRecords
		recs = recs[:MaxEgressRecords]
	}
	return recs, dropped
}

// finish stops the forwarder (nil: no-op), puts what it recorded and the
// task's target-rate outcome in out, settles as failed (egress_refused) the
// targets the scope refused every connection toward, and returns the log
// lines: refusals, the unreached targets, rate changes with their reason,
// and the rate summary with the coverage gaps.
func (e *taskEgress) finish(out *Outcome, targets []tool.Target) []LogLine {
	if e == nil {
		return nil
	}
	out.Egress, out.EgressDropped = e.stop()
	tally := e.fw.Tally()
	out.EgressTally = &tally
	unreached := markEgressRefused(out, targets, tally)
	s := e.fw.TargetRate().Summary()
	out.TargetRate = &s
	if !e.fw.Reach.Empty() {
		r := e.fw.Reach.Report()
		out.Reach = &r
	}
	lines := egressLog(out.Egress)
	if unreached > 0 {
		lines = append(lines, LogLine{Level: "warn",
			Msg:    fmt.Sprintf("egress refused every connection toward %d of %d target(s): the sensor's network confinement did not let the tool reach them", unreached, len(targets)),
			Fields: map[string]any{"egress": "unreached", "targets_unreached": unreached, "connections_refused": tally.Refused, "connections_allowed": tally.Allowed}})
	}
	e.chMu.Lock()
	for _, c := range e.changes {
		lines = append(lines, LogLine{Level: "info", Msg: fmt.Sprintf("target rate %s: %.3g/s -> %.3g/s (%s)", c.Host, c.From, c.To, c.Reason),
			Fields: map[string]any{"target_rate": c.To, "host": c.Host, "reason": c.Reason}})
	}
	if e.moreChanges > 0 {
		lines = append(lines, LogLine{Level: "info", Msg: fmt.Sprintf("target rate changed %d more times", e.moreChanges)})
	}
	e.chMu.Unlock()
	if s.Hosts > 0 {
		lines = append(lines, LogLine{Level: "info",
			Msg: fmt.Sprintf("target rate: ceiling %.3g/s, start %.3g/s, lowest %.3g/s, %d host(s), %d throttled, %d unreachable",
				s.Ceiling, s.Start, s.Min, s.Hosts, s.Throttled, s.Unreachable),
			Fields: map[string]any{"target_rate_ceiling": s.Ceiling, "target_rate_min": s.Min, "hosts": s.Hosts,
				"hosts_throttled": s.Throttled, "hosts_unreachable": s.Unreachable, "coverage_gaps": s.GapsTotal}})
	}
	for i, g := range s.Gaps {
		if i == maxEgressLogLines {
			break
		}
		lines = append(lines, LogLine{Level: "warn", Msg: "coverage gap " + g.Host + " (" + g.Reason + "): " + g.Detail,
			Fields: map[string]any{"coverage_gap": g.Reason, "host": g.Host}})
	}
	return lines
}

// markEgressRefused settles as failed (tool.EgressRefused) every target the
// tool would otherwise report done although the scope refused each
// connection it made toward it: the tool never reached it, so "nothing
// found" would be a silent false negative. When the scope refused every
// connection of the task and allowed none, every done target is unreached,
// also those the refusals cannot be traced to (an address no target name
// is pinned to). A target the tool made no connection toward is left as
// the tool reported it. A task with an unreached target is at best
// partial. It returns how many targets it settled so.
func markEgressRefused(out *Outcome, targets []tool.Target, t egress.Tally) int {
	if t.Refused == 0 {
		return 0
	}
	all := t.Allowed == 0
	keys := make(map[string]string, len(targets))
	for _, tg := range targets {
		keys[tg.Ref] = scopeKey(tg)
	}
	n := 0
	for i := range out.Targets {
		to := &out.Targets[i]
		if to.State != tool.StateDone {
			continue
		}
		if !all && !t.Targets[keys[to.Ref]].Unreached() {
			continue
		}
		to.State, to.Class = tool.StateFailed, tool.EgressRefused
		to.Detail = "the sensor's network confinement refused every connection toward the target"
		n++
	}
	if n == 0 {
		return 0
	}
	if out.Status == tool.StatusOK {
		out.Status = tool.StatusPartial
	}
	markOutcomes(out)
	return n
}

// scopeKey is the key the forwarder counts a target's connections under
// (egress.Tally.Targets): its prefix for an address or range, else its
// host name. taskScope admits targets under the same keys.
func scopeKey(t tool.Target) string {
	if pfx, err := netip.ParsePrefix(strings.TrimSpace(t.Value)); err == nil {
		return pfx.Masked().String()
	}
	host := strings.Trim(t.Host(), "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return egress.Key(host)
}

// change keeps a rate change for the task's log.
func (e *taskEgress) change(c adapt.Change) {
	e.chMu.Lock()
	defer e.chMu.Unlock()
	if len(e.changes) < adapt.TargetRate.MaxChanges {
		e.changes = append(e.changes, c)
		return
	}
	e.moreChanges++
}

// rateCeiling is the rate a confined task's forwarder never exceeds, for
// the task and per host: the lowest of the tool's own rate (its rate param,
// already capped by the local policy), the caller's (RunOptions.TargetRate)
// and the local policy's rate.max_rps. The platform's values reach the
// tool's rate param already lowered to the local maximum; nothing here can
// raise a limit.
func (h *Host) rateCeiling(p *prepared) float64 {
	c := adapt.Ceiling(egressRate(p.task.Config, p.m), p.targetRate)
	if rp, ok := h.Policy.(RatePolicy); ok {
		if capped := rp.CapRate(int(math.Ceil(c))); capped > 0 {
			c = math.Min(c, float64(capped))
		}
	}
	return c
}

// taskScope is what a task may reach: its admitted targets (names at the
// addresses the policy admitted), the manifest's vendor hosts, or any
// public address for a tool that reaches the internet through the
// sensor's egress.
func (h *Host) taskScope(ctx context.Context, m tool.Manifest, task tool.Task) egress.Scope {
	s := egress.Scope{Names: map[string][]netip.Addr{}}
	switch m.Permissions.Network {
	case tool.NetTargets, tool.NetResolver:
		s.DNSOnly = m.Permissions.Network == tool.NetResolver
		s.Limits = task.Limits
		s.Web = task.WebScope
		for _, t := range task.Targets {
			if task.WebScope != nil {
				if h := t.Host(); h != "" {
					s.WebTargets = append(s.WebTargets, h)
				}
			}
			if pfx, err := netip.ParsePrefix(strings.TrimSpace(t.Value)); err == nil {
				s.Prefixes = append(s.Prefixes, pfx.Masked())
				continue
			}
			host := strings.Trim(t.Host(), "[]")
			if host == "" {
				continue
			}
			if a, err := netip.ParseAddr(host); err == nil {
				a = a.Unmap()
				s.Prefixes = append(s.Prefixes, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			s.Names[host] = h.admittedAddrs(ctx, host)
		}
	case tool.NetVendor:
		s.Vendor = toolrt.VendorHosts(m, task.Config)
	case tool.NetEgressProxy:
		s.AnyPublic = true
	}
	return s
}

// checkLimits refuses a task whose scope limits it cannot enforce: limits
// that do not name the task's targets, a tool whose network class reaches
// more than its targets, or a sandbox that does not confine the network
// (the forwarder would then be a proxy the tool may ignore). Tool flags
// alone are never the enforcement.
func (h *Host) checkLimits(m tool.Manifest, task tool.Task) *tool.Error {
	if len(task.Limits) == 0 {
		return nil
	}
	values := make([]string, len(task.Targets))
	for i, t := range task.Targets {
		values[i] = t.Value
	}
	if err := scopelimit.Validate(task.Limits, values); err != nil {
		return tool.AsError(tool.Invalid("%v", err))
	}
	switch m.Permissions.Network {
	case tool.NetNone:
		return nil
	case tool.NetTargets, tool.NetResolver:
	default:
		return tool.AsError(tool.Refused(fmt.Sprintf("the job's targets are limited to some ports or paths; tool %s reaches the network as %q, not only its targets",
			m.Name, m.Permissions.Network)))
	}
	if !h.backend().Status().NetworkEnforced {
		return tool.AsError(tool.Refused("the job's targets are limited to some ports or paths; this sensor's sandbox does not confine the network, so the limits cannot be enforced"))
	}
	return nil
}

func (h *Host) admittedAddrs(ctx context.Context, host string) []netip.Addr {
	if r, ok := h.Policy.(HostResolver); ok && r != nil {
		addrs, _ := r.AdmittedAddrs(ctx, host)
		return addrs
	}
	addrs, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", absname.Of(host))
	return addrs
}

// egressRate is the forwarder's connection rate: the tool's own rate
// setting (already capped by the local policy) when it has one, else a
// default high enough for a connect scan.
func egressRate(config json.RawMessage, m tool.Manifest) float64 {
	if m.Safety != nil && m.Safety.RateParam != "" {
		var cfg map[string]any
		if json.Unmarshal(config, &cfg) == nil {
			if v, ok := cfg[m.Safety.RateParam].(float64); ok && v > 0 {
				return v
			}
		}
	}
	return 1000
}

// egressLog turns the forwarder's refusals into the task's log lines (the
// first few; the outcome keeps every record).
func egressLog(recs []egress.Record) []LogLine {
	var out []LogLine
	n := 0
	for _, r := range recs {
		if r.Verdict != egress.Refused {
			continue
		}
		n++
		if len(out) < maxEgressLogLines {
			dest := r.Host
			if r.Port > 0 {
				dest = net.JoinHostPort(r.Host, fmt.Sprint(r.Port))
			}
			out = append(out, LogLine{Level: "warn", Msg: "egress refused " + dest + " (" + r.Protocol + "): " + r.Reason,
				Fields: map[string]any{"egress": "refused", "host": r.Host, "port": r.Port, "protocol": r.Protocol}})
		}
	}
	if n > len(out) {
		out = append(out, LogLine{Level: "warn", Msg: fmt.Sprintf("egress refused %d more destinations", n-len(out))})
	}
	return out
}
