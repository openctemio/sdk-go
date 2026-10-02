package core

// The sensor-side half of scan work distribution (api RFC-030): the
// platform's queue is authoritative; the SDK keeps a small, bounded local
// queue of the commands this sensor holds. A sensor author implements
// executors; the SDK owns claiming (never more than the free slots), local
// ordering, per-host politeness, leases (the held ids on every heartbeat),
// cancellation and draining (unstarted or aborted work is released back to
// the platform, not left to time out).

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/resource"
)

// Release reasons sent with ReleasingCommandClient.ReleaseCommand.
const (
	ReleaseReasonDraining   = "draining"
	ReleaseReasonShutdown   = "shutdown"
	ReleaseReasonCanceled   = "canceled"
	ReleaseReasonPoliteness = "politeness"
)

// ReleasingCommandClient is a CommandClient that can hand a claimed command
// back to the platform, which returns it to pending (unpinned) so another
// sensor can run it at once. The CommandPoller uses it for work it will not
// run (draining, shutdown, canceled). *client.Client implements it.
type ReleasingCommandClient interface {
	ReleaseCommand(ctx context.Context, cmdID, reason string) error
}

// QueueStats is the local queue a heartbeat carries as "queue".
type QueueStats struct {
	// Claimed is the commands this sensor holds (claimed and not finished).
	Claimed int `json:"claimed"`
	// Running is those it is executing.
	Running int `json:"running"`
	// QueuedLocal is those claimed and not started yet.
	QueuedLocal int `json:"queued_local"`
	// OldestAgeSeconds is how long the oldest held command has been held.
	OldestAgeSeconds int64 `json:"oldest_age_seconds"`
}

// StatusReporter fills a heartbeat with what it knows about the sensor's
// work: load, resources, capacity, local queue and the held command ids.
// A BaseSensor whose load reporter (SetLoadReporter) also implements it
// calls it on every heartbeat. *CommandPoller implements it.
type StatusReporter interface {
	ReportStatus(status *SensorStatus)
}

// DefaultDrainGrace is how long a stopping poller lets running commands
// finish before it cancels them and releases them to the platform.
const DefaultDrainGrace = 30 * time.Second

// Errors a held command's context is canceled with (context.Cause).
var (
	errCanceledByPlatform = errors.New("canceled by the platform")
	errDrained            = errors.New("sensor is shutting down")
)

// heldCommand is one command this sensor holds.
type heldCommand struct {
	id        string
	claimedAt time.Time
	started   bool
	hosts     []string
	cancel    context.CancelCauseFunc
}

// localQueue tracks held commands and per-host politeness. Safe for
// concurrent use.
type localQueue struct {
	mu     sync.Mutex
	held   map[string]*heldCommand
	byHost map[string]int
}

func newLocalQueue() *localQueue {
	return &localQueue{held: map[string]*heldCommand{}, byHost: map[string]int{}}
}

// admit reserves the command's hosts if each has fewer than perHost held
// commands; false (nothing reserved) otherwise.
func (q *localQueue) admit(id string, hosts []string, perHost int, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, dup := q.held[id]; dup {
		return false
	}
	if perHost > 0 {
		for _, h := range hosts {
			if q.byHost[h] >= perHost {
				return false
			}
		}
	}
	for _, h := range hosts {
		q.byHost[h]++
	}
	q.held[id] = &heldCommand{id: id, claimedAt: now, hosts: hosts}
	return true
}

// forget drops a held command and frees its hosts.
func (q *localQueue) forget(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	hc := q.held[id]
	if hc == nil {
		return
	}
	for _, h := range hc.hosts {
		if q.byHost[h]--; q.byHost[h] <= 0 {
			delete(q.byHost, h)
		}
	}
	delete(q.held, id)
}

func (q *localQueue) setCancel(id string, cancel context.CancelCauseFunc) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if hc := q.held[id]; hc != nil {
		hc.cancel = cancel
	}
}

func (q *localQueue) markStarted(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if hc := q.held[id]; hc != nil {
		hc.started = true
	}
}

// cancel cancels the held command's context with cause; false if not held.
func (q *localQueue) cancel(id string, cause error) bool {
	q.mu.Lock()
	hc := q.held[id]
	var c context.CancelCauseFunc
	if hc != nil {
		c = hc.cancel
	}
	q.mu.Unlock()
	if hc == nil {
		return false
	}
	if c != nil {
		c(cause)
	}
	return true
}

func (q *localQueue) cancelAll(cause error) {
	q.mu.Lock()
	cs := make([]context.CancelCauseFunc, 0, len(q.held))
	for _, hc := range q.held {
		if hc.cancel != nil {
			cs = append(cs, hc.cancel)
		}
	}
	q.mu.Unlock()
	for _, c := range cs {
		c(cause)
	}
}

// stats and ids of the held commands.
func (q *localQueue) snapshot(now time.Time) (QueueStats, []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	st := QueueStats{Claimed: len(q.held)}
	ids := make([]string, 0, len(q.held))
	var oldest time.Time
	for id, hc := range q.held {
		ids = append(ids, id)
		if hc.started {
			st.Running++
		} else {
			st.QueuedLocal++
		}
		if oldest.IsZero() || hc.claimedAt.Before(oldest) {
			oldest = hc.claimedAt
		}
	}
	if !oldest.IsZero() {
		st.OldestAgeSeconds = int64(now.Sub(oldest) / time.Second)
	}
	sort.Strings(ids)
	return st, ids
}

// =============================================================================
// Command metadata: order, hosts, limits, tool
// =============================================================================

// commandMeta is what the poller reads from a command's payload.
type commandMeta struct {
	Scanner   string   `json:"scanner"`
	Collector string   `json:"collector"`
	Target    string   `json:"target"`
	Targets   []string `json:"targets"`
	Class     string   `json:"class"`
	Priority  string   `json:"priority"`
	Limits    struct {
		PerHostConcurrency int `json:"per_host_concurrency"`
	} `json:"limits"`
}

func parseCommandMeta(cmd *Command) commandMeta {
	var m commandMeta
	if len(cmd.Payload) > 0 {
		_ = json.Unmarshal(cmd.Payload, &m)
	}
	return m
}

// classRank orders priority classes: verify > interactive > scheduled >
// background (api RFC-030 D8). Unknown or absent sorts with scheduled.
func classRank(class string) int {
	switch strings.ToLower(class) {
	case "verify":
		return 0
	case "interactive":
		return 1
	case "background":
		return 3
	default:
		return 2
	}
}

// priorityRank orders command priorities: critical > high > normal > low.
func priorityRank(p string) int {
	switch strings.ToLower(p) {
	case "critical", "p0":
		return 0
	case "high":
		return 1
	case "low":
		return 3
	default:
		return 2
	}
}

// orderCommands sorts a poll batch: class first, then priority, then the
// platform's order.
func orderCommands(cmds []*Command) {
	sort.SliceStable(cmds, func(i, j int) bool {
		mi, mj := parseCommandMeta(cmds[i]), parseCommandMeta(cmds[j])
		if ci, cj := classRank(mi.Class), classRank(mj.Class); ci != cj {
			return ci < cj
		}
		pi, pj := cmds[i].Priority, cmds[j].Priority
		if pi == "" {
			pi = mi.Priority
		}
		if pj == "" {
			pj = mj.Priority
		}
		return priorityRank(pi) < priorityRank(pj)
	})
}

// DefaultPerHostConcurrency is how many held commands may touch one host
// when the command does not say (limits.per_host_concurrency).
const DefaultPerHostConcurrency = 1

// HostKey is the politeness key of a scan target: the host of a URL or
// address, "host/owner" of a repository, the path of a local directory.
func HostKey(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if u, err := url.Parse(t); err == nil && u.Scheme != "" && u.Host != "" {
		host := strings.ToLower(u.Hostname())
		if isRepoHost(u.Path) {
			if owner := firstSegment(u.Path); owner != "" {
				return host + "/" + strings.ToLower(owner)
			}
		}
		return host
	}
	if strings.HasPrefix(t, "git@") { // git@github.com:owner/repo.git
		rest := strings.TrimPrefix(t, "git@")
		host, path, ok := strings.Cut(rest, ":")
		if ok {
			return strings.ToLower(host) + "/" + strings.ToLower(firstSegment(path))
		}
	}
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, ".") || (len(t) > 1 && t[1] == ':') {
		return t // local path
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return strings.ToLower(h)
	}
	if _, n, err := net.ParseCIDR(t); err == nil {
		return n.String()
	}
	if host, path, ok := strings.Cut(t, "/"); ok && strings.Contains(host, ".") && path != "" {
		return strings.ToLower(host) + "/" + strings.ToLower(firstSegment(path))
	}
	return strings.ToLower(t)
}

func isRepoHost(path string) bool {
	return strings.Count(strings.Trim(path, "/"), "/") >= 1
}

func firstSegment(path string) string {
	seg, _, _ := strings.Cut(strings.Trim(path, "/"), "/")
	return seg
}

// commandHosts returns the distinct host keys of a command's targets.
func commandHosts(m commandMeta) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if k := HostKey(t); k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	if m.Target != "" {
		add(m.Target)
	}
	for _, t := range m.Targets {
		add(t)
	}
	return out
}

// =============================================================================
// Process usage of a command
// =============================================================================

type usageKey struct{}

// usageRecorder sums the processes a command ran.
type usageRecorder struct {
	mu     sync.Mutex
	cpu    float64
	peak   int64
	killed bool
	n      int
}

func withUsageRecorder(ctx context.Context) (context.Context, *usageRecorder) {
	r := &usageRecorder{}
	return context.WithValue(ctx, usageKey{}, r), r
}

// RecordProcessState adds a finished process's CPU time and peak memory to
// the command running in ctx, for the per-tool cost history the sensor
// reports (capacity.per_tool). The SDK's exec helpers call it; an executor
// that starts processes itself should call it after Wait. No-op outside a
// command or with a nil state.
func RecordProcessState(ctx context.Context, ps *os.ProcessState) {
	if ps == nil || ctx == nil {
		return
	}
	r, _ := ctx.Value(usageKey{}).(*usageRecorder)
	if r == nil {
		return
	}
	cpu := (ps.UserTime() + ps.SystemTime()).Seconds()
	peak := peakRSSBytes(ps)
	killed := killedBySIGKILL(ps)
	r.mu.Lock()
	r.cpu += cpu
	r.peak = max(r.peak, peak)
	r.killed = r.killed || killed
	r.n++
	r.mu.Unlock()
}

func (r *usageRecorder) sample() (cpu float64, peak int64, killed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cpu, r.peak, r.killed
}

// jobSample turns a finished command into a cost sample.
func jobSample(cmd *Command, m commandMeta, wall time.Duration, rec *usageRecorder, execErr error, ctx context.Context) resource.JobSample {
	tool := m.Scanner
	if tool == "" {
		tool = m.Collector
	}
	if tool == "" {
		tool = cmd.Type
	}
	cpu, peak, killed := rec.sample()
	s := resource.JobSample{Tool: tool, Targets: max(len(commandHosts(m)), len(m.Targets), 1), Wall: wall, CPUSeconds: cpu, PeakRSSBytes: peak}
	switch {
	// A timeout kills the process too (SIGKILL): test the deadline first.
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(execErr, context.DeadlineExceeded):
		s.Outcome = resource.OutcomeTimeout
	case killed:
		s.Outcome = resource.OutcomeKilled
	case execErr != nil:
		s.Outcome = resource.OutcomeFailed
	default:
		s.Outcome = resource.OutcomeSuccess
	}
	return s
}
