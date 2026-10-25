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
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/openctemio/ctis/politeness"
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

// ErrStoppedByPlatform is the cause a held command's context is canceled
// with when the platform asks the sensor to stop it and deliver what it
// finished (stop_command_ids: the task stalled). Unlike a cancel, the run's
// settled targets are delivered and the command completes partial with the
// rest unfinished; the platform runs only those again.
var ErrStoppedByPlatform = errors.New("stopped by the platform (the task stalled); delivering what it finished")

// heldCommand is one command this sensor holds.
type heldCommand struct {
	id        string
	claimedAt time.Time
	started   bool
	// hosts are the politeness keys the command still holds: its keys at
	// admission minus those its settled targets released.
	hosts  []string
	cancel context.CancelCauseFunc
	// canceled is set by the first cancel: a repeated one (the platform
	// re-sends its cancel on every heartbeat until the command is gone) is
	// a no-op.
	canceled bool
	progress *Progress
	// holding tracks which keys the command's pending targets still need
	// (politeness.Holding); nil until its targets are known.
	holding *politeness.Holding
	// network scopes the keys of its targets (commandMeta.NetworkID).
	network string
	// released are the keys its settled targets released, reported on the
	// heartbeat (CommandProgress.ReleasedKeys): sorted, at most
	// politeness.MaxKeys.
	released []string
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

// admit reserves the command's host keys if fewer than perHost held
// commands hold a key they conflict with (politeness.Conflicts: the same
// host, or an address and a range scan of its bucket; two addresses of one
// bucket do not conflict); false (nothing reserved) otherwise.
func (q *localQueue) admit(id string, hosts []string, perHost int, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, dup := q.held[id]; dup {
		return false
	}
	if perHost > 0 {
		for _, h := range politeness.Conflicts(hosts) {
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

// track starts releasing the held command's keys target by target: a key
// is freed once a settled target produced it and no pending target does
// (politeness.Holding). targets are the command's targets in network.
// Called again with the job's own target list (Progress.SetTargets: the
// targets the executor runs, as it reports them done), it starts over
// from the keys still held.
func (q *localQueue) track(id string, targets []string, network string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	hc := q.held[id]
	if hc == nil || len(hc.hosts) == 0 {
		return
	}
	hc.network = network
	hc.holding = politeness.NewHolding(hc.hosts, targets, network)
}

// settle records that target of the held command id ended and frees the
// keys no pending target of it needs any more. A target the command does
// not have, or one settled before, frees nothing. Reports whether a key
// was freed.
func (q *localQueue) settle(id, target string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	hc := q.held[id]
	if hc == nil || hc.holding == nil {
		return false
	}
	freed := hc.holding.Settle(target)
	if len(freed) == 0 {
		return false
	}
	for _, h := range freed {
		if q.byHost[h]--; q.byHost[h] <= 0 {
			delete(q.byHost, h)
		}
		if i := slices.Index(hc.hosts, h); i >= 0 {
			hc.hosts = slices.Delete(hc.hosts, i, i+1)
		}
	}
	hc.released = append(hc.released, freed...)
	slices.Sort(hc.released)
	hc.released = slices.Compact(hc.released)
	if len(hc.released) > politeness.MaxKeys {
		hc.released = hc.released[:politeness.MaxKeys]
	}
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

// setProgress attaches the held command's progress. With onFreed, the
// targets the job reports done free their hosts at once (settle), and
// onFreed is called (outside the queue's lock) when one did.
func (q *localQueue) setProgress(id string, p *Progress, onFreed func()) {
	q.mu.Lock()
	hc := q.held[id]
	if hc != nil {
		hc.progress = p
	}
	network := ""
	if hc != nil {
		network = hc.network
	}
	q.mu.Unlock()
	if hc == nil || p == nil {
		return
	}
	p.observe(progressObserver{
		targets: func(targets []string) { q.track(id, targets, network) },
		done: func(target string) {
			if q.settle(id, target) && onFreed != nil {
				onFreed()
			}
		},
	})
}

// progress is the progress of every held command that reports one; nil
// when none does.
func (q *localQueue) progress() map[string]CommandProgress {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out map[string]CommandProgress
	for id, hc := range q.held {
		if hc.progress == nil {
			continue
		}
		snap := hc.progress.Snapshot()
		if snap.Total == 0 && snap.Done == 0 {
			continue
		}
		if len(hc.released) > 0 {
			snap.ReleasedKeys = slices.Clone(hc.released)
		}
		if out == nil {
			out = make(map[string]CommandProgress, len(q.held))
		}
		out[id] = snap
	}
	return out
}

func (q *localQueue) markStarted(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if hc := q.held[id]; hc != nil {
		hc.started = true
	}
}

// cancel cancels the held command's context with cause; false if not held.
// cancel cancels held command id with cause. It reports whether this call
// canceled it: false when id is not held or was canceled already (a
// repeated cancel is idempotent and changes nothing).
func (q *localQueue) cancel(id string, cause error) bool {
	q.mu.Lock()
	hc := q.held[id]
	var c context.CancelCauseFunc
	first := false
	if hc != nil && !hc.canceled {
		c, first = hc.cancel, true
		hc.canceled = hc.cancel != nil
	}
	q.mu.Unlock()
	if !first {
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
	Scanner   string `json:"scanner"`
	Collector string `json:"collector"`
	// PreferredTool is the tool a command asks for when it names no
	// scanner (the platform's tool gate reads the same two members).
	PreferredTool string   `json:"preferred_tool"`
	Target        string   `json:"target"`
	Targets       []string `json:"targets"`
	// HostKeys are the politeness keys the platform admitted the command
	// under and holds while it runs (ctis/politeness); absent from an older
	// platform. An empty list is a command that touches no target host
	// (a passive stage).
	HostKeys *[]string `json:"host_keys"`
	// NetworkID is the network the command's targets belong to (api
	// RFC-089); it scopes the keys of private addresses and names.
	NetworkID string `json:"network_id"`
	Class     string `json:"class"`
	Priority  string `json:"priority"`
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

// DefaultPerHostConcurrency is how many held commands may touch one host
// when the command does not say (limits.per_host_concurrency).
const DefaultPerHostConcurrency = 1

// HostKey is the politeness key of a scan target: the host of a URL, a
// service or an address, "host/owner" of a repository, the path of a local
// directory (politeness.HostOf).
//
// Deprecated: use github.com/openctemio/ctis/politeness, the one
// definition the platform uses too (HostOf, Keys).
func HostKey(target string) string {
	return politeness.HostOf(target)
}

// maxHostKeyLen bounds one politeness key taken from a command.
const maxHostKeyLen = 512

// commandHosts is the politeness keys a command is admitted under: the keys
// the platform sent with it (it admitted the command under those and holds
// them while it runs, so the sensor never refuses what the platform has
// just offered for a host the two disagree on), else the keys of its
// targets by the same function (ctis/politeness). Sent keys are bounded: at
// most politeness.MaxKeys, each at most 512 bytes, empty ones dropped.
func commandHosts(m commandMeta) []string {
	if m.HostKeys != nil {
		out := make([]string, 0, min(len(*m.HostKeys), politeness.MaxKeys))
		for _, k := range *m.HostKeys {
			if k == "" || len(k) > maxHostKeyLen {
				continue
			}
			if len(out) == politeness.MaxKeys {
				break
			}
			out = append(out, k)
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return politeness.Keys(commandTargets(m), m.NetworkID)
}

// commandTargets is a command's target and targets.
func commandTargets(m commandMeta) []string {
	if m.Target == "" {
		return m.Targets
	}
	return append([]string{m.Target}, m.Targets...)
}

// distinctHosts is how many hosts a command's targets name.
func distinctHosts(m commandMeta) int {
	seen := map[string]bool{}
	for _, t := range commandTargets(m) {
		if h := politeness.HostOf(t); h != "" {
			seen[h] = true
		}
	}
	return len(seen)
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
	s := resource.JobSample{Tool: tool, Targets: max(distinctHosts(m), len(m.Targets), 1), Wall: wall, CPUSeconds: cpu, PeakRSSBytes: peak}
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
