package core

// Per-command progress: which of a job's targets are finished. The
// heartbeat carries it for every held command (SensorStatus.Progress), so
// the platform can tell a slow but progressing task from a stuck one, and
// settle finished targets one by one (api research notes 122 and 123). It
// is a liveness hint, never authority: the platform bounds it by the
// command's own target list and never lets it extend a task past its
// overrun or a run past its cap.

import (
	"context"
	"slices"
	"sort"
	"sync"
)

// MaxProgressRanges bounds the index ranges one command's progress lists;
// past it the ranges are left out and only the counts are sent.
const MaxProgressRanges = 256

// CommandProgress is one held command's progress. Finished lists the
// finished targets as inclusive [first, last] index ranges into the
// command's target list, sorted and merged; it is omitted when the job's
// targets are unknown or there are more than MaxProgressRanges ranges.
//
// Records, OutputBytes and CPUMs are liveness counters, all monotonic for
// the job: the records the tool's output delivered and their bytes, and the
// CPU time of the job's tool processes. A batch tool that finishes targets
// rarely still shows it is working through them; the platform calls a task
// stalled only when none of done and these moves for its stall window.
type CommandProgress struct {
	Done        int      `json:"done"`
	Total       int      `json:"total"`
	Finished    [][2]int `json:"finished,omitempty"`
	Records     int64    `json:"records,omitempty"`
	OutputBytes int64    `json:"output_bytes,omitempty"`
	CPUMs       int64    `json:"cpu_ms,omitempty"`
	// ReleasedKeys are the politeness keys the sensor freed because the
	// targets that needed them settled (politeness.Holding): the platform
	// stops counting them as held by the command, so other work on those
	// hosts can start before it ends. Sorted, at most politeness.MaxKeys.
	ReleasedKeys []string `json:"released_keys,omitempty"`
}

// Progress records a job's finished targets. Safe for concurrent use; nil
// is usable (it records nothing).
type Progress struct {
	mu    sync.Mutex
	total int
	index map[string]int // target -> its index in the job's list
	done  map[int]struct{}
	// named counts finishes of targets not in the list (or before it is
	// known), by name, so each counts once.
	named map[string]struct{}
	extra int
	// Liveness counters (CommandProgress).
	records, outputBytes int64
	cpu                  cpuMeter
	// obs is told the job's targets and each finished target (the local
	// queue frees their hosts); called outside mu.
	obs progressObserver
}

// progressObserver is told a job's target list and each target it
// finishes.
type progressObserver struct {
	targets func([]string)
	done    func(string)
}

// observe sets the observer; a target list already set is passed at once.
func (p *Progress) observe(o progressObserver) {
	p.mu.Lock()
	p.obs = o
	var known []string
	if p.index != nil {
		known = make([]string, len(p.index))
		for t, i := range p.index {
			if i < len(known) {
				known[i] = t
			}
		}
	}
	p.mu.Unlock()
	if known != nil && o.targets != nil {
		o.targets(known)
	}
}

// NewProgress returns a Progress over total targets (names unknown).
func NewProgress(total int) *Progress {
	return &Progress{total: max(total, 0), done: map[int]struct{}{}, named: map[string]struct{}{}}
}

// SetTargets sets the job's target list once it is known: the total, and
// the indexes finished targets are reported by.
func (p *Progress) SetTargets(targets []string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.total = len(targets)
	p.index = make(map[string]int, len(targets))
	for i, t := range targets {
		if _, dup := p.index[t]; !dup {
			p.index[t] = i
		}
	}
	obs := p.obs.targets
	p.mu.Unlock()
	if obs != nil {
		obs(slices.Clone(targets))
	}
}

// SetTotal sets the number of targets without their names.
func (p *Progress) SetTotal(total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total = max(total, 0)
}

func (p *Progress) count() int { return len(p.done) + len(p.named) + p.extra }

// TargetDone marks target finished (whatever the outcome: found, nothing,
// failed, timed out). Marking the same target again counts once.
func (p *Progress) TargetDone(target string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	obs := p.obs.done
	p.targetDone(target)
	p.mu.Unlock()
	if obs != nil {
		obs(target)
	}
}

func (p *Progress) targetDone(target string) {
	if p.done == nil {
		p.done, p.named = map[int]struct{}{}, map[string]struct{}{}
	}
	if i, ok := p.index[target]; ok {
		p.done[i] = struct{}{}
		return
	}
	if p.total > 0 && p.count() >= p.total {
		return
	}
	p.named[target] = struct{}{}
}

// DoneN counts n finished targets a tool reports without names.
func (p *Progress) DoneN(n int) {
	if p == nil || n <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.extra += n
}

// Snapshot is the progress now; Done never exceeds Total when Total is
// known.
func (p *Progress) Snapshot() CommandProgress {
	if p == nil {
		return CommandProgress{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	done := p.count()
	if p.total > 0 {
		done = min(done, p.total)
	}
	return CommandProgress{Done: done, Total: p.total, Finished: ranges(p.done),
		Records: p.records, OutputBytes: p.outputBytes, CPUMs: p.cpu.read()}
}

// RecordOutput counts records the tool's output delivered, of n bytes in
// all (a liveness counter).
func (p *Progress) RecordOutput(records int, bytes int) {
	if p == nil || (records <= 0 && bytes <= 0) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records += int64(max(records, 0))
	p.outputBytes += int64(max(bytes, 0))
}

// TrackProcess adds a tool process (and the processes it starts) to the
// job's CPU time (a liveness counter). Where the CPU time of a process
// cannot be read, it counts nothing.
func (p *Progress) TrackProcess(pid int) {
	if p == nil || pid <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cpu.track(pid)
}

// ranges merges finished indexes into sorted inclusive ranges; nil when
// there are none or more than MaxProgressRanges.
func ranges(done map[int]struct{}) [][2]int {
	if len(done) == 0 {
		return nil
	}
	idx := make([]int, 0, len(done))
	for i := range done {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var out [][2]int
	for _, i := range idx {
		if n := len(out); n > 0 && out[n-1][1] == i-1 {
			out[n-1][1] = i
			continue
		}
		if len(out) == MaxProgressRanges {
			return nil
		}
		out = append(out, [2]int{i, i})
	}
	return out
}

type progressKey struct{}

// WithProgress returns ctx carrying p; the command poller puts one in every
// scan job's context.
func WithProgress(ctx context.Context, p *Progress) context.Context {
	return context.WithValue(ctx, progressKey{}, p)
}

// ProgressFrom returns the job's Progress, or nil outside a job.
func ProgressFrom(ctx context.Context) *Progress {
	p, _ := ctx.Value(progressKey{}).(*Progress)
	return p
}

// TargetDone marks target finished in the job's Progress (no-op outside a
// job). A scanner that runs its targets itself calls it as each finishes.
func TargetDone(ctx context.Context, target string) {
	ProgressFrom(ctx).TargetDone(target)
}

// RecordOutput counts records of the job's tool output in its Progress
// (no-op outside a job).
func RecordOutput(ctx context.Context, records, bytes int) {
	ProgressFrom(ctx).RecordOutput(records, bytes)
}

// TrackProcess adds a tool process to the job's CPU time in its Progress
// (no-op outside a job).
func TrackProcess(ctx context.Context, pid int) {
	ProgressFrom(ctx).TrackProcess(pid)
}
