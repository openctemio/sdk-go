package core

// Per-command progress: how many of a job's targets are finished. The
// heartbeat carries it for every held command (SensorStatus.Progress), so
// the platform can tell a slow but progressing task from a stuck one
// (api research note 122). It is a liveness hint, never authority: the
// platform bounds it by the command's own target count and never lets it
// extend a task past its overrun or a run past its cap.

import (
	"context"
	"sync"
)

// CommandProgress is one held command's progress.
type CommandProgress struct {
	Done  int `json:"done"`
	Total int `json:"total"`
}

// Progress counts a job's finished targets. Safe for concurrent use; the
// zero value and nil are usable (a nil Progress counts nothing).
type Progress struct {
	mu    sync.Mutex
	total int
	done  map[string]struct{}
	// extra counts finishes with no target name (DoneN).
	extra int
}

// NewProgress returns a Progress over total targets.
func NewProgress(total int) *Progress {
	return &Progress{total: max(total, 0), done: map[string]struct{}{}}
}

// SetTotal sets the number of targets once the job knows it (the command
// poller creates the Progress before the payload is read).
func (p *Progress) SetTotal(total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total = max(total, 0)
}

// TargetDone marks target finished (whatever the outcome: found, nothing,
// timed out). Marking the same target again counts once.
func (p *Progress) TargetDone(target string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done == nil {
		p.done = map[string]struct{}{}
	}
	if p.total > 0 && len(p.done)+p.extra >= p.total {
		return
	}
	p.done[target] = struct{}{}
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
	done := len(p.done) + p.extra
	if p.total > 0 {
		done = min(done, p.total)
	}
	return CommandProgress{Done: done, Total: p.total}
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
