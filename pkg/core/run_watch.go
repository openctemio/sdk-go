package core

// Run watch: the bounds a sensor puts on one tool run and on one command
// so a job always reports before the platform gives up on it (live
// incident 2026-10-25: a run that settled every target and then hung was
// failed by the platform at the run deadline with nothing reported).
//
//   - Deadline budget: a scan command may carry the absolute time the
//     platform stops waiting for it (ScanCommandPayload.Deadline, the scan
//     run's deadline). The job's time budget ends DeadlineMargin before it,
//     so a run stopped there still delivers what it settled (partial) in
//     time. The platform can only shorten a job this way, never lengthen
//     it past MaxScanTimeout or the local policy's cap.
//   - Run watch (RunWatch, read by the tool host for every tool run of the
//     job): a tool that settled every target but does not send its result
//     within FinishGrace is stopped and its results delivered; a tool that
//     sends nothing but heartbeats while its processes use no CPU for
//     Inactivity is stopped as timed out, keeping what it settled.

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// Deadline budget bounds.
const (
	// MinDeadlineMargin and MaxDeadlineMargin bound the time kept before
	// the platform's deadline to stop the tool and deliver: a tenth of the
	// time left, within these bounds.
	MinDeadlineMargin = time.Minute
	MaxDeadlineMargin = 10 * time.Minute
	// MinDeadlineBudget is the least a job gets however close its deadline
	// is: a deadline already passed (or a skewed clock) still lets the job
	// start and report.
	MinDeadlineBudget = 30 * time.Second
)

// DeadlineMargin is the time kept before a deadline remaining away.
func DeadlineMargin(remaining time.Duration) time.Duration {
	return clampDuration(remaining/10, MinDeadlineMargin, MaxDeadlineMargin)
}

// capToDeadline is timeout (0: none) capped so the job ends DeadlineMargin
// before deadline (zero: no deadline, timeout unchanged).
func capToDeadline(timeout time.Duration, deadline, now time.Time) time.Duration {
	if deadline.IsZero() {
		return timeout
	}
	remaining := deadline.Sub(now)
	budget := max(remaining-DeadlineMargin(remaining), MinDeadlineBudget)
	if timeout <= 0 || budget < timeout {
		return budget
	}
	return timeout
}

// Run watch defaults and bounds.
const (
	// DefaultFinishGrace is how long a tool that settled every target may
	// take to send its result.
	DefaultFinishGrace = 5 * time.Minute
	// DefaultInactivity is how long a tool may send nothing but heartbeats
	// while its processes use no CPU.
	DefaultInactivity = 20 * time.Minute
	// MinInactivity and MaxInactivity bound an inactivity window the
	// platform sends (TaskBudget.StallSeconds).
	MinInactivity = 5 * time.Minute
	MaxInactivity = 2 * time.Hour
)

// RunWatch bounds each tool run of a job. A zero field takes its default;
// a negative one turns that check off.
type RunWatch struct {
	FinishGrace time.Duration
	Inactivity  time.Duration
}

// Effective is w with its defaults applied (0: the check is off).
func (w RunWatch) Effective() RunWatch {
	switch {
	case w.FinishGrace == 0:
		w.FinishGrace = DefaultFinishGrace
	case w.FinishGrace < 0:
		w.FinishGrace = 0
	}
	switch {
	case w.Inactivity == 0:
		w.Inactivity = DefaultInactivity
	case w.Inactivity < 0:
		w.Inactivity = 0
	}
	return w
}

// runWatchFor is the run watch of a scan command: the platform's stall
// window (clamped) as the inactivity window when it sent one.
func runWatchFor(b *TaskBudget) RunWatch {
	if b == nil || b.StallSeconds <= 0 {
		return RunWatch{}
	}
	return RunWatch{Inactivity: clampDuration(time.Duration(b.StallSeconds)*time.Second, MinInactivity, MaxInactivity)}
}

type runWatchKey struct{}

// WithRunWatch returns ctx carrying w for the tool runs under it.
func WithRunWatch(ctx context.Context, w RunWatch) context.Context {
	return context.WithValue(ctx, runWatchKey{}, w)
}

// RunWatchFrom is the run watch ctx carries (zero: the defaults).
func RunWatchFrom(ctx context.Context) RunWatch {
	if ctx == nil {
		return RunWatch{}
	}
	w, _ := ctx.Value(runWatchKey{}).(RunWatch)
	return w
}

// ProcessCPU is the CPU time of tracked processes with the processes they
// start: the same measure as a job's progress (cpu_ms), for one tool run.
// Safe for concurrent use.
type ProcessCPU struct {
	mu sync.Mutex
	m  cpuMeter
}

// Track adds the process pid (and, from then on, its descendants).
func (c *ProcessCPU) Track(pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m.track(pid)
}

// Read is the CPU time so far; ok is false where process CPU time cannot
// be read (not Linux), and then the time is 0.
func (c *ProcessCPU) Read() (time.Duration, bool) {
	if !cpuReadable {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Duration(c.m.read()) * time.Millisecond, true
}

// cpuReadable says process CPU time is read on this system (procTable).
var cpuReadable = runtime.GOOS == "linux"
