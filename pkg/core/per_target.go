package core

// RunPerTarget runs one function per target with the layered budget of api
// research note 122: each target gets its own deadline (the per-target
// budget), at most Concurrency run at once, a target that exceeds its
// budget is recorded as a reach timeout and the others go on, and when the
// job's context ends the targets already finished keep their results.

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/reach"
)

// PerTargetOptions configure RunPerTarget.
type PerTargetOptions struct {
	// Timeout is each target's budget; 0 runs a target until the job's
	// context ends.
	Timeout time.Duration
	// Concurrency is how many targets run at once; < 1 is 1.
	Concurrency int
}

// TargetOutcome is how one target ended.
type TargetOutcome struct {
	Target string
	// Err is the function's error; context.DeadlineExceeded when the
	// target exceeded its budget.
	Err error
	// TimedOut is set when the target exceeded its budget.
	TimedOut bool
	// Skipped is set when the job's context ended before the target
	// started.
	Skipped bool
}

// RunPerTarget calls fn for every target and returns one outcome per
// target, in the targets' order. It returns when every started target
// ended; targets not started when ctx ended are Skipped. Every target that
// ends (any outcome but Skipped) is marked done in the job's Progress.
func RunPerTarget(ctx context.Context, targets []string, opts PerTargetOptions, fn func(ctx context.Context, target string) error) []TargetOutcome {
	out := make([]TargetOutcome, len(targets))
	conc := max(opts.Concurrency, 1)
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, t := range targets {
		out[i].Target = t
		select {
		case <-ctx.Done():
			out[i].Skipped = true
			continue
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			<-sem
			out[i].Skipped = true
			continue
		}
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			tctx, cancel := ctx, context.CancelFunc(func() {})
			if opts.Timeout > 0 {
				tctx, cancel = context.WithTimeout(ctx, opts.Timeout)
			}
			err := fn(tctx, target)
			cancel()
			// Only the target's own budget makes it a target timeout; the
			// job ending is not this target's fault.
			if opts.Timeout > 0 && ctx.Err() == nil && errors.Is(tctx.Err(), context.DeadlineExceeded) {
				out[i].TimedOut = true
				if err == nil {
					err = context.DeadlineExceeded
				}
				if rec := reach.FromContext(ctx); rec != nil {
					rec.Record(reach.Observation{Target: target, Class: reach.Timeout})
				}
			}
			out[i].Err = err
			TargetDone(ctx, target)
		}(i, t)
	}
	wg.Wait()
	return out
}
