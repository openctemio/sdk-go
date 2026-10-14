package core

// Waves of a list tool's targets (api research note 130): a tool that
// settles no target before its whole run ends (nuclei runs every template
// over every host and reports no per-host end) is run once per wave
// instead, and each wave's targets are marked done when the wave ends. The
// command's local queue then frees those hosts at once (Progress.TargetDone,
// politeness.Holding), so the next tool of a pipeline starts on them while
// the later waves still run.

import (
	"context"
	"slices"

	"github.com/openctemio/ctis/politeness"
)

// PlanWaves cuts targets into at most maxWaves waves of whole hosts
// (politeness.Group in network): every target of one host is in one wave,
// so a wave that ends frees its hosts completely. Waves are balanced by
// target count (the largest host first, into the smallest wave), keep the
// targets' order inside each wave and are ordered by their first target.
// maxWaves < 1 is 1; fewer hosts than maxWaves give one wave per host. Nil
// for no targets.
func PlanWaves(targets []string, network string, maxWaves int) [][]string {
	if len(targets) == 0 {
		return nil
	}
	groups := politeness.GroupKeys(targetKeys(targets, network))
	n := min(max(maxWaves, 1), len(groups))
	order := make([]int, len(groups))
	for i := range order {
		order[i] = i
	}
	// Largest host first; equal hosts keep their order (stable).
	slices.SortStableFunc(order, func(a, b int) int { return len(groups[b]) - len(groups[a]) })
	members := make([][]int, n)
	for _, g := range order {
		w := 0
		for i := 1; i < n; i++ {
			if len(members[i]) < len(members[w]) {
				w = i
			}
		}
		members[w] = append(members[w], groups[g]...)
	}
	for _, m := range members {
		slices.Sort(m)
	}
	slices.SortFunc(members, func(a, b []int) int { return a[0] - b[0] })
	out := make([][]string, n)
	for w, m := range members {
		out[w] = make([]string, len(m))
		for j, i := range m {
			out[w][j] = targets[i]
		}
	}
	return out
}

func targetKeys(targets []string, network string) [][]string {
	keys := make([][]string, len(targets))
	for i, t := range targets {
		keys[i] = politeness.TargetKeys(t, network)
	}
	return keys
}

// RunWaves runs fn once per wave of targets (PlanWaves), one wave after the
// other, and calls done for every target of a wave when its run returns,
// whatever it returned, so the wave's hosts are freed while later waves
// run. A nil done marks the target done in the job's Progress (TargetDone);
// a tool run out of process passes its tool context's TargetDone. It stops
// at the first error, or when ctx ends, and returns it; the targets of the
// waves not run are not marked done.
func RunWaves(ctx context.Context, targets []string, network string, maxWaves int,
	fn func(ctx context.Context, wave []string) error, done func(target string),
) error {
	if done == nil {
		done = func(t string) { TargetDone(ctx, t) }
	}
	for _, wave := range PlanWaves(targets, network, maxWaves) {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn(ctx, wave)
		for _, t := range wave {
			done(t)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
