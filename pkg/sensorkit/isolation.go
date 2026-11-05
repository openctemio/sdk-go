package sensorkit

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// CheckIsolation is the config report check of the isolation backends the
// sensor proved at start-up.
const CheckIsolation = "runtime.isolation"

// ProbeIsolation proves, at start-up, which isolation backends this sensor
// really has: it runs a confined task on each (the process backend the kit
// installed, plus any extra strong candidates the program offers) and
// reports the outcome. The capability isolation.strong@1 is advertised only
// when a strong backend passed its probe; no setting, environment variable
// or declaration can add it. Call it after New and before Run. It returns
// the posture.
func (k *Kit) ProbeIsolation(ctx context.Context, extra ...executor.Candidate) executor.Posture {
	cands := append([]executor.Candidate{executor.ProcessCandidate(executor.Current())}, extra...)
	p := executor.ProbeBackends(ctx, cands...)
	k.isolation = p
	for _, b := range p.Backends {
		switch {
		case b.Proven:
			_, _ = fmt.Fprintf(k.out, "  Isolation backend: %s (%s), proven by a confined task\n", b.Name, b.Class)
		default:
			_, _ = fmt.Fprintf(k.errw, "Warning: isolation backend %s (%s) is not available: %s\n", b.Name, b.Class, b.Reason)
		}
	}
	if p.StrongProven() {
		k.Tools().AddCapabilities(executor.CapabilityIsolationStrong)
	}
	k.ReportCheck(isolationCheck(p))
	return p
}

// IsolationPosture is what ProbeIsolation proved (empty before it ran).
func (k *Kit) IsolationPosture() executor.Posture { return k.isolation }

// isolationCheck is the config report check of a posture: pass with a strong
// backend proven; pass with the process backend only (the default, jobs that
// need strong isolation wait for another sensor); a warning when not even the
// process backend ran a confined task.
func isolationCheck(p executor.Posture) core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckIsolation, Status: core.CheckPass}
	var proven, failed []string
	process := false
	for _, b := range p.Backends {
		if b.Proven {
			proven = append(proven, b.Name)
			process = process || b.Class == executor.ClassProcess
		} else {
			failed = append(failed, b.Name+": "+b.Reason)
		}
	}
	switch {
	case p.StrongProven():
		c.Code, c.Summary = "strong", "a strong isolation backend is proven: "+strings.Join(proven, ", ")
	case process:
		c.Code, c.Summary = "process_only", "the process sandbox is proven; no strong isolation backend, so jobs of tools that need strong isolation wait for another sensor"
	default:
		c.Status, c.Code = core.CheckWarn, "none_proven"
		c.Summary = "no isolation backend ran a confined task on this host"
	}
	if len(failed) > 0 {
		c.Excerpt = truncateBytes(strings.Join(failed, "; "), maxUnavailableExcerptSize)
	}
	return c
}
