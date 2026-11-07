package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// CapabilityIsolationStrong is the capability a sensor advertises when at
// least one strong isolation backend passed its start-up probe: a job whose
// tool needs isolation "strong" (tool.IsolationStrong) goes only to such a
// sensor, and waits otherwise. It comes from a probe that really ran a
// confined task, never from a setting, and the platform counts only what the
// sensor itself reported.
const CapabilityIsolationStrong = "isolation.strong@1"

// Isolation classes of a backend (the values of a tool manifest's
// isolation field).
const (
	// ClassProcess is the sensor's process sandbox.
	ClassProcess = "process"
	// ClassStrong is a backend with a boundary beyond the sensor's own
	// kernel surface (a gVisor or microVM task); none ships yet.
	ClassStrong = "strong"
)

// probeTimeout bounds one backend probe.
const probeTimeout = 20 * time.Second

// Candidate is a backend the sensor may offer: how to prove it.
type Candidate struct {
	// Name is the backend ("process", "gvisor", "microvm").
	Name string
	// Class is ClassProcess or ClassStrong: what a task on it is worth.
	Class string
	// Detail is free text for the report (platform, version, hypervisor).
	Detail string
	// Probe really runs a confined task on the backend and returns nil only
	// when the task ran confined as the class promises.
	Probe func(ctx context.Context) error
}

// BackendReport is the outcome of one probe.
type BackendReport struct {
	Name   string `json:"name"`
	Class  string `json:"class"`
	Detail string `json:"detail,omitempty"`
	// Proven is true when the probe ran a confined task successfully.
	Proven bool `json:"proven"`
	// Reason says why a backend is not proven.
	Reason string `json:"reason,omitempty"`
}

// Posture is what a sensor proved at start-up: one report per candidate.
type Posture struct {
	Backends []BackendReport `json:"backends"`
}

// ProbeBackends runs every candidate's probe, one after the other, each
// under its own timeout. A probe that panics counts as failed.
func ProbeBackends(ctx context.Context, candidates ...Candidate) Posture {
	var p Posture
	for _, c := range candidates {
		r := BackendReport{Name: c.Name, Class: c.Class, Detail: c.Detail}
		if err := runProbe(ctx, c); err != nil {
			r.Reason = err.Error()
		} else {
			r.Proven = true
		}
		p.Backends = append(p.Backends, r)
	}
	return p
}

func runProbe(ctx context.Context, c Candidate) (err error) {
	if c.Probe == nil {
		return errors.New("no probe")
	}
	if c.Class != ClassProcess && c.Class != ClassStrong {
		return fmt.Errorf("unknown isolation class %q", c.Class)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("probe panicked: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return c.Probe(ctx)
}

// StrongProven reports whether any backend of class strong passed its probe.
func (p Posture) StrongProven() bool {
	for _, b := range p.Backends {
		if b.Class == ClassStrong && b.Proven {
			return true
		}
	}
	return false
}

// ProcessCandidate is the process backend as a candidate. Its probe runs a
// real task through the backend (the sensor's own binary, which exits at
// once, as the launcher's helper) and accepts the backend only when that
// task ran sandboxed with its network confined. A backend in mode off, or one
// that fell back to plain child processes, is not proven.
func ProcessCandidate(b Backend) Candidate {
	return Candidate{Name: b.Name(), Class: ClassProcess, Probe: func(ctx context.Context) error {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("find the sensor binary: %w", err)
		}
		return probeTask(ctx, b, exe, func(r *Result) error {
			switch {
			case !r.Sandbox.Sandboxed:
				return errors.New("the task ran without the sandbox")
			case !r.Sandbox.NetworkEnforced:
				return errors.New("the task ran with its network unconfined")
			}
			return nil
		})
	}}
}

// probeTask runs one task on b: program with the envelope probe argument,
// which a program that called RunLauncherIfRequested answers by exiting 0.
func probeTask(ctx context.Context, b Backend, program string, check func(*Result) error) error {
	var out bytes.Buffer
	t, err := b.Prepare(TaskSpec{ID: "isolation-probe", Argv: []string{program, EnvelopeProbeArg}, Stdout: &out, Stderr: &out, Network: NetworkNone})
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer func() { _ = t.Cleanup() }()
	if err := t.Start(ctx); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			t.Kill("probe timeout")
		case <-done:
		}
	}()
	res, err := t.Wait()
	close(done)
	if err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("the task exited %d: %s", res.ExitCode, truncate(out.String(), 200))
	}
	return check(res)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
