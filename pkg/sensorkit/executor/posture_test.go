package executor

import (
	"context"
	"errors"
	"testing"
)

func TestProbeBackendsReportsOnlyWhatPassed(t *testing.T) {
	ok := func(context.Context) error { return nil }
	bad := func(context.Context) error { return errors.New("no kvm") }
	boom := func(context.Context) error { panic("boom") }
	p := ProbeBackends(context.Background(),
		Candidate{Name: "process", Class: ClassProcess, Probe: ok},
		Candidate{Name: "gvisor", Class: ClassStrong, Detail: "systrap", Probe: bad},
		Candidate{Name: "microvm", Class: ClassStrong, Probe: boom},
		Candidate{Name: "noprobe", Class: ClassStrong},
		Candidate{Name: "weird", Class: "ultra", Probe: ok},
	)
	if len(p.Backends) != 5 {
		t.Fatalf("report %+v", p.Backends)
	}
	for i, wantProven := range []bool{true, false, false, false, false} {
		if p.Backends[i].Proven != wantProven {
			t.Errorf("%s: proven %v, want %v (%s)", p.Backends[i].Name, p.Backends[i].Proven, wantProven, p.Backends[i].Reason)
		}
		if !wantProven && p.Backends[i].Reason == "" {
			t.Errorf("%s: a failed probe says why", p.Backends[i].Name)
		}
	}
	if p.StrongProven() {
		t.Fatal("no strong backend passed, yet StrongProven")
	}
}

func TestStrongProvenNeedsAStrongBackend(t *testing.T) {
	ok := func(context.Context) error { return nil }
	// A proven process backend is not a strong one.
	if ProbeBackends(context.Background(), Candidate{Name: "process", Class: ClassProcess, Probe: ok}).StrongProven() {
		t.Fatal("the process backend must not make a sensor strong")
	}
	if !ProbeBackends(context.Background(), Candidate{Name: "gvisor", Class: ClassStrong, Probe: ok}).StrongProven() {
		t.Fatal("a proven strong backend makes the sensor strong")
	}
}

// The process backend's probe runs a real confined task: off mode, or a
// host that cannot confine, is not proven.
func TestProcessCandidateProbesARealTask(t *testing.T) {
	b := newConfinedBackend(t)
	p := ProbeBackends(context.Background(), ProcessCandidate(b))
	if !p.Backends[0].Proven {
		t.Fatalf("a confined process backend is proven: %+v", p.Backends[0])
	}
	if p.StrongProven() {
		t.Fatal("the process backend is not strong")
	}
	off, err := NewProcessBackend(Config{Mode: ModeOff, WorkRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := ProbeBackends(context.Background(), ProcessCandidate(off)).Backends[0]
	if r.Proven || r.Reason == "" {
		t.Fatalf("a backend in mode off is not proven: %+v", r)
	}
}
