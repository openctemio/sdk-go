package core

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// specBackend records the task spec it is asked to prepare and runs
// nothing.
type specBackend struct{ spec executor.TaskSpec }

func (b *specBackend) Name() string            { return "spec" }
func (b *specBackend) Status() executor.Status { return executor.Status{} }
func (b *specBackend) Prepare(spec executor.TaskSpec) (executor.Task, error) {
	b.spec = spec
	return nil, errors.New("not run")
}

// A scanner's grandchild that called setsid left the process group a stop
// kills and outlived the task: runScanner gave the task no envelope, so it
// never got a cgroup of its own even where cgroups are delegated. Every
// scanner task now has one (no limits of its own), killed with the task.
func TestRunScannerGivesTheTaskAnEnvelope(t *testing.T) {
	b := &specBackend{}
	prev := executor.Current()
	executor.SetCurrent(b)
	t.Cleanup(func() { executor.SetCurrent(prev) })
	_, _ = ExecuteScanner(context.Background(), &ExecConfig{Binary: "/bin/true"})
	if b.spec.Envelope == nil {
		t.Fatal("the scanner task has no envelope: its process tree is not contained by a cgroup")
	}
	if *b.spec.Envelope != (executor.Envelope{}) {
		t.Fatalf("envelope %+v: runScanner must not add limits of its own", *b.spec.Envelope)
	}
}

func TestProcessTreeContained(t *testing.T) {
	for _, tc := range []struct {
		st   executor.Status
		want bool
	}{
		{executor.Status{}, false},
		{executor.Status{Envelope: executor.EnvelopeRlimit}, false},
		{executor.Status{Envelope: executor.EnvelopeCgroup}, true},
		{executor.Status{NetworkEnforced: true}, true},
	} {
		if got := tc.st.ProcessTreeContained(); got != tc.want {
			t.Errorf("%+v: %v, want %v", tc.st, got, tc.want)
		}
	}
}
