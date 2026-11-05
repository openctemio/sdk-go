package sensorkit

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

func isolationKit(t *testing.T) *Kit {
	t.Helper()
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func advertisesStrong(k *Kit) bool {
	return slices.Contains(k.Tools().CapabilityReport(context.Background()).Capabilities, executor.CapabilityIsolationStrong)
}

func TestProbeIsolationAdvertisesStrongOnlyWhenProven(t *testing.T) {
	ok := func(context.Context) error { return nil }
	for _, tc := range []struct {
		name   string
		extra  []executor.Candidate
		strong bool
		code   string
	}{
		{"no strong backend", nil, false, ""},
		{"strong probe fails", []executor.Candidate{{Name: "gvisor", Class: executor.ClassStrong, Probe: func(context.Context) error { return errors.New("runsc not found") }}}, false, ""},
		{"strong probe passes", []executor.Candidate{{Name: "gvisor", Class: executor.ClassStrong, Probe: ok}}, true, "strong"},
		// A "strong" name on a process-class candidate proves nothing.
		{"mislabeled process backend", []executor.Candidate{{Name: "strong", Class: executor.ClassProcess, Probe: ok}}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The environment cannot add it either.
			t.Setenv("SENSOR_ISOLATION_STRONG", "1")
			k := isolationKit(t)
			k.ProbeIsolation(context.Background(), tc.extra...)
			if got := advertisesStrong(k); got != tc.strong {
				t.Fatalf("advertises %s: %v, want %v", executor.CapabilityIsolationStrong, got, tc.strong)
			}
			if tc.code != "" {
				if c, ok := findCheck(*k.ConfigReport(), CheckIsolation); !ok || c.Code != tc.code {
					t.Fatalf("check %+v (found %v), want code %s", c, ok, tc.code)
				}
			}
		})
	}
}

func TestIsolationNotAdvertisedBeforeProbe(t *testing.T) {
	if advertisesStrong(isolationKit(t)) {
		t.Fatal("a sensor that has not probed must not advertise strong isolation")
	}
}

func TestIsolationCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		p      executor.Posture
		code   string
		status string
	}{
		{"strong", executor.Posture{Backends: []executor.BackendReport{{Name: "process", Class: "process", Proven: true}, {Name: "gvisor", Class: "strong", Proven: true}}}, "strong", core.CheckPass},
		{"process only", executor.Posture{Backends: []executor.BackendReport{{Name: "process", Class: "process", Proven: true}}}, "process_only", core.CheckPass},
		{"nothing proven", executor.Posture{Backends: []executor.BackendReport{{Name: "process", Class: "process", Reason: "no userns"}}}, "none_proven", core.CheckWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if c := isolationCheck(tc.p); c.Code != tc.code || c.Status != tc.status {
				t.Fatalf("check %+v, want %s/%s", c, tc.code, tc.status)
			}
		})
	}
}

// The capability follows the latest probe: a later failed probe withdraws
// what an earlier one proved.
func TestProbeIsolationWithdrawsStrongAfterFailedProbe(t *testing.T) {
	k := isolationKit(t)
	var fail atomic.Bool
	cand := executor.Candidate{Name: "gvisor", Class: executor.ClassStrong, Probe: func(context.Context) error {
		if fail.Load() {
			return errors.New("runsc died")
		}
		return nil
	}}
	k.ProbeIsolation(context.Background(), cand)
	if !advertisesStrong(k) {
		t.Fatal("a proven strong backend is not advertised")
	}
	fail.Store(true)
	k.ProbeIsolation(context.Background(), cand)
	if advertisesStrong(k) {
		t.Fatal("a failed probe left the capability advertised")
	}
	if executor.CapabilityIsolationStrong != core.CapabilityIsolationStrong {
		t.Fatal("the executor and core constants differ")
	}
}
