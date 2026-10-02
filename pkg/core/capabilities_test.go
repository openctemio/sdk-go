package core

import (
	"context"
	"runtime"
	"testing"
)

func TestCapabilityReportApply(t *testing.T) {
	tools := []ToolInfo{{Name: "semgrep", Version: "1.0", Installed: true}}
	caps := []string{"sast"}
	r := CapabilityReport{Tools: tools, Capabilities: caps, MaxConcurrentJobs: 4}

	st := &SensorStatus{MaxConcurrentJobs: 9}
	r.Apply(st)
	if len(st.Tools) != 1 || st.Tools[0].Name != tools[0].Name || st.Tools[0].Version != tools[0].Version || !st.Tools[0].Installed || len(st.Capabilities) != 1 || st.MaxConcurrentJobs != 4 {
		t.Fatalf("apply: %+v", st)
	}
	// The status owns copies: the reporter may reuse its slices.
	tools[0].Name, caps[0] = "changed", "changed"
	if st.Tools[0].Name != "semgrep" || st.Capabilities[0] != "sast" {
		t.Fatal("Apply aliased the reporter's slices")
	}

	// nil / 0 report nothing and leave the status alone.
	st2 := &SensorStatus{Tools: []ToolInfo{{Name: "x"}}, MaxConcurrentJobs: 2}
	CapabilityReport{}.Apply(st2)
	if len(st2.Tools) != 1 || st2.Capabilities != nil || st2.MaxConcurrentJobs != 2 {
		t.Fatalf("empty report changed the status: %+v", st2)
	}
	// An empty, non-nil list is a report of none.
	CapabilityReport{Tools: []ToolInfo{}}.Apply(st2)
	if st2.Tools == nil || len(st2.Tools) != 0 {
		t.Fatalf("empty inventory not applied: %+v", st2.Tools)
	}
	CapabilityReport{}.Apply(nil) // no panic
}

func TestBaseSensorReportsHostAndCapabilities(t *testing.T) {
	s := NewBaseSensor(&BaseSensorConfig{Name: "s"}, nil)
	st := s.Status()
	if st.OS != runtime.GOOS || st.Arch != runtime.GOARCH {
		t.Fatalf("os/arch = %q/%q", st.OS, st.Arch)
	}
	if got := s.withCapabilities(context.Background(), s.Status()); got.Tools != nil || got.MaxConcurrentJobs != 0 {
		t.Fatalf("no reporter must report nothing: %+v", got)
	}
	s.SetCapabilityReporter(StaticCapabilities(CapabilityReport{MaxConcurrentJobs: 7}))
	if got := s.withCapabilities(context.Background(), s.Status()); got.MaxConcurrentJobs != 7 {
		t.Fatalf("reporter not applied: %+v", got)
	}
	// The stored status is not changed by a heartbeat's report.
	if s.Status().MaxConcurrentJobs != 0 {
		t.Fatal("report leaked into the stored status")
	}
}
