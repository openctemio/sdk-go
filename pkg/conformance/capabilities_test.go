package conformance

// api RFC-029 §4.3.1: a sensor reports its tool inventory, capabilities,
// concurrency, OS and architecture on the heartbeat, on v2 and on v1, and a
// sensor without a reporter sends none of the members.

import (
	"context"
	"encoding/json"
	"reflect"
	"runtime"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
)

type reportedHeartbeat struct {
	Tools             *[]core.ToolInfo `json:"tools"`
	Capabilities      *[]string        `json:"capabilities"`
	MaxConcurrentJobs *int             `json:"max_concurrent_jobs"`
	OS                string           `json:"os"`
	Arch              string           `json:"arch"`
}

func lastHeartbeat(t *testing.T, f *FakePlatform) reportedHeartbeat {
	t.Helper()
	beats := f.Heartbeats()
	if len(beats) == 0 {
		t.Fatal("no heartbeat received")
	}
	var hb reportedHeartbeat
	if err := json.Unmarshal(beats[len(beats)-1], &hb); err != nil {
		t.Fatal(err)
	}
	return hb
}

var testReport = core.CapabilityReport{
	Tools: []core.ToolInfo{
		{Name: "semgrep", Version: "1.90.0", Installed: true},
		{Name: "nuclei", Installed: false},
	},
	Capabilities:      []string{"semgrep", "sast", "validate"},
	MaxConcurrentJobs: 3,
}

func heartbeatWithReporter(t *testing.T, f *FakePlatform, protocol string, r core.CapabilityReporter) {
	t.Helper()
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, Protocol: protocol, MaxRetries: 1})
	t.Cleanup(func() { _ = c.Close() })
	s := core.NewBaseSensor(&core.BaseSensorConfig{Name: "conformance", Version: "0.5.0"}, c)
	if r != nil {
		s.SetCapabilityReporter(r)
	}
	if _, err := s.FirstHeartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
}

func TestCapabilities_ReportedOnV2AndV1(t *testing.T) {
	for _, tc := range []struct {
		name     string
		v2       bool
		protocol string
	}{
		{"v2 control plane", true, client.ProtocolAuto},
		{"v1 platform", false, client.ProtocolAuto},
		{"v1 forced", true, client.ProtocolV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFakePlatform(tc.v2)
			f.SetControl(tc.v2)
			t.Cleanup(f.Close)
			heartbeatWithReporter(t, f, tc.protocol, core.StaticCapabilities(testReport))

			hb := lastHeartbeat(t, f)
			if hb.Tools == nil || !reflect.DeepEqual(*hb.Tools, testReport.Tools) {
				t.Errorf("tools = %+v, want %+v", hb.Tools, testReport.Tools)
			}
			if hb.Capabilities == nil || !reflect.DeepEqual(*hb.Capabilities, testReport.Capabilities) {
				t.Errorf("capabilities = %v", hb.Capabilities)
			}
			if hb.MaxConcurrentJobs == nil || *hb.MaxConcurrentJobs != 3 {
				t.Errorf("max_concurrent_jobs = %v", hb.MaxConcurrentJobs)
			}
			if hb.OS != runtime.GOOS || hb.Arch != runtime.GOARCH {
				t.Errorf("os/arch = %q/%q", hb.OS, hb.Arch)
			}
		})
	}
}

// Without a reporter the members are absent, so the platform keeps its
// administrator's settings; os/arch are always sent.
func TestCapabilities_NoReporterSendsNothing(t *testing.T) {
	f := newControlFake(t)
	heartbeatWithReporter(t, f, client.ProtocolAuto, nil)
	hb := lastHeartbeat(t, f)
	if hb.Tools != nil || hb.Capabilities != nil || hb.MaxConcurrentJobs != nil {
		t.Fatalf("reported without a reporter: %+v", hb)
	}
	if hb.OS == "" || hb.Arch == "" {
		t.Fatalf("os/arch missing: %+v", hb)
	}
}

// An empty, non-nil inventory is a report ("nothing installed"), distinct
// from no report.
func TestCapabilities_EmptyInventoryIsSent(t *testing.T) {
	f := newControlFake(t)
	heartbeatWithReporter(t, f, client.ProtocolAuto, core.StaticCapabilities(core.CapabilityReport{
		Tools: []core.ToolInfo{}, Capabilities: []string{},
	}))
	hb := lastHeartbeat(t, f)
	if hb.Tools == nil || len(*hb.Tools) != 0 || hb.Capabilities == nil || len(*hb.Capabilities) != 0 {
		t.Fatalf("empty inventory not sent as []: %+v", hb)
	}
}

// The reporter is asked on every heartbeat, so a tool installed while the
// sensor runs shows up on the next one.
func TestCapabilities_ReporterAskedEveryHeartbeat(t *testing.T) {
	f := newControlFake(t)
	c := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey, MaxRetries: 1})
	t.Cleanup(func() { _ = c.Close() })
	s := core.NewBaseSensor(&core.BaseSensorConfig{Name: "conformance"}, c)
	n := 0
	s.SetCapabilityReporter(core.CapabilityReporterFunc(func(context.Context) core.CapabilityReport {
		n++
		return core.CapabilityReport{MaxConcurrentJobs: n}
	}))
	ctx := context.Background()
	for range 2 {
		if _, err := s.FirstHeartbeat(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if hb := lastHeartbeat(t, f); hb.MaxConcurrentJobs == nil || *hb.MaxConcurrentJobs != 2 {
		t.Fatalf("second heartbeat max_concurrent_jobs = %v, want 2", hb.MaxConcurrentJobs)
	}
}
