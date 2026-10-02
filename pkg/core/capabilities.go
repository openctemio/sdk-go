package core

import (
	"context"
	"runtime"
)

// Sensor-reported capabilities (api RFC-029 §4.3.1): a sensor tells the platform
// on every heartbeat which tools it actually has, what it can run and how
// many jobs it runs at once. The platform dispatches by what the sensor
// reports; its administrator can only narrow that (limit the tools, the
// capabilities or the concurrency), never widen it. A platform that does
// not know the fields ignores them.

// ToolInfo is one tool on a heartbeat's tool inventory.
type ToolInfo struct {
	// Name is the tool's catalog name ("semgrep", "nuclei", "trivy").
	Name string `json:"name"`
	// Kind is what the tool does (scanner or collector); empty when the
	// sensor does not say.
	Kind ToolKind `json:"kind,omitempty"`
	// Version is the installed version, when known.
	Version string `json:"version,omitempty"`
	// Installed is false for a tool the sensor is configured to run but
	// cannot find (or cannot run). The platform does not dispatch jobs for
	// it and shows it as not installed.
	Installed bool `json:"installed"`
	// Capabilities are what this tool serves besides its own name ("sast",
	// "dast", "validate:nuclei"): the per-tool mapping behind the sensor's
	// flat capability list, so the platform can show (and route by) which
	// tool provides what. nil reports nothing.
	Capabilities []string `json:"capabilities,omitzero"`
	// Content is the data the tool scans with (vulnerability database,
	// templates, rules) and how fresh it is; see ContentInfo. nil reports
	// nothing (the platform shows no content for the tool).
	Content []ContentInfo `json:"content,omitzero"`
}

// CapabilityReport is what a sensor reports it can do.
type CapabilityReport struct {
	// Tools is the tool inventory. nil reports nothing (the platform keeps
	// using its administrator's list); an empty, non-nil slice reports that
	// no tool is available.
	Tools []ToolInfo
	// Capabilities are the capability names the sensor serves ("validate",
	// a tool name, "sast"). nil reports nothing, as for Tools.
	Capabilities []string
	// MaxConcurrentJobs is the operator's ceiling on concurrent jobs
	// (SENSOR_MAX_JOBS, SetMaxConcurrentJobs); 0 reports none. It is not
	// what the sensor can run now: a sensor with a resource manager reports
	// that as its dynamic slots (SensorStatus.Capacity.SlotsTotal), always
	// at most this ceiling.
	MaxConcurrentJobs int
}

// CapabilityReporter supplies the capability report a BaseSensor puts on
// every heartbeat. It is called once per heartbeat, so an implementation
// that probes tools should cache the result.
type CapabilityReporter interface {
	CapabilityReport(ctx context.Context) CapabilityReport
}

// CapabilityReporterFunc adapts a function to CapabilityReporter.
type CapabilityReporterFunc func(ctx context.Context) CapabilityReport

// CapabilityReport calls f.
func (f CapabilityReporterFunc) CapabilityReport(ctx context.Context) CapabilityReport {
	return f(ctx)
}

// StaticCapabilities is a reporter that always reports r.
func StaticCapabilities(r CapabilityReport) CapabilityReporter {
	return CapabilityReporterFunc(func(context.Context) CapabilityReport { return r })
}

// Apply copies the report onto a heartbeat status (copies of the slices,
// so the reporter may reuse its own).
func (r CapabilityReport) Apply(status *SensorStatus) {
	if status == nil {
		return
	}
	if r.Tools != nil {
		status.Tools = make([]ToolInfo, 0, len(r.Tools))
		for _, t := range r.Tools {
			if t.Content != nil {
				t.Content = append(make([]ContentInfo, 0, len(t.Content)), t.Content...)
			}
			if t.Capabilities != nil {
				t.Capabilities = append(make([]string, 0, len(t.Capabilities)), t.Capabilities...)
			}
			status.Tools = append(status.Tools, t)
		}
	}
	if r.Capabilities != nil {
		status.Capabilities = append(make([]string, 0, len(r.Capabilities)), r.Capabilities...)
	}
	if r.MaxConcurrentJobs > 0 {
		status.MaxConcurrentJobs = r.MaxConcurrentJobs
	}
}

// HostOS and HostArch are the operating system and architecture the sensor
// reports (runtime.GOOS, runtime.GOARCH).
func HostOS() string   { return runtime.GOOS }
func HostArch() string { return runtime.GOARCH }
