package sensorkit

import (
	"context"

	"github.com/openctemio/sdk-go/pkg/core"
)

// capabilityReporter is the heartbeat's report: the tool registry's, with
// each tool's scanner content, and an empty inventory reported as "no tool"
// (a sensor reports what it has, even nothing).
type capabilityReporter struct {
	tools   *core.ToolRegistry
	content Content // nil: no content
}

var _ core.CapabilityReporter = (*capabilityReporter)(nil)

// CapabilityReport implements core.CapabilityReporter.
func (r *capabilityReporter) CapabilityReport(ctx context.Context) core.CapabilityReport {
	rep := r.tools.CapabilityReport(ctx)
	if rep.Tools == nil {
		rep.Tools = []core.ToolInfo{}
	}
	if rep.Capabilities == nil {
		rep.Capabilities = []string{}
	}
	if r.content != nil {
		// Content changes between probes (refreshes): added on every
		// heartbeat.
		return r.content.Decorate(rep)
	}
	return rep
}
