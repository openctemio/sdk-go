package sensorkit

// Host pressure governor wiring (research/318): the kit's resource manager
// owns the governor; every tool host the sensor builds takes it through
// ToolGovernor, so tool launches wait while the host is overloaded, start
// handshakes grow with the stall, and the heartbeat reports the pressure,
// the held launches and the transient start failures.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/resource"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
)

// EnvToolCgroups turns the per-task cgroup envelopes off ("off"); by
// default the kit uses them where the sensor's cgroup is delegated
// (executor.EnableEnvelopes) and rlimits elsewhere.
const EnvToolCgroups = "SENSOR_TOOL_CGROUPS"

// ToolGovernor is the governor for a tool host the sensor builds itself
// (toolhost.Host.Governor). It may be taken before Run: until the kit runs,
// launches are admitted at once with the base handshake timeout.
func (k *Kit) ToolGovernor() toolhost.Governor { return kitGovernor{k} }

type kitGovernor struct{ k *Kit }

func (g kitGovernor) Admit(ctx context.Context, tool string) (func(), time.Duration, error) {
	if gov := g.k.gov.Load(); gov != nil {
		return gov.Admit(ctx, tool)
	}
	return func() {}, 0, nil
}

func (g kitGovernor) StartTimeoutFactor() float64 {
	if gov := g.k.gov.Load(); gov != nil {
		return gov.StartTimeoutFactor()
	}
	return resource.MinStartFactor
}

func (g kitGovernor) Pressure() resource.Pressure {
	if gov := g.k.gov.Load(); gov != nil {
		return gov.Pressure()
	}
	return resource.Pressure{Level: resource.PressureOK}
}

func (g kitGovernor) Transient(kind string) {
	if gov := g.k.gov.Load(); gov != nil {
		gov.Transient(kind)
	}
}

// logLaunchHeld writes the held launch to the command's log.
func (k *Kit) logLaunchHeld(ctx context.Context, tool string, p resource.Pressure) {
	why := ""
	if len(p.Reasons) > 0 {
		why = " (" + strings.Join(p.Reasons, ", ") + ")"
	}
	msg := fmt.Sprintf("Tool %s held: the sensor host is %s%s; it starts when the pressure drops", tool, p.Level, why)
	if p.NoisyNeighbor {
		msg += "; other programs on this host use most of its CPU"
	}
	k.CommandLogger(ctx).Warn(msg, "tool", tool, "pressure", string(p.Level))
}
