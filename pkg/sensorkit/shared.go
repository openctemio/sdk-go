package sensorkit

import (
	"fmt"
	"os"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// Shared mode: the per-job isolation profile of a sensor that runs jobs of
// many tenants (api RFC-100 §8 in openctemio/openctem). The mechanisms are
// the SDK's; a sensor only switches them on (Options.Shared or
// SENSOR_SHARED_MODE=1):
//
//   - the tool sandbox and network confinement are required: the sensor
//     refuses to start where the host cannot give them (never degraded);
//   - every task runs in a fresh private directory under the task root,
//     removed after the task; its write paths and state directories
//     (HOME, TMPDIR, XDG_*) must lie there, so no writable cache is shared
//     between jobs (executor Config.Shared);
//   - a task reaches only the addresses checked for it, through its
//     forwarder; a private address only when the operator allows private
//     targets and the address lies in the job's zone ranges
//     (Command.ZoneRanges); loopback, link-local, metadata and CGNAT
//     addresses never;
//   - the sensor advertises CapabilitySharedIsolation, from its runtime
//     state, so the platform can send shared jobs only to a sensor that
//     enforces all of this.

// EnvSharedMode switches shared mode on ("1") or off ("0" or unset).
const EnvSharedMode = "SENSOR_SHARED_MODE"

// CapabilitySharedIsolation is what a sensor in shared mode advertises:
// every job runs under the shared isolation profile.
const CapabilitySharedIsolation = "shared.isolation@1"

// SharedModeFromEnv reads EnvSharedMode. Anything but "", "0" or "1" is an
// error, so a typo never silently runs a shared sensor without isolation.
func SharedModeFromEnv() (bool, error) {
	switch v := strings.TrimSpace(os.Getenv(EnvSharedMode)); v {
	case "", "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, usageError(fmt.Errorf("%s=%q is not recognized: set it to 1 for a sensor that runs jobs of many tenants, or 0 (or unset)", EnvSharedMode, v))
	}
}

// resolveShared decides whether the kit runs in shared mode.
func resolveShared(opts Options) (bool, error) {
	env, err := SharedModeFromEnv()
	if err != nil {
		return false, err
	}
	return opts.Shared || env, nil
}

// sharedSandboxModes are the sandbox modes of shared mode: both required.
// A setting that asks for less is a configuration error, not a downgrade.
func sharedSandboxModes(sandbox string) (mode, netMode executor.Mode, err error) {
	for name, v := range map[string]string{EnvSandbox: envOr(sandbox, EnvSandbox), EnvSandboxNetwork: os.Getenv(EnvSandboxNetwork)} {
		if v = strings.TrimSpace(v); v != "" && v != string(executor.ModeRequired) {
			return "", "", usageError(fmt.Errorf("%s=%s: a shared sensor (%s=1) runs every tool sandboxed and network-confined; set %s=required or unset it", name, v, EnvSharedMode, name))
		}
	}
	return executor.ModeRequired, executor.ModeRequired, nil
}

// Shared reports whether the kit runs in shared mode. A sensor that builds
// its own tool host sets toolhost.Host.Shared from it.
func (k *Kit) Shared() bool { return k.s.shared }

// sharedScanTargetPolicy is the scan target policy of shared mode: the
// configured one (else the default) with the job's zone rule.
func sharedScanTargetPolicy(p *core.ScanTargetPolicy) *core.ScanTargetPolicy {
	if p == nil {
		p = core.DefaultScanTargetPolicy()
	}
	c := *p
	c.Shared, c.Disabled, c.AllowLoopback = true, false, false
	return &c
}
