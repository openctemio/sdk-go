package sensorkit

import (
	"fmt"
	"os"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/outbox"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
)

// EnvSandbox sets the tool sandbox mode: off, auto (default) or required.
const EnvSandbox = "SENSOR_SANDBOX"

// EnvSandboxNetwork sets network confinement (api RFC-060): auto (default:
// each task in its own network namespace whose only way out is its
// forwarder, where user namespaces are available), required (refuse to
// start without it; for shared sensors) or off.
const EnvSandboxNetwork = "SENSOR_SANDBOX_NETWORK"

// sandboxModes reads the tool sandbox mode (sandbox, else SENSOR_SANDBOX)
// and SENSOR_SANDBOX_NETWORK.
func sandboxModes(sandbox string) (mode, netMode executor.Mode, err error) {
	mode, ok := executor.ParseMode(strings.TrimSpace(envOr(sandbox, EnvSandbox)))
	if !ok {
		return "", "", usageError(fmt.Errorf("%s must be off, auto or required", EnvSandbox))
	}
	netMode, ok = executor.ParseMode(strings.TrimSpace(os.Getenv(EnvSandboxNetwork)))
	if !ok {
		return "", "", usageError(fmt.Errorf("%s must be off, auto or required", EnvSandboxNetwork))
	}
	return mode, netMode, nil
}

// ValidateSandboxNetwork fails when SENSOR_SANDBOX_NETWORK=required and this
// host cannot confine a tool's network (no unprivileged user namespaces, a
// container profile that blocks them, or the tool sandbox off). sandbox is
// the tool sandbox mode, "" for SENSOR_SANDBOX. It only probes: nothing is
// installed. New calls it before pairing, and a pair command should too: a
// host that can never run confined is refused before the platform admits
// it and gives it an identity.
func ValidateSandboxNetwork(sandbox string) error {
	mode, netMode, err := sandboxModes(sandbox)
	if err != nil || netMode != executor.ModeRequired {
		return err
	}
	if _, err := executor.NewProcessBackend(executor.Config{Mode: mode, ConfineNetwork: true, RequireNetwork: true}); err != nil {
		return usageError(fmt.Errorf("%s=required: %w", EnvSandboxNetwork, err))
	}
	return nil
}

// setupSandbox installs the executor backend every tool run uses, with the
// kit's protected paths, and logs what it enforces.
func (k *Kit) setupSandbox() error {
	mode, netMode, err := sandboxModes(k.opts.Sandbox)
	if err != nil {
		return err
	}
	b, err := executor.NewProcessBackend(executor.Config{Mode: mode, ReadDeny: k.protectedPaths(),
		ConfineNetwork: netMode != executor.ModeOff, RequireNetwork: netMode == executor.ModeRequired})
	if err != nil {
		return usageError(err)
	}
	executor.SetCurrent(b)
	st := b.Status()
	switch {
	case mode == executor.ModeOff:
		_, _ = fmt.Fprintf(k.out, "  Tool sandbox: off (%s=off)\n", EnvSandbox)
	case st.Sandboxed:
		_, _ = fmt.Fprintf(k.out, "  Tool sandbox: %s; private task directory, rlimits, no_new_privs, landlock v%d, seccomp %t\n", st.Mode, st.Landlock, st.Seccomp)
	}
	for _, m := range st.Missing {
		_, _ = fmt.Fprintf(k.errw, "Warning: tool sandbox: %s\n", m)
	}
	k.sandboxNetworkCheck(mode, netMode, st)
	switch {
	case st.NetworkEnforced:
		_, _ = fmt.Fprintf(k.out, "  Tool network: confined (each task reaches only its targets, through its forwarder)\n")
	case st.NetworkMissing != "":
		_, _ = fmt.Fprintf(k.errw, "Warning: tool network not confined (%s=%s): %s\n", EnvSandboxNetwork, netMode, st.NetworkMissing)
	}
	return nil
}

// protectedPaths are the files no tool may read: the renewable API key, the
// paired identity (signing key, protocol v3 certificate), the outbox and its
// key, the local policy, and the sensor's own list.
func (k *Kit) protectedPaths() []string {
	var out []string
	add := func(p string) {
		if p = strings.TrimSpace(p); p != "" {
			if _, err := os.Lstat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	add(k.s.key.file)
	// The paired identity: the signing key, and the protocol v3 client
	// certificate and pinned CA kept next to it.
	if k.s.stateDir != "" {
		add(identity.NewStore(k.s.stateDir).Dir())
	}
	add(k.s.outbox.Config.Dir)
	add(k.s.outbox.Config.KeyFile)
	if d := k.s.outbox.Config.Dir; d != "" {
		add(outbox.DefaultKeyFile(d))
	}
	if lp := k.s.local; lp != nil {
		add(lp.Path())
	}
	add(k.opts.LocalPolicyPath)
	for _, p := range k.opts.ProtectedPaths {
		add(p)
	}
	return out
}

// sandboxNetworkCheck reports whether tool runs are network-confined, and
// when they are not, the detected cause, so the platform's setup checklist
// shows the exact fix: the seccomp profile when the runtime refuses user
// namespaces, the default AppArmor profile when the host restricts them.
func (k *Kit) sandboxNetworkCheck(mode, netMode executor.Mode, st executor.Status) {
	c := core.ConfigCheck{ID: CheckSandboxNetwork, Status: core.CheckWarn, Keys: []string{EnvSandboxNetwork}}
	missing := strings.ToLower(st.NetworkMissing)
	switch {
	case st.NetworkEnforced:
		c.Status, c.Code, c.Keys = core.CheckPass, "confined", nil
	case mode == executor.ModeOff:
		c.Code, c.Keys = "sandbox_off", []string{EnvSandbox}
	case netMode == executor.ModeOff:
		c.Code = "off"
	case strings.Contains(missing, "operation not permitted"):
		c.Code = "userns_blocked"
	case strings.Contains(missing, "permission denied"):
		c.Code = "userns_restricted"
	default:
		c.Code = "unavailable"
	}
	if !st.NetworkEnforced {
		c.Summary = "tool runs are not network-confined"
		c.Excerpt = truncateBytes(st.NetworkMissing, maxUnavailableExcerptSize)
	}
	k.ReportCheck(c)
}
