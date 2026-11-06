package sensorkit

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
func sandboxModes(sandbox string, shared bool) (mode, netMode executor.Mode, err error) {
	if shared {
		return sharedSandboxModes(sandbox)
	}
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
//
// With SENSOR_SHARED_MODE=1 both the sandbox and its network confinement
// are required (see EnvSharedMode).
func ValidateSandboxNetwork(sandbox string) error {
	shared, err := SharedModeFromEnv()
	if err != nil {
		return err
	}
	return validateSandboxNetwork(sandbox, shared)
}

func validateSandboxNetwork(sandbox string, shared bool) error {
	mode, netMode, err := sandboxModes(sandbox, shared)
	if err != nil || netMode != executor.ModeRequired {
		return err
	}
	if _, err := executor.NewProcessBackend(executor.Config{Mode: mode, ConfineNetwork: true, RequireNetwork: true, Shared: shared}); err != nil {
		if shared {
			return usageError(fmt.Errorf("%s=1: %w", EnvSharedMode, err))
		}
		return usageError(fmt.Errorf("%s=required: %w", EnvSandboxNetwork, err))
	}
	return nil
}

// setupSandbox installs the executor backend every tool run uses, with the
// kit's protected paths, and logs what it enforces.
func (k *Kit) setupSandbox() error {
	mode, netMode, err := sandboxModes(k.opts.Sandbox, k.s.shared)
	if err != nil {
		return err
	}
	b, err := executor.NewProcessBackend(executor.Config{Mode: mode, ReadDeny: k.protectedPaths(),
		ConfineNetwork: netMode != executor.ModeOff, RequireNetwork: netMode == executor.ModeRequired, Shared: k.s.shared})
	if err != nil {
		return usageError(err)
	}
	if k.s.shared {
		_, _ = fmt.Fprintf(k.out, "  Shared mode: every job sandboxed and network-confined in its own task directories; private targets only inside the job's zone\n")
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
	switch st.Unconfined() {
	case executor.UnconfinedRefused:
		_, _ = fmt.Fprintf(k.errw, "Warning: the tool sandbox is not available on this host: tools that contact their targets (tier T1 and above) are refused; passive lookups still run. Run on Linux with the sandbox, or set %s=off to acknowledge running every tool unconfined\n", EnvSandbox)
	case executor.UnconfinedAcknowledged:
		_, _ = fmt.Fprintf(k.errw, "Warning: tools run unconfined (%s=off), the ones that contact their targets included\n", EnvSandbox)
	}
	k.setupEnvelopes()
	k.sandboxNetworkCheck(mode, netMode, st)
	k.sandboxUnconfinedCheck(st)
	switch {
	case st.NetworkEnforced:
		_, _ = fmt.Fprintf(k.out, "  Tool network: confined (each task reaches only its targets, through its forwarder)\n")
	case st.NetworkMissing != "":
		_, _ = fmt.Fprintf(k.errw, "Warning: tool network not confined (%s=%s): %s\n", EnvSandboxNetwork, netMode, st.NetworkMissing)
	}
	return nil
}

// setupEnvelopes turns on per-task cgroup envelopes where the sensor's
// cgroup is delegated (research/318 §6.2) and logs which envelope tasks get.
func (k *Kit) setupEnvelopes() {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(EnvToolCgroups)), "off") {
		_, _ = fmt.Fprintf(k.out, "  Tool envelope: rlimits (%s=off)\n", EnvToolCgroups)
		return
	}
	switch mode, why := executor.EnableEnvelopes(); mode {
	case executor.EnvelopeCgroup:
		_, _ = fmt.Fprintf(k.out, "  Tool envelope: a cgroup per task (CPU, memory and process limits from each tool's resources)\n")
	default:
		_, _ = fmt.Fprintf(k.out, "  Tool envelope: rlimits and priorities (no per-task cgroup: %s)\n", why)
	}
}

// protectedPaths are the files no tool may read: the renewable API key, the
// paired identity (signing key, protocol v3 certificate), the outbox and its
// key, the local store and its master key, the local policy, and the
// sensor's own list.
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
	// The local store and its master key: the keys of every organization's
	// records.
	if k.ls != nil {
		add(k.ls.dir)
		add(k.ls.keyFile)
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
func (k *Kit) sandboxUnconfinedCheck(st executor.Status) {
	k.ReportCheck(unconfinedCheck(st))
}

// unconfinedCheck is the config report check of how tools run without the
// sandbox: pass when they run sandboxed; a failure when the tools that
// contact their targets are refused (the sandbox is not available and the
// operator did not acknowledge running them unconfined); a warning when the
// operator acknowledged it (SENSOR_SANDBOX=off).
func unconfinedCheck(st executor.Status) core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckSandboxUnconfined, Keys: []string{EnvSandbox}}
	switch st.Unconfined() {
	case "":
		c.Status, c.Code, c.Keys = core.CheckPass, "sandboxed", nil
	case executor.UnconfinedRefused:
		c.Status, c.Code = core.CheckFail, "active_refused"
		c.Summary = "the tool sandbox is not available on this host: tools that contact their targets are refused, passive lookups still run"
		c.Excerpt = truncateBytes(strings.Join(st.Missing, "; "), maxUnavailableExcerptSize)
	default:
		c.Status, c.Code = core.CheckWarn, "acknowledged"
		c.Summary = "tools run unconfined (" + EnvSandbox + "=off), the ones that contact their targets included"
	}
	return c
}

func (k *Kit) sandboxNetworkCheck(mode, netMode executor.Mode, st executor.Status) {
	c := core.ConfigCheck{ID: CheckSandboxNetwork, Status: core.CheckWarn, Keys: []string{EnvSandboxNetwork}}
	var host usernsHost
	switch {
	case st.NetworkEnforced:
		c.Status, c.Code, c.Keys = core.CheckPass, "confined", nil
	case mode == executor.ModeOff:
		c.Code, c.Keys = "sandbox_off", []string{EnvSandbox}
	case netMode == executor.ModeOff:
		c.Code = "off"
	default:
		host = readUsernsHost(procRoot)
		c.Code = classifyUserns(host, strings.ToLower(st.NetworkMissing))
	}
	if !st.NetworkEnforced {
		c.Summary = "tool runs are not network-confined"
		if s := usernsSummary(c.Code); s != "" {
			c.Summary += ": " + s
		}
		c.Excerpt = st.NetworkMissing
		if e := host.excerpt(); e != "" {
			c.Excerpt = e + "; " + st.NetworkMissing
		}
		c.Excerpt = truncateBytes(c.Excerpt, maxUnavailableExcerptSize)
	}
	k.ReportCheck(c)
}

// procRoot is where the host knobs are read from; tests point it at a fake
// tree.
var procRoot = "/proc"

// usernsHost holds the host knobs that decide whether a process may create
// a user namespace, as visible from inside the container. A knob that could
// not be read is nil or empty: unknown, never a guess.
type usernsHost struct {
	clone    *int   // kernel.unprivileged_userns_clone (Debian, Ubuntu): 0 = off
	maxNS    *int   // user.max_user_namespaces: 0 = off
	restrict *int   // kernel.apparmor_restrict_unprivileged_userns: 1 = on
	label    string // the task's AppArmor label
	seccomp  *int   // Seccomp: of /proc/self/status: 0 off, 1 strict, 2 filter
}

func readUsernsHost(root string) usernsHost {
	num := func(rel string) *int {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			return nil
		}
		return &n
	}
	h := usernsHost{
		clone:    num("sys/kernel/unprivileged_userns_clone"),
		maxNS:    num("sys/user/max_user_namespaces"),
		restrict: num("sys/kernel/apparmor_restrict_unprivileged_userns"),
	}
	for _, rel := range []string{"self/attr/apparmor/current", "self/attr/current"} {
		if b, err := os.ReadFile(filepath.Join(root, rel)); err == nil {
			if l := strings.TrimSpace(strings.TrimRight(string(b), "\x00")); l != "" {
				h.label = l
				break
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "self/status")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "Seccomp:"); ok {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					h.seccomp = &n
				}
			}
		}
	}
	return h
}

func (h usernsHost) unconfined() bool {
	return strings.HasPrefix(strings.ToLower(h.label), "unconfined")
}

// classifyUserns names the cause of an unavailable network confinement. The
// host knobs come first: a sysctl that disables user namespaces is the cause
// whatever the runtime's profile says, and the error text alone cannot tell
// it from a seccomp refusal (both are EPERM).
func classifyUserns(h usernsHost, missing string) string {
	switch {
	case (h.clone != nil && *h.clone == 0) || (h.maxNS != nil && *h.maxNS == 0):
		return "userns_disabled_host"
	case h.restrict != nil && *h.restrict == 1 && h.unconfined():
		return "userns_restricted"
	case strings.Contains(missing, "operation not permitted"):
		return "userns_blocked"
	case strings.Contains(missing, "permission denied"):
		return "userns_restricted"
	}
	return "unavailable"
}

func usernsSummary(code string) string {
	switch code {
	case "userns_disabled_host":
		return "the host disables unprivileged user namespaces (kernel.unprivileged_userns_clone or user.max_user_namespaces is 0): the host admin sets kernel.unprivileged_userns_clone=1 (or a positive user.max_user_namespaces) and keeps kernel.apparmor_restrict_unprivileged_userns=1"
	case "userns_restricted":
		return "the host's AppArmor restricts unprivileged user namespaces for this process: keep the restriction on and run with the default container profile or an AppArmor profile that grants userns"
	case "userns_blocked":
		return "the host allows user namespaces but the container runtime's seccomp profile refuses them: run with the sensor's seccomp profile"
	}
	return ""
}

// excerpt lists the knob names and values that were read (evidence for the
// platform), and says nothing about the ones that were not.
func (h usernsHost) excerpt() string {
	var parts []string
	add := func(name string, v *int) {
		if v != nil {
			parts = append(parts, name+"="+strconv.Itoa(*v))
		}
	}
	add("kernel.unprivileged_userns_clone", h.clone)
	add("user.max_user_namespaces", h.maxNS)
	add("kernel.apparmor_restrict_unprivileged_userns", h.restrict)
	if h.label != "" {
		parts = append(parts, "apparmor_label="+h.label)
	}
	add("seccomp_mode", h.seccomp)
	return strings.Join(parts, " ")
}
