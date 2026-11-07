// Package executor runs one task (one tool invocation) for a sensor, in a
// sandbox.
//
// An Executor backend takes a generic task specification (argv, environment,
// working directory, resource limits, network class, writable paths) and
// runs it; it knows nothing about the tool. The process backend (the only
// one today) runs the task as a child process of the sensor, through a
// small launcher (the sensor's own binary, re-executed) that confines it
// before the tool starts:
//
//   - a private, throwaway working directory (also its HOME and TMPDIR),
//     under a task root hidden from every other task;
//   - resource limits: memory (RLIMIT_DATA), processes (RLIMIT_NPROC),
//     file size, open files, CPU time, no core dumps;
//   - no_new_privs: no setuid/file-capability escalation;
//   - Landlock (Linux 5.13+): it writes only under its working directory and
//     the paths the caller names, and cannot read the paths the sensor
//     protects (its key and credentials, outbox, configuration, local
//     policy);
//   - a seccomp filter refusing the syscalls a scanner has no business
//     making (ptrace, mount, namespaces, kernel modules, keyrings, bpf, …);
//   - its own process group, killed whole on timeout or cancel; a confined
//     task (Config.ConfineNetwork) also gets its own PID namespace, so it
//     cannot signal the sensor or another task and nothing it starts
//     outlives it.
//
// The sensor also makes itself non-dumpable, so a task running under the
// same user cannot read the sensor's memory, environment or open files
// through /proc.
//
// A Docker socket is never used: a container backend, when one is added,
// must be rootless or a Kubernetes Pod per task, never the host's docker.
//
// Mode "auto" (the default for a sensor) enforces what the kernel and the
// container allow and reports what it could not; "required" refuses to run
// tasks without every control; "off" runs tasks as plain child processes.
//
// Stability: Beta (docs/STABILITY.md).
package executor

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

// RelayProxyAddr is where a confined task finds its proxy (HTTP CONNECT,
// absolute-form HTTP or SOCKS5, all relayed to its forwarder), and
// RelayDNSAddr its resolver.
const (
	RelayProxyAddr = "127.0.0.1:1080"
	RelayDNSAddr   = "127.0.0.1:53"
)

// EnvEgressProxy is set, for a confined task with a forwarder, to the
// relay's proxy URL (HTTP CONNECT and SOCKS5 on one port): a wrapper passes
// it to a tool that takes a proxy flag rather than the proxy variables.
const EnvEgressProxy = "OPENCTEM_EGRESS_PROXY"

// Mode says how strictly tasks are sandboxed.
type Mode string

// Modes.
const (
	// ModeOff runs tasks as plain child processes (process group and the
	// caller's environment allowlist only).
	ModeOff Mode = "off"
	// ModeAuto enforces every control the host supports and reports the
	// rest (Status.Missing).
	ModeAuto Mode = "auto"
	// ModeRequired refuses to run a task unless every control is enforced.
	ModeRequired Mode = "required"
)

// ParseMode reads a mode name ("" is ModeAuto).
func ParseMode(s string) (Mode, bool) {
	switch Mode(s) {
	case "":
		return ModeAuto, true
	case ModeOff, ModeAuto, ModeRequired:
		return Mode(s), true
	}
	return "", false
}

// NetworkClass is the network a task may reach. The process backend records
// it in the result; it does not enforce it (the sensor's target guard and
// egress settings do). Backends that can (a Pod per task with a
// NetworkPolicy) enforce it.
type NetworkClass string

// Network classes.
const (
	NetworkAny         NetworkClass = "any"
	NetworkTargetsOnly NetworkClass = "targets-only"
	NetworkEgressProxy NetworkClass = "egress-proxy"
	// NetworkResolver: DNS questions through the task's forwarder only, no
	// connection to any host.
	NetworkResolver NetworkClass = "resolver"
	NetworkNone     NetworkClass = "none"
)

// Limits bound one task. Zero means the backend's default (DefaultLimits).
type Limits struct {
	// MemoryBytes bounds the data segment (heap and private mappings).
	MemoryBytes uint64 `json:"memory_bytes,omitempty"`
	// Processes is how many more processes and threads the task may create.
	Processes uint64 `json:"processes,omitempty"`
	// FileSizeBytes bounds any file the task writes.
	FileSizeBytes uint64 `json:"file_size_bytes,omitempty"`
	// OpenFiles bounds the task's open file descriptors.
	OpenFiles uint64 `json:"open_files,omitempty"`
	// CPUSeconds bounds CPU time per process (0: none; the timeout bounds
	// wall time).
	CPUSeconds uint64 `json:"cpu_seconds,omitempty"`
}

// DefaultLimits are generous enough for every bundled scanner and stop a
// runaway or hostile one.
func DefaultLimits() Limits {
	return Limits{
		MemoryBytes:   8 << 30,
		Processes:     1024,
		FileSizeBytes: 8 << 30,
		OpenFiles:     8192,
	}
}

// withDefaults fills zero fields from DefaultLimits.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MemoryBytes == 0 {
		l.MemoryBytes = d.MemoryBytes
	}
	if l.Processes == 0 {
		l.Processes = d.Processes
	}
	if l.FileSizeBytes == 0 {
		l.FileSizeBytes = d.FileSizeBytes
	}
	if l.OpenFiles == 0 {
		l.OpenFiles = d.OpenFiles
	}
	return l
}

// TaskSpec is one task. It names no tool: whatever a tool needs beyond the
// defaults (a path it must write, a variable it reads) the caller says here.
type TaskSpec struct {
	// ID names the task in logs and the working directory (optional).
	ID string
	// Argv is the program and its arguments. Argv[0] is resolved on PATH
	// when it has no slash.
	Argv []string
	// Env is the task's environment ("KEY=value"), already filtered by the
	// caller (the SDK passes an allowlist; never the sensor's credentials).
	Env []string
	// SetEnv are variables the caller sets explicitly; they win over the
	// sandbox's own HOME, TMPDIR and XDG_* defaults.
	SetEnv map[string]string
	// Dir is the working directory; "" is the task's private directory.
	Dir string
	// WritePaths are paths the task may write besides its private
	// directory (an output file's directory, a tool cache it owns).
	WritePaths []string
	// ReadPaths are paths the task may read even beneath a private root
	// (Config.Private, the task root): the content packs of this task
	// (templates, rules, wordlists), which no other task may read. Never
	// beneath a protected path.
	ReadPaths []string
	// Limits bound the task (zero fields: DefaultLimits).
	Limits Limits
	// Network is the network class (see NetworkClass).
	Network NetworkClass
	// Stdin is the task's standard input (nil: none). A tool that speaks
	// the adapter protocol reads its messages from it. Pass an *os.File
	// (the read end of an os.Pipe) so the process gets the descriptor
	// itself: any other reader is copied by a goroutine that Wait waits
	// for.
	Stdin io.Reader
	// Stdout and Stderr receive the task's output.
	Stdout, Stderr io.Writer
	// Hooks let the caller adjust the process (process backend only).
	Hooks ProcessHooks
	// EgressProxy and EgressDNS are unix socket paths of the task's
	// forwarder (pkg/sensorkit/egress): its proxy listener and its DNS
	// stream listener. On a backend that confines the network (Status.
	// NetworkEnforced) they are the task's only way out: the task sees a
	// proxy on 127.0.0.1:1080 (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) and a
	// resolver on 127.0.0.1:53 that lead to them, and nothing else. Empty:
	// a confined task has no network at all. Ignored when the network is
	// not confined.
	EgressProxy string
	EgressDNS   string
	// Envelope bounds the task's CPU, memory and processes (nil: the
	// default limits only). See Envelope.
	Envelope *Envelope
	// Browser is the sandbox of a tool that runs a web browser with the
	// browser's own sandbox on (tool.SandboxBrowser). The task must run
	// confined (Prepare refuses it otherwise). The tool runs as a non-root
	// user of its own user namespace beneath the confined one (it holds no
	// capability over the task's network namespace), may create user, PID
	// and network namespaces (the browser's renderer sandbox) and no other,
	// and may write /proc (the browser writes its children's id maps).
	Browser bool
	// Passive is the caller's statement that the task is a passive (tier
	// T0) tool that does not contact its targets. A backend whose required
	// controls are missing (Status.RequiredUnmet) runs only passive tasks
	// and tasks without network; the tool host sets it from the tool's
	// tier, and a caller that does not know the tier leaves it false.
	Passive bool
}

// ProcessHooks are the caller's process-level adjustments, called by the
// process backend: Configure before start (process group, cancel), Started
// after start (priority), Finished after wait (reap the group, accounting).
type ProcessHooks struct {
	Configure func(*exec.Cmd)
	Started   func(*exec.Cmd)
	Finished  func(*exec.Cmd)
}

// Result is how a task ended.
type Result struct {
	// ExitCode is the exit status (-1: killed by a signal or not run).
	ExitCode int
	// State is the process state (process backend).
	State *os.ProcessState
	// Killed is why the executor stopped the task ("" when it exited).
	Killed string
	// Duration is the wall time.
	Duration time.Duration
	// Sandbox is the protection the task ran under (runtime-stamped
	// provenance).
	Sandbox Status
	// Network is the task's network class.
	Network NetworkClass
	// EnvelopeOOM is set when the kernel killed a process of the task for
	// reaching its envelope's memory limit (cgroup envelope only): the
	// tool needs more memory, which a retry on the same host cannot give.
	EnvelopeOOM bool
}

// Task is a prepared task: Start it, Wait for it, Kill it, then Cleanup
// (always; it removes the private directory).
type Task interface {
	// Workdir is the task's private directory.
	Workdir() string
	Start(ctx context.Context) error
	// Wait returns when the task ends. An error means it could not be
	// waited for; a non-zero exit is in the result.
	Wait() (*Result, error)
	// Kill stops the task and its process group; reason is recorded.
	Kill(reason string)
	Cleanup() error
}

// Backend runs tasks.
type Backend interface {
	// Name is the backend ("process").
	Name() string
	// Status is the protection tasks get.
	Status() Status
	// Prepare checks spec and sets up the task without starting it.
	Prepare(spec TaskSpec) (Task, error)
}

// Status is the protection a backend gives its tasks.
type Status struct {
	Backend string `json:"backend"`
	Mode    Mode   `json:"mode"`
	// Sandboxed is true when tasks run through the launcher.
	Sandboxed bool `json:"sandboxed"`
	// Landlock is the Landlock ABI used (0: not available).
	Landlock   int  `json:"landlock,omitempty"`
	Seccomp    bool `json:"seccomp"`
	NoNewPrivs bool `json:"no_new_privs"`
	Rlimits    bool `json:"rlimits"`
	// NetworkEnforced is true when the backend itself confines the task's
	// network: the process backend with Config.ConfineNetwork, where user
	// namespaces are available, runs each task in its own network
	// namespace whose only way out is its forwarder (TaskSpec.EgressProxy,
	// EgressDNS). Without it the sensor's target guard and egress settings
	// apply instead. Code from outside the project must not run on a
	// backend without it.
	NetworkEnforced bool `json:"network_enforced"`
	// NetworkMissing says why network confinement was asked for and is not
	// enforced (empty when it is, or was not asked for).
	NetworkMissing string `json:"network_missing,omitempty"`
	// Missing lists the controls this host could not enforce, and why.
	Missing []string `json:"missing,omitempty"`
	// Envelope is how a task's resource envelope is enforced:
	// EnvelopeCgroup or EnvelopeRlimit ("" before EnableEnvelopes ran or
	// for a backend without one). EnvelopeMissing says why cgroups are not
	// used.
	Envelope        string `json:"envelope,omitempty"`
	EnvelopeMissing string `json:"envelope_missing,omitempty"`
	// NoSandboxOnHost is true when the host's operating system has no
	// sandbox at all (it is Linux only: macOS, Windows).
	NoSandboxOnHost bool `json:"no_sandbox_on_host,omitempty"`
	// RequiredUnmet says why a control the operator required
	// (SENSOR_SANDBOX=required, SENSOR_SANDBOX_NETWORK=required) is not
	// available on this host when the backend was asked to refuse active
	// tasks instead of failing (Config.RefuseActiveWhenUnmet). Non-empty:
	// tasks that may contact their targets are refused (ErrActiveRefused).
	RequiredUnmet string `json:"required_unmet,omitempty"`
}

// Unconfined states (Status.Unconfined): how a backend that runs tools
// without the sandbox treats the tools that contact their targets.
const (
	// UnconfinedRefused: the sandbox was asked for (SENSOR_SANDBOX=auto) and
	// a control could not be enforced (the host has none, the launcher
	// failed, user namespaces or Landlock are blocked, or the network is not
	// confined), so tools of tier T1 and above are refused; passive (T0)
	// tools still run.
	UnconfinedRefused = "refused"
	// UnconfinedAcknowledged: the operator turned the sandbox off
	// (SENSOR_SANDBOX=off), which is the acknowledgement that tools run
	// unconfined, every tier included.
	UnconfinedAcknowledged = "acknowledged"
)

// Unconfined is how tools run without full confinement: "" when the sandbox
// protects the sensor's identity and the network is confined as asked;
// UnconfinedAcknowledged when the operator turned the sandbox off;
// UnconfinedRefused when the sandbox was asked for (auto) and a control that
// keeps tools from the sensor's key or from the network could not be
// enforced: the launcher failed or is not wired, user namespaces are
// blocked or Landlock is missing (FailedControls says which). Network
// confinement missing alone does not refuse: the key paths are still denied,
// the sensor reports the gap (NetworkMissing, the sandbox_network check) and
// SENSOR_SANDBOX_NETWORK=required makes it refuse active tools
// (RequiredUnmet). A required control that is missing (RequiredUnmet)
// always refuses.
func (s Status) Unconfined() string {
	switch {
	case s.RequiredUnmet != "":
		return UnconfinedRefused
	case s.Mode == ModeOff:
		return UnconfinedAcknowledged
	case s.Mode == "":
		// No sandbox was asked for (tests, one-shot runs).
		return ""
	case s.Sandboxed && s.Landlock > 0:
		return ""
	}
	return UnconfinedRefused
}

// FailedControls names the controls that are not enforced and make
// Unconfined refuse: "launcher" (the sandbox did not start), "os" (the host
// has no sandbox), "landlock" (the sensor's key paths are not denied) and
// "required" (a control the operator required is missing: RequiredUnmet).
// Empty when Unconfined is not UnconfinedRefused.
func (s Status) FailedControls() []string {
	if s.Unconfined() != UnconfinedRefused {
		return nil
	}
	var out []string
	if !s.Sandboxed {
		out = append(out, "launcher")
		if s.NoSandboxOnHost {
			out = append(out, "os")
		}
	} else if s.Landlock == 0 {
		out = append(out, "landlock")
	}
	if s.RequiredUnmet != "" {
		out = append(out, "required")
	}
	return out
}

// UnconfinedDetail is the reasons behind FailedControls, as the status
// recorded them.
func (s Status) UnconfinedDetail() string {
	var d []string
	if s.RequiredUnmet != "" {
		d = append(d, "required: "+s.RequiredUnmet)
	}
	d = append(d, s.Missing...)
	if s.NetworkMissing != "" {
		d = append(d, "network: "+s.NetworkMissing)
	}
	return strings.Join(d, "; ")
}

// RefusesActiveTools reports whether tools of tier T1 and above (tools that
// contact their targets) are refused: the sandbox is not available and the
// operator did not turn it off (Unconfined).
func (s Status) RefusesActiveTools() bool { return s.Unconfined() == UnconfinedRefused }

// Complete reports whether every control is enforced.
func (s Status) Complete() bool {
	return s.Sandboxed && s.Landlock > 0 && s.Seccomp && s.NoNewPrivs && s.Rlimits && len(s.Missing) == 0
}

var current atomic.Pointer[backendHolder]

// CapabilityNetConfined is the capability a sensor advertises when every
// tool it runs for a job runs in a sandbox whose network is confined to the
// task's forwarder (Status.NetworkEnforced, and no tool runs in the sensor's
// own process). The platform sends jobs that need confinement (a web scope,
// scope limits) only to a sensor that advertises it. A sensor advertises
// it only from its runtime's status, never from a setting.
const CapabilityNetConfined = "net.confined@1"

type backendHolder struct{ b Backend }

// Current is the backend tasks run on: the one Configure installed, else a
// process backend in ModeOff.
func Current() Backend {
	if h := current.Load(); h != nil {
		return h.b
	}
	return offBackend
}

var offBackend = &ProcessBackend{status: Status{Backend: "process", Mode: ModeOff}}

// SetCurrent installs b as the backend (tests, or a backend built
// elsewhere). nil restores the default.
func SetCurrent(b Backend) {
	if b == nil {
		current.Store(nil)
		return
	}
	current.Store(&backendHolder{b: b})
}
