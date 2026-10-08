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
//   - its own process group, killed whole on timeout or cancel.
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
	NetworkNone        NetworkClass = "none"
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
	// Missing lists the controls this host could not enforce, and why.
	Missing []string `json:"missing,omitempty"`
}

// Complete reports whether every control is enforced.
func (s Status) Complete() bool {
	return s.Sandboxed && s.Landlock > 0 && s.Seccomp && s.NoNewPrivs && s.Rlimits && len(s.Missing) == 0
}

var current atomic.Pointer[backendHolder]

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
