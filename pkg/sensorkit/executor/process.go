package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// Config sets up a ProcessBackend.
type Config struct {
	// Mode is how strictly tasks are sandboxed ("" is ModeAuto).
	Mode Mode
	// ReadDeny are paths no task may read or write: the sensor's key and
	// credentials, its outbox, its configuration and local policy. A path
	// that does not exist yet is skipped.
	ReadDeny []string
	// Limits are the default limits of every task (zero fields:
	// DefaultLimits).
	Limits Limits
	// WorkRoot is where private task directories are made (default
	// <os.TempDir()>/openctem-tasks).
	WorkRoot string
	// Launcher is the binary re-executed as the launcher (default: this
	// program). It must call RunLauncherIfRequested first thing in main.
	Launcher string
	// ConfineNetwork runs every task in its own user, network and mount
	// namespaces (Linux; api RFC-060): only loopback exists, and the task's
	// way out is its forwarder (TaskSpec.EgressProxy, EgressDNS). It needs
	// unprivileged user namespaces (a container seccomp profile that
	// allows them; on a host with AppArmor's restriction, a profile for the
	// sensor). Where they are not available, tasks run unconfined and
	// Status.NetworkMissing says why, unless RequireNetwork is set.
	ConfineNetwork bool
	// RequireNetwork makes NewProcessBackend fail when ConfineNetwork
	// cannot be enforced (a shared sensor, where it is a requirement).
	RequireNetwork bool
}

// ProcessBackend runs each task as a child process, through the launcher
// when sandboxing is on.
type ProcessBackend struct {
	cfg      Config
	launcher string
	status   Status
	deny     []string
	// confine: tasks run in their own network namespace (the probe
	// proved it works here).
	confine bool
}

// NewProcessBackend checks what this host enforces by running the launcher
// once in probe mode, and returns the backend. With ModeRequired it fails
// unless every control is enforced; with ModeAuto it degrades and lists what
// is missing in Status. With RequireNetwork it fails unless tasks' network
// is confined.
func NewProcessBackend(cfg Config) (*ProcessBackend, error) {
	b, err := newProcessBackend(cfg)
	if err == nil && cfg.RequireNetwork && !b.confine {
		why := b.status.NetworkMissing
		if why == "" {
			why = strings.Join(b.status.Missing, "; ")
		}
		if why == "" {
			why = "sandbox mode " + string(b.cfg.Mode)
		}
		return nil, fmt.Errorf("executor: network confinement required but not available: %s", why)
	}
	return b, err
}

func newProcessBackend(cfg Config) (*ProcessBackend, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeAuto
	}
	if _, ok := ParseMode(string(cfg.Mode)); !ok {
		return nil, fmt.Errorf("executor: unknown sandbox mode %q (off, auto, required)", cfg.Mode)
	}
	cfg.Limits = cfg.Limits.withDefaults()
	if cfg.WorkRoot == "" {
		cfg.WorkRoot = filepath.Join(os.TempDir(), "openctem-tasks")
	}
	b := &ProcessBackend{cfg: cfg, status: Status{Backend: "process", Mode: cfg.Mode}}
	for _, p := range cfg.ReadDeny {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("executor: protected path %q: %w", p, err)
		}
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = r
		}
		if abs == "/" {
			return nil, errors.New("executor: / cannot be a protected path")
		}
		b.deny = append(b.deny, filepath.Clean(abs))
	}
	if cfg.Mode == ModeOff {
		return b, nil
	}
	if runtime.GOOS != "linux" {
		if cfg.Mode == ModeRequired {
			return nil, errors.New("executor: sandbox required but it is available on Linux only")
		}
		b.status.Missing = []string{"sandbox: available on Linux only"}
		return b, nil
	}
	launcher := cfg.Launcher
	if launcher == "" && !launcherWired.Load() {
		if cfg.Mode == ModeRequired {
			return nil, errors.New("executor: sandbox required but this program does not call executor.RunLauncherIfRequested first in main")
		}
		b.status.Missing = []string{"launcher: this program does not call executor.RunLauncherIfRequested"}
		return b, nil
	}
	if launcher == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("executor: find the launcher: %w", err)
		}
		launcher = exe
	}
	b.launcher = launcher
	makeUndumpable()
	st, err := probe(launcher, b.deny, cfg.Limits, cfg.ConfineNetwork)
	if cfg.ConfineNetwork {
		if err == nil {
			b.confine = true
		} else {
			// Without network confinement the rest of the sandbox still
			// applies: probe again and say why the network is not.
			netErr := err
			if cfg.RequireNetwork {
				return nil, fmt.Errorf("executor: network confinement required but not available: %w", netErr)
			}
			if st, err = probe(launcher, b.deny, cfg.Limits, false); err == nil {
				st.NetworkMissing = netErr.Error()
			}
		}
	}
	switch {
	case err != nil && cfg.Mode == ModeRequired:
		return nil, fmt.Errorf("executor: sandbox required but the launcher does not work: %w", err)
	case err != nil:
		b.launcher = ""
		b.status.Missing = []string{"launcher: " + err.Error()}
		return b, nil
	}
	st.Backend, st.Mode, st.Sandboxed = "process", cfg.Mode, true
	b.status = st
	if cfg.Mode == ModeRequired && !st.Complete() {
		return nil, fmt.Errorf("executor: sandbox required but not every control is enforced: %s", strings.Join(st.Missing, "; "))
	}
	return b, nil
}

// Name is "process".
func (b *ProcessBackend) Name() string { return "process" }

// Status is the protection tasks get.
func (b *ProcessBackend) Status() Status {
	s := b.status
	s.Missing = slices.Clone(s.Missing)
	return s
}

var taskIDRE = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Prepare makes the task's private directory and its command.
func (b *ProcessBackend) Prepare(spec TaskSpec) (Task, error) {
	if len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return nil, errors.New("executor: empty argv")
	}
	t := &processTask{b: b, spec: spec}
	if b.launcher == "" {
		// ModeOff, or auto without a working launcher: a plain child
		// process in the caller's directory, as before.
		t.cmdPath, t.args = spec.Argv[0], spec.Argv[1:]
		return t, nil
	}
	bin, err := exec.LookPath(spec.Argv[0])
	if err != nil {
		return nil, fmt.Errorf("executor: %w", err)
	}
	if bin, err = filepath.Abs(bin); err != nil {
		return nil, fmt.Errorf("executor: %w", err)
	}
	if err := ensurePrivateDir(b.cfg.WorkRoot); err != nil {
		return nil, err
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	id := taskIDRE.ReplaceAllString(spec.ID, "_")
	if len(id) > 40 {
		id = id[:40]
	}
	dir, err := os.MkdirTemp(b.cfg.WorkRoot, "task-"+id+"-"+hex.EncodeToString(rnd[:])+"-")
	if err != nil {
		return nil, fmt.Errorf("executor: task directory: %w", err)
	}
	t.workdir = dir
	if err := os.Mkdir(filepath.Join(dir, "tmp"), 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("executor: task directory: %w", err)
	}
	for _, p := range spec.WritePaths {
		if b.denied(p) {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("executor: write path %q is a protected path", p)
		}
	}
	cwd := spec.Dir
	if cwd == "" {
		cwd = dir
	}
	limits := spec.Limits
	if limits == (Limits{}) {
		limits = b.cfg.Limits
	}
	ls := launchSpec{
		Workdir:    dir,
		Cwd:        cwd,
		Limits:     limits.withDefaults(),
		ReadDeny:   b.deny,
		Private:    b.private(),
		WritePaths: append([]string{dir}, spec.WritePaths...),
		Binary:     bin,
	}
	if b.confine {
		ls.Confined, ls.EgressProxy, ls.EgressDNS = true, spec.EgressProxy, spec.EgressDNS
		t.confine = true
	}
	enc, err := ls.encode()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	t.cmdPath = b.launcher
	t.args = append([]string{LauncherArg, enc, "--"}, spec.Argv...)
	return t, nil
}

// private are the paths hidden from every task besides the deny paths: the
// task root, where each task's own directory is granted back as its write
// path. Concurrent tasks, of one tenant or of several on a shared sensor,
// cannot read or list one another's files.
func (b *ProcessBackend) private() []string {
	var out []string
	for _, root := range []string{b.cfg.WorkRoot, TaskRoot()} {
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = r
		}
		if abs = filepath.Clean(abs); abs != "/" && !slices.Contains(out, abs) {
			out = append(out, abs)
		}
	}
	return out
}

// denied reports whether p is, or is under, a protected path.
func (b *ProcessBackend) denied(p string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		return true
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	for _, d := range b.deny {
		if abs == d || strings.HasPrefix(abs, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// taskEnv is the task's environment: the caller's, then the sandbox's
// private HOME, TMPDIR and XDG directories, then the caller's explicit
// variables.
func (t *processTask) taskEnv() []string {
	env := slices.Clone(t.spec.Env)
	set := func(k, v string) {
		for i, kv := range env {
			if strings.HasPrefix(kv, k+"=") {
				env[i] = k + "=" + v
				return
			}
		}
		env = append(env, k+"="+v)
	}
	if t.workdir != "" {
		tmp := filepath.Join(t.workdir, "tmp")
		for k, v := range map[string]string{
			"HOME": t.workdir, "TMPDIR": tmp, "TMP": tmp, "TEMP": tmp,
			"XDG_CACHE_HOME":  filepath.Join(t.workdir, ".cache"),
			"XDG_CONFIG_HOME": filepath.Join(t.workdir, ".config"),
			"XDG_DATA_HOME":   filepath.Join(t.workdir, ".local", "share"),
			"XDG_STATE_HOME":  filepath.Join(t.workdir, ".local", "state"),
		} {
			set(k, v)
		}
	}
	keys := make([]string, 0, len(t.spec.SetEnv))
	for k := range t.spec.SetEnv {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		set(k, t.spec.SetEnv[k])
	}
	// A confined task's only way out is its forwarder, through the relay
	// in its namespace: the proxy variables say so, whatever the caller set.
	if t.confine {
		proxy := ""
		if t.spec.EgressProxy != "" {
			proxy = "http://" + RelayProxyAddr
		}
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
			set(k, proxy)
		}
		set("NO_PROXY", "")
		set("no_proxy", "")
	}
	return env
}

type processTask struct {
	b       *ProcessBackend
	spec    TaskSpec
	confine bool
	workdir string
	cmdPath string
	args    []string

	mu     sync.Mutex
	cmd    *exec.Cmd
	start  time.Time
	killed string
}

func (t *processTask) Workdir() string { return t.workdir }

func (t *processTask) Start(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, t.cmdPath, t.args...) //nolint:gosec // the launcher (this binary) or the caller's tool
	cmd.Env = t.taskEnv()
	if t.workdir == "" {
		cmd.Dir = t.spec.Dir
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = t.spec.Stdin, t.spec.Stdout, t.spec.Stderr
	if h := t.spec.Hooks.Configure; h != nil {
		h(cmd)
	}
	t.mu.Lock()
	t.cmd, t.start = cmd, time.Now()
	t.mu.Unlock()
	if err := cmd.Start(); err != nil {
		return err
	}
	if h := t.spec.Hooks.Started; h != nil {
		h(cmd)
	}
	return nil
}

func (t *processTask) Wait() (*Result, error) {
	t.mu.Lock()
	cmd := t.cmd
	t.mu.Unlock()
	if cmd == nil {
		return nil, errors.New("executor: task not started")
	}
	err := cmd.Wait()
	if h := t.spec.Hooks.Finished; h != nil {
		h(cmd)
	}
	t.mu.Lock()
	res := &Result{ExitCode: -1, State: cmd.ProcessState, Killed: t.killed, Duration: time.Since(t.start),
		Sandbox: t.b.Status(), Network: t.spec.Network}
	t.mu.Unlock()
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return res, err
	}
	return res, nil
}

func (t *processTask) Kill(reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.killed == "" {
		t.killed = reason
	}
	if t.cmd != nil && t.cmd.Process != nil {
		if t.cmd.Cancel != nil {
			_ = t.cmd.Cancel()
		} else {
			_ = t.cmd.Process.Kill()
		}
	}
}

func (t *processTask) Cleanup() error {
	if t.workdir == "" {
		return nil
	}
	return os.RemoveAll(t.workdir)
}
