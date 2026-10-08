//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The test binary is its own launcher and its own hostile tool: with
// EXECUTOR_TEST_TOOL set it does what the variable says and prints the
// outcome.
func TestMain(m *testing.M) {
	RunLauncherIfRequested()
	if mode := os.Getenv("EXECUTOR_TEST_TOOL"); mode != "" {
		os.Exit(hostileTool(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func hostileTool(mode string, args []string) int {
	report := func(err error) int {
		if err != nil {
			fmt.Println("ERR", err)
			return 3
		}
		fmt.Println("OK")
		return 0
	}
	switch mode {
	case "read":
		_, err := os.ReadFile(args[0])
		return report(err)
	case "write":
		return report(os.WriteFile(args[0], []byte("pwned"), 0o600))
	case "list":
		_, err := os.ReadDir(args[0])
		return report(err)
	case "roundtrip":
		wd, err := os.Getwd()
		if err != nil {
			return report(err)
		}
		p := filepath.Join(wd, "tmp", "roundtrip.txt")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			return report(err)
		}
		_, err = os.ReadFile(p)
		return report(err)
	case "env":
		fmt.Println(os.Getenv("HOME"), os.Getenv("TMPDIR"))
		wd, _ := os.Getwd()
		fmt.Println(wd)
		return 0
	case "forkbomb":
		n, _ := strconv.Atoi(args[0])
		started := 0
		var firstErr error
		for range n {
			c := exec.Command("/bin/sleep", "30")
			if err := c.Start(); err != nil {
				firstErr = err
				break
			}
			started++
		}
		fmt.Println("STARTED", started, firstErr)
		return 0
	case "unshare":
		return report(unix.Unshare(unix.CLONE_NEWUSER | unix.CLONE_NEWNS))
	case "ptrace":
		pid, _ := strconv.Atoi(args[0])
		return report(unix.PtraceAttach(pid))
	case "mount":
		return report(unix.Mount("tmpfs", args[0], "tmpfs", 0, ""))
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	case "stdin":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return report(err)
		}
		fmt.Print(strings.ToUpper(string(b)))
		return 0
	case "kill-parent":
		return report(syscall.Kill(os.Getppid(), 0))
	}
	return 99
}

func newTestBackend(t *testing.T, deny ...string) *ProcessBackend {
	t.Helper()
	b, err := NewProcessBackend(Config{Mode: ModeRequired, ReadDeny: deny, WorkRoot: t.TempDir(),
		Limits: Limits{Processes: 64}})
	if err != nil {
		t.Skipf("sandbox not available here: %v", err)
	}
	return b
}

// runTool runs the test binary as a hostile tool in a task.
func runTool(t *testing.T, b Backend, spec TaskSpec, mode string, args ...string) (string, *Result) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	spec.Argv = append([]string{exe}, args...)
	spec.Env = append(spec.Env, "EXECUTOR_TEST_TOOL="+mode, "PATH=/usr/bin:/bin")
	spec.Stdout, spec.Stderr = &out, &errb
	task, err := b.Prepare(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = task.Cleanup() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := task.Start(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := task.Wait()
	if err != nil {
		t.Fatalf("wait: %v (stderr %s)", err, errb.String())
	}
	// The tool's verdict is on stdout; stderr carries the launcher's own
	// errors (and the test binary's coverage notes under -cover).
	if o := strings.TrimSpace(out.String()); o != "" {
		return o, res
	}
	return strings.TrimSpace(errb.String()), res
}

// A task reads its standard input (the adapter protocol's channel), in the
// sandbox and without it, from a pipe whose descriptor the task gets.
func TestTaskReadsStdin(t *testing.T) {
	off, err := NewProcessBackend(Config{Mode: ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]Backend{"sandbox": newTestBackend(t), "off": off} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_, _ = io.WriteString(w, "hello adapter")
			_ = w.Close()
		}()
		out, res := runTool(t, b, TaskSpec{Stdin: r}, "stdin")
		_ = r.Close()
		if out != "HELLO ADAPTER" || res.ExitCode != 0 {
			t.Errorf("%s: %q exit %d", name, out, res.ExitCode)
		}
	}
}

// The process backend never claims to enforce the network class: untrusted
// tools must not be admitted on it.
func TestProcessBackendDoesNotEnforceNetwork(t *testing.T) {
	if st := newTestBackend(t).Status(); st.NetworkEnforced {
		t.Fatalf("sandboxed process backend claims network enforcement: %+v", st)
	}
	off, err := NewProcessBackend(Config{Mode: ModeOff})
	if err != nil {
		t.Fatal(err)
	}
	if off.Status().NetworkEnforced {
		t.Fatal("ModeOff claims network enforcement")
	}
}

func TestProbeEnforcesEverything(t *testing.T) {
	b := newTestBackend(t)
	st := b.Status()
	if !st.Complete() || st.Landlock < 1 {
		t.Fatalf("status %+v", st)
	}
}

// SECURITY (acceptance): a task cannot read the sensor's protected files
// (its key, outbox, configuration), even with the same user.
func TestTaskCannotReadProtectedFiles(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(state, "sensor.key")
	if err := os.WriteFile(key, []byte("secret-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(t.TempDir(), "sensor.yaml")
	if err := os.WriteFile(cfgFile, []byte("api_key: x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(state), "public.txt")
	if err := os.WriteFile(other, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink elsewhere that points into the protected directory.
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(state, link); err != nil {
		t.Fatal(err)
	}
	b := newTestBackend(t, state, cfgFile)
	for _, p := range []string{key, cfgFile, filepath.Join(link, "sensor.key")} {
		if out, _ := runTool(t, b, TaskSpec{}, "read", p); !strings.Contains(out, "permission denied") {
			t.Errorf("read %s: %q", p, out)
		}
	}
	if out, _ := runTool(t, b, TaskSpec{}, "read", other); out != "OK" {
		t.Errorf("read of an unprotected sibling: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{}, "write", key); !strings.Contains(out, "permission denied") {
		t.Errorf("overwrite the key: %q", out)
	}
	// Nor through /proc: the sensor (this test process) is not dumpable.
	if out, _ := runTool(t, b, TaskSpec{}, "read", fmt.Sprintf("/proc/%d/environ", os.Getpid())); !strings.Contains(out, "permission denied") {
		t.Errorf("read the sensor's environment: %q", out)
	}
}

// SECURITY (acceptance): a task writes only in its private directory and
// the paths it was given.
func TestTaskWritesOnlyInItsDirectory(t *testing.T) {
	b := newTestBackend(t)
	outside := t.TempDir()
	given := t.TempDir()
	for _, p := range []string{filepath.Join(outside, "x"), "/tmp/openctem-sandbox-escape", filepath.Join(os.Getenv("HOME"), ".openctem-escape")} {
		if out, _ := runTool(t, b, TaskSpec{}, "write", p); !strings.Contains(out, "permission denied") {
			t.Errorf("write %s: %q", p, out)
			_ = os.Remove(p)
		}
	}
	if out, _ := runTool(t, b, TaskSpec{WritePaths: []string{given}}, "write", filepath.Join(given, "out.json")); out != "OK" {
		t.Errorf("write in a given path: %q", out)
	}
	// Relative to its working directory (its private one) works.
	if out, _ := runTool(t, b, TaskSpec{}, "write", "result.txt"); out != "OK" {
		t.Errorf("write in its directory: %q", out)
	}
}

// The task's HOME and TMPDIR are its private directory, which Cleanup
// removes; an explicit variable wins.
func TestTaskEnvironmentAndCleanup(t *testing.T) {
	b := newTestBackend(t)
	exe, _ := os.Executable()
	var out, errb bytes.Buffer
	task, err := b.Prepare(TaskSpec{Argv: []string{exe}, Env: []string{"EXECUTOR_TEST_TOOL=env", "HOME=/home/sensor"}, Stdout: &out, Stderr: &errb})
	if err != nil {
		t.Fatal(err)
	}
	dir := task.Workdir()
	if err := task.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Wait(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || lines[0] != dir+" "+filepath.Join(dir, "tmp") || lines[1] != dir {
		t.Errorf("env/cwd: %q (dir %s)", out.String(), dir)
	}
	if err := task.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workdir left: %v", err)
	}
	out.Reset()
	task, _ = b.Prepare(TaskSpec{Argv: []string{exe}, Env: []string{"EXECUTOR_TEST_TOOL=env"}, SetEnv: map[string]string{"HOME": "/opt/tool-home"}, Stdout: &out, Stderr: &errb})
	_ = task.Start(context.Background())
	_, _ = task.Wait()
	_ = task.Cleanup()
	if !strings.HasPrefix(out.String(), "/opt/tool-home ") {
		t.Errorf("explicit HOME lost: %q", out.String())
	}
}

// SECURITY (acceptance): a fork bomb is stopped at the task's process
// allowance, far below 1000, and the sensor can still start processes.
func TestForkBombIsRefused(t *testing.T) {
	b := newTestBackend(t)
	out, _ := runTool(t, b, TaskSpec{Hooks: ProcessHooks{Configure: func(c *exec.Cmd) {
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	}, Finished: func(c *exec.Cmd) { _ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }}}, "forkbomb", "1000")
	var started int
	if _, err := fmt.Sscanf(out, "STARTED %d", &started); err != nil {
		t.Fatalf("output %q", out)
	}
	if started >= 1000 || started > 100 || !strings.Contains(out, "resource temporarily unavailable") {
		t.Fatalf("fork bomb: %q", out)
	}
	if err := exec.Command("/bin/true").Run(); err != nil {
		t.Fatalf("the sensor cannot start a process after the bomb: %v", err)
	}
}

// SECURITY: the syscalls a scanner never needs are refused.
func TestDangerousSyscallsAreRefused(t *testing.T) {
	b := newTestBackend(t)
	if out, _ := runTool(t, b, TaskSpec{}, "unshare"); !strings.Contains(out, "operation not permitted") {
		t.Errorf("unshare: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{}, "ptrace", strconv.Itoa(os.Getpid())); !strings.Contains(out, "operation not permitted") {
		t.Errorf("ptrace the sensor: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{}, "mount", t.TempDir()); !strings.Contains(out, "operation not permitted") {
		t.Errorf("mount: %q", out)
	}
}

// A canceled task is killed, and its result says so.
func TestCanceledTaskIsKilled(t *testing.T) {
	b := newTestBackend(t)
	exe, _ := os.Executable()
	task, err := b.Prepare(TaskSpec{Argv: []string{exe}, Env: []string{"EXECUTOR_TEST_TOOL=sleep"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = task.Cleanup() }()
	ctx, cancel := context.WithCancel(context.Background())
	if err := task.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(200*time.Millisecond, func() { task.Kill("timeout"); cancel() })
	start := time.Now()
	res, _ := task.Wait()
	if time.Since(start) > 10*time.Second || res.Killed != "timeout" || res.ExitCode == 0 {
		t.Fatalf("result %+v after %s", res, time.Since(start))
	}
	if !res.Sandbox.Complete() {
		t.Errorf("result not stamped with the sandbox: %+v", res.Sandbox)
	}
}

// A write path inside a protected path is refused before anything runs.
func TestWritePathCannotBeProtected(t *testing.T) {
	state := t.TempDir()
	b := newTestBackend(t, state)
	if _, err := b.Prepare(TaskSpec{Argv: []string{"/bin/true"}, WritePaths: []string{filepath.Join(state, "x")}}); err == nil {
		t.Fatal("accepted a write path in a protected directory")
	}
}

// Modes: required fails without a working launcher; auto degrades and says
// why; off runs the command directly.
func TestModes(t *testing.T) {
	if _, err := NewProcessBackend(Config{Mode: ModeRequired, Launcher: "/bin/true"}); err == nil {
		t.Error("required mode accepted a launcher that does not answer")
	}
	b, err := NewProcessBackend(Config{Mode: ModeAuto, Launcher: "/bin/true"})
	if err != nil || b.Status().Sandboxed || len(b.Status().Missing) == 0 {
		t.Errorf("auto with a broken launcher: %v %+v", err, b.Status())
	}
	if _, err := NewProcessBackend(Config{Mode: "loose"}); err == nil {
		t.Error("unknown mode accepted")
	}
	off, _ := NewProcessBackend(Config{Mode: ModeOff})
	var out bytes.Buffer
	task, err := off.Prepare(TaskSpec{Argv: []string{"/bin/echo", "hi"}, Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	_ = task.Start(context.Background())
	if res, err := task.Wait(); err != nil || res.ExitCode != 0 || strings.TrimSpace(out.String()) != "hi" || task.Workdir() != "" {
		t.Errorf("off: %v %+v %q", err, res, out.String())
	}
	if _, err := NewProcessBackend(Config{Mode: ModeAuto, ReadDeny: []string{"/"}}); err == nil {
		t.Error("/ accepted as a protected path")
	}
}

// Launch specs from anywhere but the parent are refused.
func TestLaunchSpecIsStrict(t *testing.T) {
	for _, s := range []string{"", "!!!", "e30", // {}
		"eyJ3b3JrZGlyIjoiLyIsImV2aWwiOnRydWV9"} { // unknown field
		if _, err := decodeLaunchSpec(s); err == nil && s != "e30" {
			t.Errorf("accepted %q", s)
		}
	}
}
