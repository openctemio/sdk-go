//go:build linux

package executor

// Per-task cgroup v2 envelopes (research/318 §6.2). Where the sensor's own
// cgroup is delegated to it (writable, with the cpu, memory and pids
// controllers available), the sensor moves itself into a leaf
// (resource.EnvelopeSelfLeaf) and starts every task directly inside a
// cgroup of its own under "openctem-tasks": clone3 with CLONE_INTO_CGROUP,
// so nothing the tool forks is ever outside its limits. The sensor never
// writes outside the cgroup it was started in and needs no privilege; a
// host that does not delegate keeps the rlimit envelope.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openctemio/sdk-go/pkg/resource"
)

// EnvelopeProbeArg makes a program that calls RunLauncherIfRequested exit
// at once: the probe that clone3 into a cgroup works here.
const EnvelopeProbeArg = "__openctem-envelope-probe"

const (
	cgroupRoot     = "/sys/fs/cgroup"
	tasksLeaf      = "openctem-tasks"
	cpuPeriodMicro = 100000
	// taskCPUWeight is a task's CPU weight against the sensor's 100: the
	// sensor's heartbeats and uploads go first within its own share.
	taskCPUWeight = 50
)

type cgroupEnvelopes struct {
	tasks string
	ctrls []string
}

var (
	envMu      sync.Mutex
	envMgr     *cgroupEnvelopes
	envMissing = "not enabled"
	envTried   bool
)

// EnableEnvelopes sets up per-task cgroup envelopes once, when the sensor's
// cgroup is delegated and holds the sensor alone, and reports the envelope
// tasks get: EnvelopeCgroup, or EnvelopeRlimit with the reason cgroups are
// not used. It moves this process into a leaf cgroup, so call it from the
// sensor's start-up.
func EnableEnvelopes() (mode, missing string) {
	envMu.Lock()
	defer envMu.Unlock()
	if !envTried {
		envTried = true
		m, err := setupEnvelopes(cgroupRoot, os.Getpid())
		if err != nil {
			envMissing = err.Error()
		} else if err := probeClone3(m); err != nil {
			envMissing = "the kernel or the container's seccomp profile refuses clone3 into a cgroup: " + err.Error()
		} else {
			envMgr, envMissing = m, ""
		}
	}
	if envMgr != nil {
		return EnvelopeCgroup, ""
	}
	return EnvelopeRlimit, envMissing
}

func currentEnvelopes() (*cgroupEnvelopes, string) {
	envMu.Lock()
	defer envMu.Unlock()
	return envMgr, envMissing
}

// ownCgroup is this process's cgroup v2 path ("0::/path").
func ownCgroup() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Clean("/" + rest), nil
		}
	}
	return "", errors.New("no cgroup v2 hierarchy")
}

// setupEnvelopes makes root/<own>/openctem-sensor (where every process of
// the sensor's cgroup moves) and root/<own>/openctem-tasks with the
// controllers enabled for task cgroups.
func setupEnvelopes(root string, pid int) (*cgroupEnvelopes, error) {
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return nil, errors.New("no cgroup v2 unified hierarchy")
	}
	own, err := ownCgroup()
	if err != nil {
		return nil, err
	}
	if filepath.Base(own) == resource.EnvelopeSelfLeaf {
		own = filepath.Dir(own)
	}
	dir := filepath.Join(root, own)
	avail, err := readFields(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	var ctrls []string
	for _, c := range []string{"cpu", "memory", "pids"} {
		if slices.Contains(avail, c) {
			ctrls = append(ctrls, c)
		}
	}
	if !slices.Contains(ctrls, "memory") || !slices.Contains(ctrls, "pids") {
		return nil, fmt.Errorf("the sensor's cgroup does not delegate the memory and pids controllers (has %q)", strings.Join(avail, " "))
	}
	if unix.Access(filepath.Join(dir, "cgroup.subtree_control"), unix.W_OK) != nil ||
		unix.Access(filepath.Join(dir, "cgroup.procs"), unix.W_OK) != nil {
		return nil, errors.New("the sensor's cgroup is not writable (read-only cgroup mount or no delegation)")
	}
	self := filepath.Join(dir, resource.EnvelopeSelfLeaf)
	if err := os.Mkdir(self, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("make %s: %w", resource.EnvelopeSelfLeaf, err)
	}
	// cgroup v2 allows no process in a cgroup whose controllers are
	// enabled for its children, so the sensor moves to the leaf. Only when
	// it is alone in its cgroup: a cgroup shared with other programs (a
	// shell, an init that is not the sensor, a test runner) is not the
	// sensor's to rearrange.
	procs, _ := readFields(filepath.Join(dir, "cgroup.procs"))
	for _, p := range procs {
		if p != strconv.Itoa(pid) {
			return nil, errors.New("the sensor's cgroup holds other processes too; give the sensor a cgroup of its own (systemd Delegate=yes, or the container's main process)")
		}
	}
	if len(procs) > 0 {
		if err := os.WriteFile(filepath.Join(self, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
			return nil, fmt.Errorf("move the sensor into its leaf cgroup: %w", err)
		}
	}
	enable := "+" + strings.Join(ctrls, " +")
	if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(enable), 0); err != nil {
		return nil, fmt.Errorf("enable %s for task cgroups: %w", strings.Join(ctrls, ", "), err)
	}
	tasks := filepath.Join(dir, tasksLeaf)
	if err := os.Mkdir(tasks, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("make %s: %w", tasksLeaf, err)
	}
	if err := os.WriteFile(filepath.Join(tasks, "cgroup.subtree_control"), []byte(enable), 0); err != nil {
		return nil, fmt.Errorf("enable controllers under %s: %w", tasksLeaf, err)
	}
	m := &cgroupEnvelopes{tasks: tasks, ctrls: ctrls}
	m.sweep()
	return m, nil
}

// sweep removes task cgroups a previous run of the sensor left (a crash).
func (m *cgroupEnvelopes) sweep() {
	entries, err := os.ReadDir(m.tasks)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "task-") {
			removeCgroup(filepath.Join(m.tasks, e.Name()))
		}
	}
}

func readFields(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(b)), nil
}

// probeClone3 starts a trivial child straight into a task cgroup.
func probeClone3(m *cgroupEnvelopes) error {
	bin, args := "", []string(nil)
	if launcherWired.Load() {
		if exe, err := os.Executable(); err == nil {
			bin, args = exe, []string{EnvelopeProbeArg}
		}
	}
	if bin == "" {
		for _, p := range []string{"/bin/true", "/usr/bin/true"} {
			if _, err := os.Stat(p); err == nil {
				bin = p
				break
			}
		}
	}
	if bin == "" {
		return errors.New("no program to probe with")
	}
	cg, err := m.create("probe", Envelope{CPU: 1, MemoryMax: 64 << 20, Pids: 8})
	if err != nil {
		return err
	}
	defer cg.close()
	cmd := exec.Command(bin, args...) //nolint:gosec // this program, or true
	cmd.Env = []string{}
	cg.configure(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	cg.started()
	return cmd.Wait()
}

// taskCgroup is one task's cgroup.
type taskCgroup struct {
	dir string
	fd  int
}

// create makes a task cgroup with the envelope's limits.
func (m *cgroupEnvelopes) create(id string, e Envelope) (*taskCgroup, error) {
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	id = taskIDRE.ReplaceAllString(id, "_")
	if len(id) > 40 {
		id = id[:40]
	}
	dir := filepath.Join(m.tasks, "task-"+id+"-"+hex.EncodeToString(rnd[:]))
	if err := os.Mkdir(dir, 0o750); err != nil {
		return nil, fmt.Errorf("executor: task cgroup: %w", err)
	}
	write := func(name, v string) error {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0); err != nil {
			return fmt.Errorf("executor: task cgroup %s: %w", name, err)
		}
		return nil
	}
	var err error
	if slices.Contains(m.ctrls, "cpu") {
		if e.CPU > 0 {
			err = errors.Join(err, write("cpu.max", fmt.Sprintf("%d %d", max(int64(e.CPU*cpuPeriodMicro), 1000), cpuPeriodMicro)))
		}
		err = errors.Join(err, write("cpu.weight", strconv.Itoa(taskCPUWeight)))
	}
	if e.MemoryMax > 0 {
		// memory.max only: memory.high throttles a task's allocations once
		// it is over, which without swap stalls a tool for minutes instead
		// of ending it; a hard limit gives a clear out-of-memory instead.
		err = errors.Join(err, write("memory.max", strconv.FormatUint(e.MemoryMax, 10)))
	}
	if e.Pids > 0 {
		err = errors.Join(err, write("pids.max", strconv.FormatUint(e.Pids, 10)))
	}
	if err != nil {
		removeCgroup(dir)
		return nil, err
	}
	fd, oerr := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if oerr != nil {
		removeCgroup(dir)
		return nil, fmt.Errorf("executor: open task cgroup: %w", oerr)
	}
	return &taskCgroup{dir: dir, fd: fd}, nil
}

// configure makes the process start inside the cgroup.
func (c *taskCgroup) configure(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = c.fd
}

// started closes the descriptor the start needed.
func (c *taskCgroup) started() {
	if c.fd >= 0 {
		_ = unix.Close(c.fd)
		c.fd = -1
	}
}

// oomKilled reports whether the kernel killed a process of the task for
// reaching the envelope's memory limit.
func (c *taskCgroup) oomKilled() bool {
	b, err := os.ReadFile(filepath.Join(c.dir, "memory.events"))
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "oom_kill "); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n > 0
		}
	}
	return false
}

// close kills whatever the task left running in its cgroup and removes it.
func (c *taskCgroup) close() {
	c.started()
	removeCgroup(c.dir)
}

// removeCgroup kills every process left in dir (cgroup.kill, or SIGKILL
// to each listed process) and removes it.
func removeCgroup(dir string) {
	for i := 0; i < 20; i++ {
		if err := unix.Rmdir(dir); err == nil || errors.Is(err, unix.ENOENT) {
			return
		}
		if os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0) != nil {
			procs, _ := readFields(filepath.Join(dir, "cgroup.procs"))
			for _, p := range procs {
				if pid, err := strconv.Atoi(p); err == nil && pid > 1 {
					_ = unix.Kill(pid, unix.SIGKILL)
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
}
