//go:build linux

package executor

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// confine applies the sandbox to this process (the launcher, which then
// becomes the tool): working directory, resource limits, no_new_privs,
// Landlock, seccomp. A control the kernel does not support is listed in
// Status.Missing; any other failure is an error (the tool does not run).
func confine(ls launchSpec) (Status, error) {
	st := Status{Backend: "process"}
	if ls.Cwd != "" {
		if err := os.Chdir(ls.Cwd); err != nil {
			return st, fmt.Errorf("working directory: %w", err)
		}
	}
	if err := setLimits(ls.Limits); err != nil {
		return st, err
	}
	st.Rlimits = true
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return st, fmt.Errorf("no_new_privs: %w", err)
	}
	st.NoNewPrivs = true
	abi, err := applyLandlock(ls.ReadDeny, ls.Private, ls.WritePaths)
	switch {
	case err == errLandlockUnsupported:
		st.Missing = append(st.Missing, "landlock: not supported by this kernel or blocked by the container's seccomp profile")
	case err != nil:
		return st, fmt.Errorf("landlock: %w", err)
	default:
		st.Landlock = abi
	}
	if err := applySeccomp(); err != nil {
		if err == errSeccompUnsupported {
			st.Missing = append(st.Missing, "seccomp: not supported on this architecture or kernel")
		} else {
			return st, fmt.Errorf("seccomp: %w", err)
		}
	} else {
		st.Seccomp = true
	}
	return st, nil
}

// setLimits sets the task's resource limits. RLIMIT_NPROC counts every
// process and thread of the user, so the task gets the user's current count
// plus its allowance: a fork bomb stops at that, while the sensor (which
// keeps its own limit) can still start threads.
func setLimits(l Limits) error {
	l = l.withDefaults()
	set := func(name string, res int, v uint64) error {
		if err := unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v}); err != nil {
			// Lowering a limit always works unless the current hard limit
			// is already lower: keep that one.
			var cur unix.Rlimit
			if gerr := unix.Getrlimit(res, &cur); gerr == nil && cur.Max < v {
				return unix.Setrlimit(res, &unix.Rlimit{Cur: cur.Max, Max: cur.Max})
			}
			return fmt.Errorf("rlimit %s: %w", name, err)
		}
		return nil
	}
	if err := set("data", unix.RLIMIT_DATA, l.MemoryBytes); err != nil {
		return err
	}
	if err := set("fsize", unix.RLIMIT_FSIZE, l.FileSizeBytes); err != nil {
		return err
	}
	if err := set("nofile", unix.RLIMIT_NOFILE, l.OpenFiles); err != nil {
		return err
	}
	if err := set("core", unix.RLIMIT_CORE, 0); err != nil {
		return err
	}
	if l.CPUSeconds > 0 {
		if err := set("cpu", unix.RLIMIT_CPU, l.CPUSeconds); err != nil {
			return err
		}
	}
	return set("nproc", unix.RLIMIT_NPROC, userTasks()+l.Processes)
}

// userTasks counts the processes and threads of this process's real user
// (what RLIMIT_NPROC counts).
func userTasks() uint64 {
	uid := strconv.Itoa(os.Getuid())
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	var n uint64
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		f, err := os.Open(filepath.Join("/proc", e.Name(), "status"))
		if err != nil {
			continue
		}
		var mine bool
		var threads uint64
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if v, ok := strings.CutPrefix(line, "Uid:"); ok {
				if f := strings.Fields(v); len(f) > 0 && f[0] == uid {
					mine = true
				}
			} else if v, ok := strings.CutPrefix(line, "Threads:"); ok {
				threads, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			}
		}
		_ = f.Close()
		if mine {
			n += max(threads, 1)
		}
	}
	return n
}

// execTool replaces this process with the tool.
func execTool(bin string, argv []string, env []string) error {
	if bin == "" {
		return fmt.Errorf("no binary")
	}
	return syscall.Exec(bin, argv, env) //nolint:gosec // the caller's tool, resolved by the parent
}

// makeUndumpable stops tasks running under the same user from reading this
// process's memory, environment and open files through /proc.
func makeUndumpable() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
