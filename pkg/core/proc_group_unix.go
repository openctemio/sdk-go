//go:build unix

package core

import (
	"errors"
	"os/exec"
	"syscall"
)

func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	setParentDeathSignal(cmd.SysProcAttr)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		killProcessGroup(cmd.Process.Pid)
		return nil
	}
}

// killProcessGroup sends SIGKILL to the process group led by pid.
func killProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}
