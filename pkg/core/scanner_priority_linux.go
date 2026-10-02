//go:build linux

package core

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// ioprio_set(2) constants (linux/ioprio.h).
const (
	ioprioWhoProcess = 1
	ioprioWhoPgrp    = 2
	ioprioClassBE    = 2
	ioprioClassShift = 13
)

func applyScannerPriority(cmd *exec.Cmd, p ScannerPriority) {
	pid := cmd.Process.Pid
	if pid <= 0 {
		return
	}
	group := cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid
	which, who := syscall.PRIO_PROCESS, pid
	ioWho := ioprioWhoProcess
	if group {
		// The scanner leads its process group (pgid == pid): the whole
		// group, including anything it forked already.
		which, ioWho = syscall.PRIO_PGRP, ioprioWhoPgrp
	}
	if p.Nice > 0 {
		// Relative to the sensor: getpriority returns 20 - nice.
		self := 0
		if v, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0); err == nil {
			self = 20 - v
		}
		_ = syscall.Setpriority(which, who, min(self+p.Nice, 19))
	}
	if p.IOLevel >= 0 {
		prio := ioprioClassBE<<ioprioClassShift | p.IOLevel
		_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, uintptr(ioWho), uintptr(who), uintptr(prio))
	}
	if p.OOMScoreAdj > 0 {
		// Raising a score is unprivileged; a lower value than the current
		// one would need CAP_SYS_RESOURCE, and the write then just fails.
		_ = os.WriteFile("/proc/"+strconv.Itoa(pid)+"/oom_score_adj", []byte(strconv.Itoa(p.OOMScoreAdj)), 0)
	}
}
