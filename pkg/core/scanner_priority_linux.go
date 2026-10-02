//go:build linux

package core

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
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

func applyScannerPriority(cmd *exec.Cmd, p *ScannerPriority) {
	pid := cmd.Process.Pid
	if pid <= 0 {
		return
	}
	if p != nil {
		applyScannerCPUAndIO(pid, cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid, *p)
	}
	if adj, ok := scannerOOMScoreAdj(p, sensorOOMScoreAdj()); ok {
		// Raising a score is unprivileged; a lower value than the current
		// one would need CAP_SYS_RESOURCE, and the write then just fails.
		_ = os.WriteFile("/proc/"+strconv.Itoa(pid)+"/oom_score_adj", []byte(strconv.Itoa(adj)), 0)
	}
}

func applyScannerCPUAndIO(pid int, group bool, p ScannerPriority) {
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
}

// scannerOOMScoreAdj is the oom_score_adj to write to a scanner the sensor
// just started, given the priority (nil: none set) and the sensor's own
// oom_score_adj, which the scanner inherited at fork. ok is false when the
// inherited value stays.
func scannerOOMScoreAdj(p *ScannerPriority, sensor int) (adj int, ok bool) {
	if p != nil && p.OOMScoreAdj > 0 {
		return p.OOMScoreAdj, true
	}
	if sensor < 0 {
		// Never keep the sensor's protection from the OOM killer.
		return 0, true
	}
	return 0, false
}

// sensorOOMScoreAdj is the sensor's own oom_score_adj (0 when unreadable).
func sensorOOMScoreAdj() int {
	b, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return n
}
