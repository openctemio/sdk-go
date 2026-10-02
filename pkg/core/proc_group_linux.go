//go:build linux

package core

import "syscall"

// setParentDeathSignal kills the scanner when the sensor process dies.
func setParentDeathSignal(attr *syscall.SysProcAttr) {
	attr.Pdeathsig = syscall.SIGKILL
}
