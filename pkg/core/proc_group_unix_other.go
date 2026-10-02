//go:build unix && !linux

package core

import "syscall"

func setParentDeathSignal(*syscall.SysProcAttr) {}
