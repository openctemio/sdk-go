//go:build !linux

package core

import "os/exec"

func applyScannerPriority(*exec.Cmd, *ScannerPriority) {}
