//go:build unix

package core

import (
	"os"
	"runtime"
	"syscall"
)

// peakRSSBytes is the process's peak resident memory (ru_maxrss: KiB on
// Linux and the BSDs, bytes on macOS).
func peakRSSBytes(ps *os.ProcessState) int64 {
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0
	}
	v := int64(ru.Maxrss) //nolint:unconvert // int32 on some systems
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		return v
	}
	return v * 1024
}

// killedBySIGKILL reports a process ended by SIGKILL (the OOM killer's
// signal; a timeout kill is told apart by the context).
func killedBySIGKILL(ps *os.ProcessState) bool {
	ws, ok := ps.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}
