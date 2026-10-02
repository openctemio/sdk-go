package core

import (
	"os/exec"
	"time"
)

// scannerWaitDelay bounds how long Wait waits for a canceled scanner's
// output pipes after its process group was killed.
const scannerWaitDelay = 5 * time.Second

// ConfigureScannerProcess makes a scanner command safe to cancel: it runs in
// its own process group, a canceled context kills the WHOLE group (a
// wrapper script's children too, not only the direct child), and on Linux
// the scanner is killed if the sensor dies. Call before Start; right after
// Start, call ApplyScannerPriority; after Wait, call ReapScannerProcess. The
// SDK's exec helpers do all three. No-op on systems without process groups.
func ConfigureScannerProcess(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	configureProcessGroup(cmd)
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = scannerWaitDelay
	}
}

// ReapScannerProcess kills what is left of a finished scanner's process
// group (background children it did not wait for), so nothing outlives the
// command (api RFC-030 §5.4). Safe to call on any command that was started.
func ReapScannerProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	killProcessGroup(cmd.Process.Pid)
}
