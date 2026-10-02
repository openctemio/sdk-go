package core

import (
	"os/exec"
	"sync"
)

// ScannerPriority is how much a scanner process yields to the sensor that
// runs it (api RFC-035 §5.3). A scanner can saturate the CPU, the disk and
// the memory; the sensor must still heartbeat, poll and upload. Linux only;
// elsewhere it does nothing.
type ScannerPriority struct {
	// Nice is added to the sensor's own nice value for the scanner's process
	// group (0-19; 10 is the "low" process priority of other scanning
	// agents). Each nice step is about 10% less CPU under contention.
	Nice int
	// IOLevel is the best-effort I/O priority level of the process group,
	// 0 (highest) to 7 (lowest); -1 leaves it. Only I/O schedulers that
	// honor priorities (bfq, mq-deadline) apply it.
	IOLevel int
	// OOMScoreAdj is written to the scanner's oom_score_adj (0-1000): when
	// memory runs out, the kernel kills a scanner before the sensor. Raising
	// it needs no privilege; children forked after the write inherit it.
	OOMScoreAdj int
}

// DefaultScannerPriority is the priority sensorkit gives scanners: nice +10,
// lowest best-effort I/O, and an OOM score well above the sensor's.
var DefaultScannerPriority = ScannerPriority{Nice: 10, IOLevel: 7, OOMScoreAdj: 500}

var (
	scannerPriorityMu sync.RWMutex
	scannerPriority   *ScannerPriority
)

// SetScannerPriority sets the priority every scanner process the SDK starts
// gets from now on (ExecuteScanner, StreamScanner, BaseScanner). nil, the
// default, leaves scanners at the sensor's own priority. sensorkit sets
// DefaultScannerPriority unless SENSOR_SCANNER_PRIORITY=normal.
func SetScannerPriority(p *ScannerPriority) {
	scannerPriorityMu.Lock()
	defer scannerPriorityMu.Unlock()
	if p == nil {
		scannerPriority = nil
		return
	}
	v := *p
	v.Nice = min(max(v.Nice, 0), 19)
	if v.IOLevel > 7 {
		v.IOLevel = 7
	}
	v.OOMScoreAdj = min(max(v.OOMScoreAdj, 0), 1000)
	scannerPriority = &v
}

// CurrentScannerPriority returns the priority set with SetScannerPriority,
// nil when none is.
func CurrentScannerPriority() *ScannerPriority {
	scannerPriorityMu.RLock()
	defer scannerPriorityMu.RUnlock()
	if scannerPriority == nil {
		return nil
	}
	v := *scannerPriority
	return &v
}

// ApplyScannerPriority lowers a started scanner's priority as
// SetScannerPriority says: its process group's CPU and I/O priority, and the
// OOM score of its leader. Call right after Start (the SDK's exec helpers
// do); a scanner configured with ConfigureScannerProcess leads its own
// process group, so processes it already forked are covered too. Best
// effort: a refused change is ignored and the scanner runs as it is.
func ApplyScannerPriority(cmd *exec.Cmd) {
	p := CurrentScannerPriority()
	if p == nil || cmd == nil || cmd.Process == nil {
		return
	}
	applyScannerPriority(cmd, *p)
}
