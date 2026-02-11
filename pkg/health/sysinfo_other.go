//go:build !linux

package health

import (
	"context"
	"runtime"
	"time"
)

// SystemMemoryCheck checks system-wide memory usage.
// On non-Linux platforms, this falls back to Go runtime memory stats.
type SystemMemoryCheck struct {
	MaxUsagePercent float64
}

func (c *SystemMemoryCheck) Name() string { return "system_memory" }

func (c *SystemMemoryCheck) Check(ctx context.Context) CheckResult {
	result := CheckResult{
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}

	// On non-Linux platforms, use Go runtime memory stats as a proxy
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	result.Metadata["heap_alloc_bytes"] = m.HeapAlloc
	result.Metadata["heap_sys_bytes"] = m.HeapSys
	result.Metadata["total_alloc_bytes"] = m.TotalAlloc
	result.Metadata["sys_bytes"] = m.Sys
	result.Metadata["platform"] = runtime.GOOS
	result.Metadata["note"] = "system memory stats only available on Linux; showing Go runtime stats"

	result.Status = StatusHealthy
	result.Message = "system memory check (limited on " + runtime.GOOS + ")"
	return result
}
