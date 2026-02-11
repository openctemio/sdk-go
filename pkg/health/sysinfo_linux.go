//go:build linux

package health

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// SystemMemoryCheck checks system-wide memory usage (Linux only).
type SystemMemoryCheck struct {
	MaxUsagePercent float64
}

func (c *SystemMemoryCheck) Name() string { return "system_memory" }

func (c *SystemMemoryCheck) Check(ctx context.Context) CheckResult {
	result := CheckResult{
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}

	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("failed to get system memory info: %v", err)
		return result
	}

	totalMem := info.Totalram * uint64(info.Unit)
	freeMem := info.Freeram * uint64(info.Unit)
	usedMem := totalMem - freeMem
	usagePercent := float64(usedMem) / float64(totalMem) * 100

	result.Metadata["total_bytes"] = totalMem
	result.Metadata["free_bytes"] = freeMem
	result.Metadata["used_bytes"] = usedMem
	result.Metadata["usage_percent"] = fmt.Sprintf("%.2f%%", usagePercent)

	if c.MaxUsagePercent > 0 && usagePercent > c.MaxUsagePercent {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("memory usage %.2f%% exceeds threshold %.2f%%", usagePercent, c.MaxUsagePercent)
		return result
	}

	result.Status = StatusHealthy
	result.Message = fmt.Sprintf("memory usage: %.2f%%", usagePercent)
	return result
}
