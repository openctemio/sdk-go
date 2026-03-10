//go:build windows

package health

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

// DiskCheck checks available disk space.
// On Windows, disk space checking is not supported and always returns healthy.
type DiskCheck struct {
	Path         string
	MinFreeBytes int64
	// MinFreePercent is the minimum percentage of free space required (0-100).
	// If set, this takes precedence over MinFreeBytes.
	MinFreePercent float64
}

func (c *DiskCheck) Name() string { return "disk" }
func (c *DiskCheck) Check(ctx context.Context) CheckResult {
	result := CheckResult{
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}

	result.Metadata["platform"] = runtime.GOOS
	result.Metadata["note"] = "disk space check not supported on Windows"

	result.Status = StatusHealthy
	result.Message = fmt.Sprintf("disk check (not available on %s)", runtime.GOOS)
	return result
}
