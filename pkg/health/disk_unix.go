//go:build !windows

package health

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// DiskCheck checks available disk space.
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

	path := c.Path
	if path == "" {
		path = "/"
	}

	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("failed to get disk stats: %v", err)
		return result
	}

	// Calculate disk usage
	// Bsize is always positive on supported platforms (Linux/Unix)
	totalBytes := stat.Blocks * uint64(stat.Bsize) //nolint:gosec // G115: safe conversion
	freeBytes := stat.Bavail * uint64(stat.Bsize)  //nolint:gosec // G115: safe conversion
	usedBytes := totalBytes - freeBytes
	freePercent := float64(freeBytes) / float64(totalBytes) * 100

	result.Metadata["total_bytes"] = totalBytes
	result.Metadata["free_bytes"] = freeBytes
	result.Metadata["used_bytes"] = usedBytes
	result.Metadata["free_percent"] = fmt.Sprintf("%.2f%%", freePercent)
	result.Metadata["path"] = path

	// Check thresholds
	if c.MinFreePercent > 0 {
		if freePercent < c.MinFreePercent {
			result.Status = StatusUnhealthy
			result.Error = fmt.Sprintf("disk free space %.2f%% is below threshold %.2f%%", freePercent, c.MinFreePercent)
			return result
		}
	} else if c.MinFreeBytes > 0 {
		// Safe comparison: convert threshold to uint64 instead of converting freeBytes to int64
		if freeBytes < uint64(c.MinFreeBytes) { //nolint:gosec // MinFreeBytes is always positive here
			result.Status = StatusUnhealthy
			result.Error = fmt.Sprintf("disk free space %d bytes is below threshold %d bytes", freeBytes, c.MinFreeBytes)
			return result
		}
	}

	result.Status = StatusHealthy
	result.Message = fmt.Sprintf("disk has %.2f%% free space", freePercent)
	return result
}
