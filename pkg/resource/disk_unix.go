//go:build unix

package resource

import (
	"math"

	"golang.org/x/sys/unix"
)

// diskFree returns the bytes available to an unprivileged user on dir's
// file system; 0 when it cannot be read.
func diskFree(dir string) int64 {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0
	}
	free := uint64(st.Bavail) * uint64(st.Bsize) //nolint:gosec,unconvert // block size is positive; field types differ per OS
	if free > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(free)
}
