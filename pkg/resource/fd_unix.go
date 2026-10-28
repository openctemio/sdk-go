//go:build unix

package resource

import "golang.org/x/sys/unix"

// fdSoftLimit is the process's soft limit on open descriptors; 0 when
// unknown.
func fdSoftLimit() uint64 {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return rl.Cur
}
