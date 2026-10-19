//go:build unix && !linux

package workspace

import "golang.org/x/sys/unix"

// noexecFlag is not read on this platform (the flag field differs).
func noexecFlag(unix.Statfs_t) (on, known bool) { return false, false }
