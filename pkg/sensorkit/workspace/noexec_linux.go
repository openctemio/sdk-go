//go:build linux

package workspace

import "golang.org/x/sys/unix"

func noexecFlag(st unix.Statfs_t) (on, known bool) { return st.Flags&unix.ST_NOEXEC != 0, true }
