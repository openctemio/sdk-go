//go:build unix

package workspace

import (
	"os"

	"golang.org/x/sys/unix"
)

// ownedByOther reports whether fi belongs to another user.
func ownedByOther(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*unix.Stat_t)
	return ok && int(st.Uid) != os.Getuid()
}

// noexec reports whether dir's file system is mounted noexec (known=false
// when it cannot tell).
func noexec(dir string) (on, known bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, false
	}
	return noexecFlag(st)
}
