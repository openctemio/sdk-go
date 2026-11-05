//go:build linux

package executor

import "golang.org/x/sys/unix"

// TaskRootInMemory reports whether TaskRoot is on a memory file system
// (tmpfs or ramfs): a file a task writes there never reaches a disk. known
// is false when it cannot be told.
func TaskRootInMemory() (inMemory, known bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(TaskRoot(), &st); err != nil {
		return false, false
	}
	return st.Type == unix.TMPFS_MAGIC || st.Type == unix.RAMFS_MAGIC, true
}
