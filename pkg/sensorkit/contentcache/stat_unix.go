//go:build unix

package contentcache

import (
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

// statMeta is the file metadata a load check compares: size, mode,
// modification and change time, inode. An unprivileged writer can set the
// modification time back but not the change time.
func statMeta(info fs.FileInfo) string {
	st, ok := info.Sys().(*unix.Stat_t)
	if !ok {
		return fmt.Sprintf("%d|%o|%d", info.Size(), info.Mode(), info.ModTime().UnixNano())
	}
	return fmt.Sprintf("%d|%o|%d|%d.%d|%d", info.Size(), info.Mode(), info.ModTime().UnixNano(),
		st.Ctim.Sec, st.Ctim.Nsec, st.Ino) //nolint:unconvert // field types differ per OS
}
