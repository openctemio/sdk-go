//go:build unix

package sensorkit

import (
	"io/fs"
	"syscall"
)

// dirOwner reports the owner of fi; ok is false when the platform does not
// say.
func dirOwner(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat {
		return -1, -1, false
	}
	return int(st.Uid), int(st.Gid), true
}
