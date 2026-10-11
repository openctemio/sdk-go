//go:build unix

package sensorkit

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedBySensorUser reports the owner of fi and whether it is the user the
// sensor runs as.
func ownedBySensorUser(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, true
	}
	return int(st.Uid), int(st.Uid) == os.Getuid()
}
