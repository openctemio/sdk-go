//go:build unix

package identity

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkAccess refuses a path that does not belong to the user the sensor
// runs as, or that its group or others may read, write or enter.
func checkAccess(path string, fi fs.FileInfo, dir bool) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if uid := os.Getuid(); int(st.Uid) != uid {
			return &PermissionError{Path: path, Reason: fmt.Sprintf("is owned by uid %d, not by the sensor's user (uid %d)", st.Uid, uid),
				Fix: fmt.Sprintf("chown %d %s", uid, path)}
		}
	}
	allowed := fileMode
	if dir {
		allowed = dirMode
	}
	if fi.Mode().Perm()&^allowed != 0 {
		return &PermissionError{Path: path, Reason: fmt.Sprintf("has mode %04o (group or others have access)", fi.Mode().Perm()),
			Fix: fmt.Sprintf("chmod %04o %s", allowed, path)}
	}
	return nil
}
