//go:build unix

package sensorkit

import (
	"fmt"
	"os"
	"syscall"
)

// checkTrustedPath refuses a path another user could change: a symbolic
// link, a file or directory writable by group or others, or one owned by
// someone other than root or the sensor's user.
func checkTrustedPath(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link", p)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %v)", p, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if uid := int(st.Uid); uid != 0 && uid != os.Geteuid() {
			return fmt.Errorf("%s is owned by uid %d, not root or the sensor's user", p, uid)
		}
	}
	return nil
}
