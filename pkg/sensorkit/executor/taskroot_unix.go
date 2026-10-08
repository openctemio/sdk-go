//go:build unix

package executor

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwner refuses a directory another user owns.
func checkOwner(dir string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("executor: task root %s is owned by uid %d, not this process (uid %d)", dir, st.Uid, os.Getuid())
	}
	return nil
}
