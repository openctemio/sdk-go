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

// lockOwnerFile creates path (0600) and holds an exclusive lock on it for
// the life of the process (nil when it cannot).
func lockOwnerFile(path string) *os.File {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // a file under the private task root
	if err != nil {
		return nil
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // an fd fits an int
		_ = f.Close()
		return nil
	}
	return f
}

// ownerFileGone reports whether the instance that owns path no longer
// runs: the file is missing, or nobody holds its lock.
func ownerFileGone(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // a file under the private task root
	if err != nil {
		return os.IsNotExist(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // an fd fits an int
		return false
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // an fd fits an int
	return true
}
