//go:build unix

package outbox

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// syncDir fsyncs a directory so a rename or removal in it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // outbox directory
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, unix.EINVAL) {
		// EINVAL: the file system does not support fsync on directories.
		return err
	}
	return nil
}

// lockDir takes an exclusive, non-blocking flock on path. The returned
// function releases it. The lock dies with the process, so a kill -9 never
// leaves the directory locked.
func lockDir(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, fileMode) //nolint:gosec // outbox directory
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd()) //nolint:gosec // a file descriptor fits in int
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("outbox: lock: %w", err)
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// freeBytes returns the bytes available to an unprivileged user on the file
// system holding dir, or ok=false when it cannot tell.
func freeBytes(dir string) (uint64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true //nolint:gosec,unconvert // non-negative; field types differ per OS
}
