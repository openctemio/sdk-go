//go:build unix

package localstore

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// syncDir fsyncs a directory so a rename or removal in it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // a store directory
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

// lockDir takes an exclusive, non-blocking flock on path. The lock dies with
// the process, so a kill -9 never leaves the store locked.
func lockDir(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, fileMode) //nolint:gosec // the store's lock file
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd()) //nolint:gosec // a file descriptor fits in int
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("localstore: lock: %w", err)
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// diskSpace returns the bytes and inodes available to an unprivileged user
// on the file system holding dir, and their totals; ok=false when it cannot
// tell.
func diskSpace(dir string) (sp space, ok bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return space{}, false
	}
	bs := uint64(st.Bsize) //nolint:gosec,unconvert // non-negative; field types differ per OS
	return space{
		freeBytes:  uint64(st.Bavail) * bs, //nolint:unconvert // field types differ per OS
		totalBytes: uint64(st.Blocks) * bs, //nolint:unconvert // field types differ per OS
		freeFiles:  uint64(st.Ffree),       //nolint:gosec,unconvert // field types differ per OS
		totalFiles: uint64(st.Files),       //nolint:unconvert // field types differ per OS
	}, true
}

// fileOwnedByOther reports whether fi belongs to another user than the
// process's (a key file someone else can replace).
func fileOwnedByOther(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*unix.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) != os.Getuid() && os.Getuid() != 0
}
