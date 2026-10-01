//go:build windows

package outbox

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// syncDir is a no-op: Windows cannot fsync a directory; NTFS journals the
// rename itself.
func syncDir(string) error { return nil }

// lockDir takes an exclusive, non-blocking LockFileEx lock on path. It dies
// with the process.
func lockDir(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, fileMode) //nolint:gosec // outbox directory
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		_ = f.Close()
	}, nil
}

// freeBytes returns the bytes available to the caller on dir's volume.
func freeBytes(dir string) (uint64, bool) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, false
	}
	return avail, true
}
