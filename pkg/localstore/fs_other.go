//go:build !unix && !windows

package localstore

import "os"

// syncDir is a no-op on platforms without directory fsync.
func syncDir(string) error { return nil }

// lockDir does not lock on this platform: run one process per store.
func lockDir(string) (func(), error) { return func() {}, nil }

// diskSpace is not implemented here; the disk guard reports "unknown".
func diskSpace(string) (space, bool) { return space{}, false }

// fileOwnedByOther is not checked on this platform.
func fileOwnedByOther(os.FileInfo) bool { return false }
