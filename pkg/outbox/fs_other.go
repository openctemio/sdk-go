//go:build !unix && !windows

package outbox

// syncDir is a no-op on platforms without directory fsync.
func syncDir(string) error { return nil }

// lockDir does not lock on this platform: run one process per directory.
func lockDir(string) (func(), error) { return func() {}, nil }

// freeBytes is not implemented here; only the fixed byte cap applies.
func freeBytes(string) (uint64, bool) { return 0, false }
