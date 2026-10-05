package adapter

import "golang.org/x/sys/unix"

// makeUndumpable keeps another task under the same user from reading this
// process's memory (its credentials) through /proc.
func makeUndumpable() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
