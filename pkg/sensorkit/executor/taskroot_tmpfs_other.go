//go:build !linux

package executor

// TaskRootInMemory cannot tell off Linux (known false).
func TaskRootInMemory() (inMemory, known bool) { return false, false }
