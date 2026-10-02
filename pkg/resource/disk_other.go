//go:build !unix

package resource

// diskFree is not measured on this system.
func diskFree(string) int64 { return 0 }
