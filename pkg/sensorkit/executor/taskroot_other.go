//go:build !unix

package executor

import "os"

// checkOwner has no owner to compare off Unix.
func checkOwner(string, os.FileInfo) error { return nil }
