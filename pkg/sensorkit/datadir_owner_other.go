//go:build !unix

package sensorkit

import "io/fs"

// dirOwner: ownership is not reported outside unix.
func dirOwner(fs.FileInfo) (uid, gid int, ok bool) { return -1, -1, false }
