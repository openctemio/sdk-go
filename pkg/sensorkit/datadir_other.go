//go:build !unix

package sensorkit

import "io/fs"

// ownedBySensorUser: ownership is not checked outside unix.
func ownedBySensorUser(fs.FileInfo) (int, bool) { return -1, true }
