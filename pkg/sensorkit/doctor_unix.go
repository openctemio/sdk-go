//go:build unix

package sensorkit

import "golang.org/x/sys/unix"

// dirWritable reports whether this user may create files in dir.
func dirWritable(dir string) bool { return unix.Access(dir, unix.W_OK) == nil }
