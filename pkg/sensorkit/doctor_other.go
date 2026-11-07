//go:build !unix

package sensorkit

// dirWritable is not checked on this system: the start-up's own write
// shows it.
func dirWritable(string) bool { return true }
