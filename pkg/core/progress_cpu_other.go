//go:build !linux

package core

// procTable: process CPU time is read on Linux only.
func procTable() map[int]procInfo { return nil }

func procStart(int) (uint64, bool) { return 0, false }
