//go:build !unix

package core

import "os"

func peakRSSBytes(*os.ProcessState) int64 { return 0 }

func killedBySIGKILL(*os.ProcessState) bool { return false }
