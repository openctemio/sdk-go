//go:build !linux

package sensorkit

func writeSelfOOMScoreAdj(int) error { return errOOMUnsupported }
