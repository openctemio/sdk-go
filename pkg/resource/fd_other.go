//go:build !unix

package resource

func fdSoftLimit() uint64 { return 0 }
