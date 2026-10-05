//go:build linux && !amd64 && !arm64

package executor

import "errors"

var errSeccompUnsupported = errors.New("seccomp unsupported")

// applySeccomp: no filter for this architecture (reported as missing).
func applySeccomp() error { return errSeccompUnsupported }
