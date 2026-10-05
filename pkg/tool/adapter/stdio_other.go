//go:build !unix

package adapter

import "os"

// protectStdout returns stdout as it is where descriptors cannot be moved.
func protectStdout() (*os.File, error) { return os.Stdout, nil }

func makeUndumpable() {}
