package executor

import (
	"fmt"
	"os"
	"path/filepath"
)

// TaskRoot is the directory private task directories are made under by
// default (<os.TempDir()>/openctem-tasks). The process backend hides it,
// and its own WorkRoot, from every task: a task reads and writes its own
// directory and cannot read or list a sibling's, whether the sibling is a
// task of the same tenant or, on a shared sensor, of another.
func TaskRoot() string { return filepath.Join(os.TempDir(), "openctem-tasks") }

// NewTaskDir makes a new private directory (0700) under TaskRoot for a
// caller that keeps a task's files outside the backend's own directory (the
// tool host's protocol directory).
func NewTaskDir(prefix string) (string, error) {
	root := TaskRoot()
	if err := ensurePrivateDir(root); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, prefix)
	if err != nil {
		return "", fmt.Errorf("executor: task directory: %w", err)
	}
	return dir, nil
}

// ensurePrivateDir makes dir (0700) when it is missing, refuses a symbolic
// link or another user's directory (a shared temporary directory lets
// anyone create the name first), and closes one this process owns to other
// users.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("executor: task root: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("executor: task root: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("executor: task root %s is not a directory", dir)
	}
	if err := checkOwner(dir, fi); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // dir is this process's own, checked above
			return fmt.Errorf("executor: task root %s: %w", dir, err)
		}
	}
	return nil
}
