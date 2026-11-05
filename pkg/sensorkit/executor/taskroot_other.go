//go:build !unix

package executor

import "os"

// checkOwner has no owner to compare off Unix.
func checkOwner(string, os.FileInfo) error { return nil }

// lockOwnerFile has no lock off Unix: the owner file only marks the
// instance.
func lockOwnerFile(path string) *os.File {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // a file under the private task root
	if err != nil {
		return nil
	}
	return f
}

// ownerFileGone cannot tell off Unix whether an instance runs: only a
// missing owner file is gone.
func ownerFileGone(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}
