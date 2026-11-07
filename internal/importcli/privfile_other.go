//go:build !windows

package importcli

import "os"

// createPrivate creates or truncates a file only its owner can read (mode
// 0600 on creation; an existing file is set to 0600 first).
func createPrivate(path string) (*os.File, error) {
	if _, err := os.Lstat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the user names the file
}
