package tool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteSecretFile writes data to a new file name in dir (the task's
// Workdir), readable and writable by the task's own user only (0600). It
// refuses a name with a path separator and a file that already exists (a
// planted file or symbolic link is never followed or reused: O_EXCL). For a
// tool that hands a credential to a program as a file (a provider
// configuration): the directory, and the file with it, is removed when the
// task ends, whether it succeeded, failed or was canceled. Never put a
// credential in an environment variable or an argument instead.
func WriteSecretFile(dir, name string, data []byte) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`+"\x00") {
		return "", errors.New("tool: secret file: invalid name")
	}
	if dir == "" {
		return "", errors.New("tool: secret file: no task directory")
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path is a base name joined to the task's own directory
	if err != nil {
		return "", fmt.Errorf("tool: secret file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("tool: secret file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("tool: secret file: %w", err)
	}
	return path, nil
}
