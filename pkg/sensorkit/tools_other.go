//go:build !unix

package sensorkit

import (
	"fmt"
	"os"
)

// checkTrustedPath refuses a symbolic link; ownership and permission bits
// are left to the operating system's access control lists here.
func checkTrustedPath(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link", p)
	}
	return nil
}
