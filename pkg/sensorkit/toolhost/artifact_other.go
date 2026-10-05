//go:build !unix

package toolhost

import "os"

func openNoFollow(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrPermission
	}
	return os.Open(path)
}
