//go:build !unix

package contentcache

import (
	"fmt"
	"io/fs"
)

// statMeta is the file metadata a load check compares (no change time on
// this platform: size, mode and modification time).
func statMeta(info fs.FileInfo) string {
	return fmt.Sprintf("%d|%o|%d", info.Size(), info.Mode(), info.ModTime().UnixNano())
}
