//go:build !unix

package workspace

import "os"

func ownedByOther(os.FileInfo) bool { return false }

func noexec(string) (on, known bool) { return false, false }
