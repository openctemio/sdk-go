//go:build !unix

package identity

import "io/fs"

// checkAccess: where the OS has no uid and mode bits (Windows), access is
// governed by the ACL of the state directory, which the installer sets;
// nothing is checked here.
func checkAccess(string, fs.FileInfo, bool) error { return nil }
