package executor

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A path the launcher listed that is gone when its rule is added (a
// sibling task's temporary file in /tmp) is skipped instead of failing the
// task; existing paths still get their rule.
func TestAddReadableSkipsVanishedPaths(t *testing.T) {
	attr := unix.LandlockRulesetAttr{Access_fs: uint64(llReadFile | llReadDir)}
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0) //nolint:gosec // landlock ABI
	if e != 0 {
		t.Skipf("landlock unavailable: %v", e)
	}
	defer func() { _ = unix.Close(int(fd)) }()
	dir := t.TempDir()
	gone := filepath.Join(dir, "gone")
	if err := addReadable(int(fd), []string{dir, gone}, uint64(llReadFile|llReadDir)); err != nil {
		t.Fatalf("a vanished path failed the ruleset: %v", err)
	}
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Fatal("test setup")
	}
}
