//go:build unix

package executor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SECURITY: a sensor that crashed leaves task directories (with what its
// tools wrote) behind; the start-up sweep removes those of instances that
// no longer run and old unmarked ones, and never a running instance's.
func TestSweepStaleTaskDirs(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	root := TaskRoot()
	mine, err := NewTaskDir("tool-")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(mine); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("task dir %v %v", fi, err)
	}
	// A dead instance: its owner file exists, nobody holds its lock.
	deadID := "00000000000000aa"
	if err := os.WriteFile(filepath.Join(root, ownerFilePrefix+deadID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dead := filepath.Join(root, "tool-.i"+deadID+".123")
	// A running instance: another holder of its owner file's lock.
	liveID := "00000000000000bb"
	live := filepath.Join(root, "tool-.i"+liveID+".456")
	lock := lockOwnerFile(filepath.Join(root, ownerFilePrefix+liveID))
	if lock == nil {
		t.Fatal("cannot lock")
	}
	defer lock.Close()
	// An instance whose owner file is gone.
	orphan := filepath.Join(root, "egress-.i00000000000000cc.789")
	oldUnmarked := filepath.Join(root, "tool-old")
	newUnmarked := filepath.Join(root, "tool-new")
	for _, d := range []string{dead, live, orphan, oldUnmarked, newUnmarked} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "provider.yaml"), []byte("k: v"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleUnmarkedAge)
	if err := os.Chtimes(oldUnmarked, old, old); err != nil {
		t.Fatal(err)
	}
	n, err := SweepStaleTaskDirs()
	if err != nil || n != 3 {
		t.Fatalf("removed %d (%v)", n, err)
	}
	for _, d := range []string{dead, orphan, oldUnmarked} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("%s kept", d)
		}
	}
	for _, d := range []string{mine, live, newUnmarked} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("%s removed", d)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ownerFilePrefix+deadID)); !os.IsNotExist(err) {
		t.Fatal("the dead instance's owner file was kept")
	}
}
