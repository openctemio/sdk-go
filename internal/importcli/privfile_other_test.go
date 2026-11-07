//go:build !windows

package importcli

import (
	"os"
	"path/filepath"
	"testing"
)

func assertPrivate(t *testing.T, path string, st os.FileInfo) {
	t.Helper()
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("%s: mode %v, want 0600", path, st.Mode().Perm())
	}
}

func TestWriteFile_TightensAnExistingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	assertPrivate(t, p, st)
}
