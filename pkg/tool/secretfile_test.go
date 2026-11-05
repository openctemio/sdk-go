package tool

import (
	"os"
	"path/filepath"
	"testing"
)

// SECURITY: a secret file is 0600 and new: an existing file or a planted
// symbolic link is refused, never written through; a name never leaves the
// directory.
func TestWriteSecretFile(t *testing.T) {
	dir := t.TempDir()
	p, err := WriteSecretFile(dir, "provider.yaml", []byte("k: secret-value-123"))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	if _, err := WriteSecretFile(dir, "provider.yaml", []byte("again")); err == nil {
		t.Fatal("an existing file was overwritten")
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Symlink(victim, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteSecretFile(dir, "link", []byte("x")); err == nil {
		t.Fatal("a symbolic link was followed")
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("the link target was created")
	}
	for _, bad := range []string{"", ".", "..", "../x", "a/b"} {
		if _, err := WriteSecretFile(dir, bad, nil); err == nil {
			t.Fatalf("name %q accepted", bad)
		}
	}
}
