//go:build unix

package sensorkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The sensor creates its directories on a fresh data volume (a bind mount
// or a Kubernetes volume does not get the image's directories) and keeps an
// existing one private to its user.
func TestSecurePrivateDir(t *testing.T) {
	root := t.TempDir()

	missing := filepath.Join(root, "data", "state")
	if w := securePrivateDir(missing); w != "" {
		t.Fatalf("create: %s", w)
	}
	if fi, err := os.Stat(missing); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("created %v %v, want a 0700 directory", fi, err)
	}

	loose := filepath.Join(root, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if w := securePrivateDir(loose); w != "" {
		t.Fatalf("narrow: %s", w)
	}
	if fi, _ := os.Stat(loose); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %04o, want 0700", fi.Mode().Perm())
	}

	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if w := securePrivateDir(file); !strings.Contains(w, "not a directory") {
		t.Fatalf("a file must be reported, got %q", w)
	}
	if w := securePrivateDir(""); w != "" {
		t.Fatalf("empty: %q", w)
	}
}

// A state directory another user owns is reported with the fix (run as
// root, where chown to another uid works).
func TestSecurePrivateDir_OtherOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to give a directory to another user")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if w := securePrivateDir(dir); !strings.Contains(w, "owned by uid 12345") || !strings.Contains(w, "chown") {
		t.Fatalf("got %q", w)
	}
}
