package chunk

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewStorage_PrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}

	t.Run("new directory and database", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "queue")
		cfg := DefaultConfig()
		cfg.DatabasePath = filepath.Join(dir, "chunks.db")
		s, err := NewStorage(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		assertMode(t, dir, 0o700)
		assertMode(t, cfg.DatabasePath, 0o600)
		for _, side := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(cfg.DatabasePath + side); err == nil {
				assertMode(t, cfg.DatabasePath+side, 0o600)
			}
		}
	})

	t.Run("existing world-readable database tightened", func(t *testing.T) {
		dir := t.TempDir()
		cfg := DefaultConfig()
		cfg.DatabasePath = filepath.Join(dir, "chunks.db")
		if err := os.WriteFile(cfg.DatabasePath, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		s, err := NewStorage(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		assertMode(t, cfg.DatabasePath, 0o600)
	})
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}
