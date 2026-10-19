//go:build unix

package localstore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func sameDevice(t *testing.T, a, b string) bool {
	t.Helper()
	fa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return fa.Sys().(*syscall.Stat_t).Dev == fb.Sys().(*syscall.Stat_t).Dev
}

// TestKeyFileOnAnotherVolume: a KeyFile on another file system than the
// store (the recommended setup: a tmpfs or a mounted secret) is created
// there; a temporary file in the store's tmp/ could not be linked or renamed
// across devices.
func TestKeyFileOnAnotherVolume(t *testing.T) {
	dir := t.TempDir()
	keyDir, err := os.MkdirTemp("/dev/shm", "lskey")
	if err != nil {
		t.Skip("no /dev/shm")
	}
	t.Cleanup(func() { _ = os.RemoveAll(keyDir) })
	if sameDevice(t, dir, keyDir) {
		t.Skip("/dev/shm is on the same device as the temp dir")
	}
	kf := filepath.Join(keyDir, "store.key")
	s := openT(t, dir, func(o *Options) { o.KeyFile = kf; o.CreateKey = true })
	kv := kvT(t, s, SensorTenant, "ns")
	if err := kv.Put("a", []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	entries, _ := os.ReadDir(keyDir)
	if len(entries) != 1 {
		t.Fatalf("key dir holds %d entries, want only the key", len(entries))
	}
	s = openT(t, dir, func(o *Options) { o.KeyFile = kf })
	if got, err := kvT(t, s, SensorTenant, "ns").Get("a"); err != nil || string(got) != "x" {
		t.Fatalf("reopen: %q %v", got, err)
	}
}
