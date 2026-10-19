package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreatePrivateAndIsolated(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "work"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Create("tenant-a", "cmd-1", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Create("tenant-b", "cmd-1", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	a2, err := m.Create("tenant-a", "cmd-1", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Dir() == a2.Dir() || a.Dir() == b.Dir() {
		t.Fatal("two jobs share a directory")
	}
	if !strings.HasPrefix(a.Dir(), filepath.Join(m.Root(), "tenant-a")+string(os.PathSeparator)) ||
		!strings.HasPrefix(b.Dir(), filepath.Join(m.Root(), "tenant-b")+string(os.PathSeparator)) {
		t.Fatalf("not under the tenant: %s %s", a.Dir(), b.Dir())
	}
	for _, d := range []string{m.Root(), filepath.Dir(a.Dir()), a.Dir()} {
		fi, _ := os.Stat(d)
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %04o", d, fi.Mode().Perm())
		}
	}
	if err := os.WriteFile(filepath.Join(a.Dir(), "f"), []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	_ = os.Mkdir(filepath.Join(a.Dir(), "ro"), 0o500)
	if err := a.Close(); err != nil {
		t.Fatalf("close with read-only content: %v", err)
	}
	if _, err := os.Stat(a.Dir()); !os.IsNotExist(err) {
		t.Fatal("workspace not removed")
	}
	if err := a.Close(); err != nil {
		t.Fatal("second close failed")
	}
}

func TestInvalidNamesAndSymlinkTenant(t *testing.T) {
	root := filepath.Join(t.TempDir(), "work")
	m, _ := Open(root)
	for _, n := range []string{"", "..", "../x", "a/b", ".h"} {
		if _, err := m.Create(n, "job", Limits{}); !errors.Is(err, ErrInvalidName) {
			t.Errorf("tenant %q accepted", n)
		}
		if _, err := m.Create("t", n, Limits{}); !errors.Is(err, ErrInvalidName) {
			t.Errorf("job %q accepted", n)
		}
	}
	// A tenant directory replaced by a link elsewhere is refused.
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, "evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("evil", "job", Limits{}); !errors.Is(err, ErrNotPrivate) {
		t.Fatalf("symlinked tenant: %v", err)
	}
}

func TestSweepAfterCrash(t *testing.T) {
	root := filepath.Join(t.TempDir(), "work")
	m, _ := Open(root)
	left1, _ := m.Create("tenant-a", "cmd-1", Limits{})
	left2, _ := m.Create("tenant-b", "cmd-2", Limits{})
	_ = os.WriteFile(filepath.Join(left1.Dir(), "secret"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "stray"), []byte("x"), 0o600)
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600)
	_ = os.Symlink(outside, filepath.Join(root, "tenant-a", "link-1"))

	// A new process (the crash): the old directories are not live.
	m2, _ := Open(root)
	live, _ := m2.Create("tenant-a", "cmd-3", Limits{})
	n, err := m2.Sweep(func(tenant, job string) bool { return tenant == "tenant-b" && job == "cmd-2" })
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("removed %d, want 3 (cmd-1, the link, the stray file)", n)
	}
	if _, err := os.Stat(left1.Dir()); !os.IsNotExist(err) {
		t.Fatal("crashed job's directory kept")
	}
	if _, err := os.Stat(left2.Dir()); err != nil {
		t.Fatal("kept job removed")
	}
	if _, err := os.Stat(live.Dir()); err != nil {
		t.Fatal("live job removed")
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatal("sweep followed a symbolic link out of the root")
	}
}

func TestWatchQuota(t *testing.T) {
	m, _ := Open(filepath.Join(t.TempDir(), "work"))
	w, _ := m.Create("t", "cmd", Limits{MaxBytes: 1000})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exceeded := make(chan int64, 1)
	w.Watch(ctx, 10*time.Millisecond, func(used int64) { exceeded <- used })
	_ = os.WriteFile(filepath.Join(w.Dir(), "big"), make([]byte, 2000), 0o600)
	select {
	case used := <-exceeded:
		if used < 2000 {
			t.Fatalf("used %d", used)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("quota not reported")
	}
}

func TestEraseTenant(t *testing.T) {
	m, _ := Open(filepath.Join(t.TempDir(), "work"))
	a, _ := m.Create("tenant-a", "cmd-1", Limits{})
	b, _ := m.Create("tenant-b", "cmd-1", Limits{})
	if err := m.EraseTenant("tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.Dir()); !os.IsNotExist(err) {
		t.Fatal("tenant directory kept")
	}
	if _, err := os.Stat(b.Dir()); err != nil {
		t.Fatal("other tenant removed")
	}
}

func TestRootNarrowed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "work")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(m.Root())
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("root mode %04o", fi.Mode().Perm())
	}
	if _, known := m.Noexec(); !known {
		t.Log("noexec unknown on this platform")
	}
}

func TestSweepBoundedByLimitAndContext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "work")
	m, _ := Open(root)
	for i := range 5 {
		w, _ := m.Create("tenant-a", "cmd-"+string(rune('a'+i)), Limits{})
		_ = os.WriteFile(filepath.Join(w.Dir(), "f"), []byte("data"), 0o600)
	}
	m2, _ := Open(root) // a new process: all five are orphans
	n, err := m2.SweepBounded(context.Background(), nil, 2)
	if err != nil || n != 2 {
		t.Fatalf("limit: %d %v", n, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := m2.SweepBounded(ctx, nil, 0); n != 0 || err == nil {
		t.Fatalf("canceled: %d %v", n, err)
	}
	if n, _ := m2.SweepBounded(context.Background(), nil, 0); n != 3 {
		t.Fatalf("rest: %d", n)
	}
}

func TestBytesCountsAllJobs(t *testing.T) {
	m, _ := Open(filepath.Join(t.TempDir(), "work"))
	a, _ := m.Create("tenant-a", "cmd-1", Limits{})
	b, _ := m.Create("tenant-b", "cmd-1", Limits{})
	_ = os.WriteFile(filepath.Join(a.Dir(), "f"), make([]byte, 1000), 0o600)
	_ = os.WriteFile(filepath.Join(b.Dir(), "f"), make([]byte, 500), 0o600)
	if got := m.Bytes(); got != 1500 {
		t.Fatalf("bytes %d", got)
	}
}
