//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A task cannot read another task's directory: concurrent tasks (on a
// shared sensor, tasks of different tenants) see only their own files.
func TestTaskCannotReadSiblingTask(t *testing.T) {
	b := newTestBackend(t)
	other, err := b.Prepare(TaskSpec{ID: "other", Argv: []string{"/bin/true"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Cleanup() }()
	secret := filepath.Join(other.Workdir(), "repo-secret.txt")
	if err := os.WriteFile(secret, []byte("tenant-b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "reader"}, "read", secret); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("a task read a sibling task's file: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "lister"}, "list", filepath.Dir(other.Workdir())); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("a task listed the task root: %q", out)
	}
}

// A directory made with NewTaskDir (the tool host's protocol directory) is
// hidden from every task too, whatever the backend's own WorkRoot.
func TestTaskCannotReadNewTaskDir(t *testing.T) {
	b := newTestBackend(t)
	dir, err := NewTaskDir("isolation-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	secret := filepath.Join(dir, "result.json")
	if err := os.WriteFile(secret, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "reader"}, "read", secret); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("a task read another task's tool directory: %q", out)
	}
	// The task that owns it (its working and write path) still uses it.
	if out, _ := runTool(t, b, TaskSpec{ID: "owner", Dir: dir, WritePaths: []string{dir}}, "read", secret); out != "OK" {
		t.Fatalf("the owning task could not read its directory: %q", out)
	}
}

// A task root is this process's own and closed to other users; a symbolic
// link someone could have planted is refused.
func TestTaskRootMustBePrivate(t *testing.T) {
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(open); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(open); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("task root left open to other users: %v %v", fi.Mode().Perm(), err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(link); err == nil {
		t.Fatal("a symbolic link was accepted as a task root")
	}
	b, err := NewProcessBackend(Config{Mode: ModeOff, WorkRoot: open})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Prepare(TaskSpec{Argv: []string{"/bin/true"}}); err != nil {
		t.Fatalf("ModeOff runs in the caller's directory and makes no task root: %v", err)
	}
}

// A task still reads and writes its own directory, by relative and
// absolute path.
func TestTaskUsesOwnWorkdir(t *testing.T) {
	b := newTestBackend(t)
	if out, _ := runTool(t, b, TaskSpec{ID: "self"}, "write", "own.txt"); out != "OK" {
		t.Fatalf("own workdir write: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "selfread"}, "roundtrip"); out != "OK" {
		t.Fatalf("own workdir read back: %q", out)
	}
}

// SECURITY: a content pack under a private root (the sensor content
// cache) is readable only by the task granted it: another tenant task, or
// the same task for another pack, cannot read it.
func TestReadPathsUnderAPrivateRoot(t *testing.T) {
	cache := t.TempDir()
	mine := filepath.Join(cache, "sha256-aaaa")
	theirs := filepath.Join(cache, "sha256-bbbb")
	for _, d := range []string{mine, theirs} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "t.yaml"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := NewProcessBackend(Config{Mode: ModeRequired, WorkRoot: t.TempDir(), Limits: Limits{Processes: 64}, Private: []string{cache}})
	if err != nil {
		t.Skipf("sandbox not available here: %v", err)
	}
	spec := TaskSpec{ID: "reader", ReadPaths: []string{mine}}
	if out, _ := runTool(t, b, spec, "read", filepath.Join(mine, "t.yaml")); out != "OK" {
		t.Fatalf("granted pack unreadable: %q", out)
	}
	if out, _ := runTool(t, b, spec, "read", filepath.Join(theirs, "t.yaml")); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("a pack not granted was read: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "other"}, "read", filepath.Join(mine, "t.yaml")); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("a task without the grant read the pack: %q", out)
	}
	if out, _ := runTool(t, b, spec, "write", filepath.Join(mine, "t.yaml")); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("a granted pack was writable: %q", out)
	}
}
