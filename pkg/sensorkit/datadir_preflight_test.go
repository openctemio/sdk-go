package sensorkit

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheckDataDirsCreatesAndAccepts(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "outbox"), filepath.Join(root, "x", "content")
	if err := CheckDataDirs(a, b); err != nil {
		t.Fatalf("writable root: %v", err)
	}
	for _, d := range []string{a, b} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Fatalf("%s not created: %v", d, err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(a, ".preflight-*")); len(m) != 0 {
		t.Fatalf("probe file left behind: %v", m)
	}
}

func TestCheckDataDirsReadOnlyRoot(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a non-root unix user")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	err := CheckDataDirs(filepath.Join(root, "content"))
	var p *DataDirProblem
	if !errors.As(err, &p) {
		t.Fatalf("want *DataDirProblem, got %v", err)
	}
	if p.Blocked != root || p.OwnerUID != os.Getuid() || p.UID != os.Getuid() {
		t.Fatalf("problem = %+v", p)
	}
	msg := err.Error()
	for _, want := range []string{
		filepath.Join(root, "content"), "permission denied", "uid", "chown -R", "named volume", DataDirDocsURL,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("cause not unwrapped: %v", err)
	}
}

func TestCheckDataDirsFileInTheWay(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "state")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := CheckDataDirs(f)
	var p *DataDirProblem
	if !errors.As(err, &p) || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("got %v", err)
	}
}

func TestDataDirsFromEnvironment(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvOutboxDir, filepath.Join(root, "out", "outbox"))
	t.Setenv(EnvStateDir, filepath.Join(root, "st"))
	t.Setenv(EnvStoreDir, "")
	t.Setenv(EnvWorkspaceDir, "")
	got := DataDirs(filepath.Join(root, "c"))
	want := []string{
		filepath.Join(root, "out", "outbox"),
		filepath.Join(root, "st"),
		filepath.Join(root, "out", "store"),
		filepath.Join(root, "out", "workspaces"),
		filepath.Join(root, "c"),
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("DataDirs = %v, want %v", got, want)
	}
	if err := PreflightDataDirs(filepath.Join(root, "c")); err != nil {
		t.Fatal(err)
	}
}
