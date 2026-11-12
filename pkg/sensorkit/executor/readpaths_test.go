package executor

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A job's read grants are carried by its context: added, deduplicated,
// never shared with a sibling context, and handed out as a copy.
func TestReadPathsTravelWithTheJobContext(t *testing.T) {
	base := context.Background()
	if got := ReadPathsFrom(base); got != nil {
		t.Fatalf("an empty context grants %v", got)
	}
	a := WithReadPaths(base, "/t/a", "", "/t/a")
	b := WithReadPaths(base, "/t/b")
	a2 := WithReadPaths(a, "/t/a2")
	if got := ReadPathsFrom(a2); !slices.Equal(got, []string{"/t/a", "/t/a2"}) {
		t.Fatalf("a2 grants %v", got)
	}
	if got := ReadPathsFrom(a); !slices.Equal(got, []string{"/t/a"}) {
		t.Fatalf("a child's grant leaked into its parent: %v", got)
	}
	if got := ReadPathsFrom(b); !slices.Equal(got, []string{"/t/b"}) {
		t.Fatalf("b grants %v", got)
	}
	got := ReadPathsFrom(a)
	got[0] = "/"
	if ReadPathsFrom(a)[0] != "/t/a" {
		t.Fatal("the returned slice aliases the context's")
	}
	if WithReadPaths(a) != a {
		t.Fatal("no paths must return the same context")
	}
}

// NewJobDir makes a private directory under the task root and grants it.
func TestNewJobDirIsPrivateAndGranted(t *testing.T) {
	ctx, dir, err := NewJobDir(context.Background(), "jobdir-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if filepath.Dir(dir) != TaskRoot() {
		t.Fatalf("%s is not directly under the task root %s", dir, TaskRoot())
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v, err %v", fi.Mode().Perm(), err)
	}
	if got := ReadPathsFrom(ctx); !slices.Equal(got, []string{dir}) {
		t.Fatalf("grants %v", got)
	}
}
