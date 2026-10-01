package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// setup copies testdata/<name> to a temp dir, pointing its replace directive
// at the stub of the old SDK API.
func setup(t *testing.T, name string) string {
	t.Helper()
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOPROXY", "off")
	oldSDK, err := filepath.Abs("testdata/oldsdk")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), name)
	copyDir(t, filepath.Join("testdata", name), dst)
	gomod := filepath.Join(dst, "go.mod")
	b, err := os.ReadFile(gomod)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, gomod, strings.ReplaceAll(string(b), "OLDSDK", oldSDK))
	return dst
}

func TestMigrateFixture(t *testing.T) {
	dir := setup(t, "fixture")
	orig := readFile(t, filepath.Join(dir, "main.go"))

	// -dry-run prints the diff and changes nothing.
	var out, errb bytes.Buffer
	if code := run([]string{"-dir", dir, "-dry-run"}, &out, &errb); code != 0 {
		t.Fatalf("dry run exit %d: %s", code, errb.String())
	}
	for _, want := range []string{
		"-\t*core.BaseAgent", "+\t*core.BaseSensor",
		"+\tm := &myAgent{BaseSensor: core.NewBaseSensor(cfg, nil), agentNote: \"n\"}",
		"+\t_ = client.NewWithOptions(client.WithSensorID(\"s-1\"))",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry-run diff lacks %q:\n%s", want, out.String())
		}
	}
	if got := readFile(t, filepath.Join(dir, "main.go")); got != orig {
		t.Fatal("-dry-run modified the file")
	}

	// Rewrite.
	out.Reset()
	errb.Reset()
	if code := run([]string{"-dir", dir, "-sdk-version", "none"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := readFile(t, filepath.Join(dir, "main.go"))
	want := readFile(t, "testdata/fixture.want.go")
	if got != want {
		t.Fatalf("migrated fixture differs from testdata/fixture.want.go:\n%s", got)
	}

	// Build the result against the real, renamed SDK (this repository): the
	// "upgrade the SDK" step, done offline with a replace directive.
	useRealSDK(t, dir)
	build := exec.Command("go", "build", "./...")
	build.Dir = dir
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("migrated fixture does not build against the new SDK: %v\n%s", err, b)
	}

	// Idempotent: on the upgraded module there is nothing left to rename.
	out.Reset()
	errb.Reset()
	if code := run([]string{"-dir", dir, "-sdk-version", "none"}, &out, &errb); code != 0 {
		t.Fatalf("second run exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "nothing to rename") {
		t.Fatalf("second run output %q", out.String())
	}
	if again := readFile(t, filepath.Join(dir, "main.go")); again != got {
		t.Fatal("second run changed the file")
	}
}

func TestMigrateRefusesConflicts(t *testing.T) {
	dir := setup(t, "conflict")
	orig := readFile(t, filepath.Join(dir, "main.go"))
	var out, errb bytes.Buffer
	if code := run([]string{"-dir", dir, "-sdk-version", "none"}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1 (conflict)", code)
	}
	if !strings.Contains(errb.String(), ".AgentID -> .SensorID collides") {
		t.Fatalf("stderr %q does not report the collision", errb.String())
	}
	if readFile(t, filepath.Join(dir, "main.go")) != orig {
		t.Fatal("a conflict must leave the code untouched")
	}
}

// useRealSDK points the module at this repository's SDK, with the SDK's own
// requirements and checksums so the build needs no network.
func useRealSDK(t *testing.T, dir string) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	sdkMod := readFile(t, filepath.Join(root, "go.mod"))
	var reqs []string
	in := false
	for _, l := range strings.Split(sdkMod, "\n") {
		switch {
		case strings.HasPrefix(l, "require ("):
			in = true
		case in && l == ")":
			in = false
		case in && strings.TrimSpace(l) != "":
			reqs = append(reqs, "\t"+strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(l), "// indirect")))
		}
	}
	gomod := "module example.com/fixture\n\ngo 1.26.0\n\nrequire (\n\tgithub.com/openctemio/sdk-go v0.6.0\n" +
		strings.Join(reqs, "\n") + "\n)\n\nreplace github.com/openctemio/sdk-go => " + root + "\n"
	writeFile(t, filepath.Join(dir, "go.mod"), gomod)
	writeFile(t, filepath.Join(dir, "go.sum"), readFile(t, filepath.Join(root, "go.sum")))
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		b, err := os.ReadFile(p) //nolint:gosec // test fixtures
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // test fixtures
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
