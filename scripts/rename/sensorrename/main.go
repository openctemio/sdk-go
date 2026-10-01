// Command sensorrename performs the type-aware "agent" -> "sensor" rename of
// the SDK's own Go code (RFC-023 §9.5). It is driven by
// scripts/rename/sensor-rename.sh and is safe to re-run: on a tree that is
// already renamed it changes nothing.
//
// It renames identifiers (types, funcs, methods, fields, consts, vars,
// params, labels, package names), comments, and the files with "agent" in
// their name (git mv, so history follows). It never changes string literals
// or struct tags: those are the frozen protocol v1 wire and persisted
// formats, handled by hand in pkg/sensorproto/legacyv1 and its callers. See
// internal/sensorrename for how identifiers are resolved.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openctemio/sdk-go/internal/sensorrename"
)

func main() {
	dir := flag.String("dir", ".", "module root")
	dry := flag.Bool("dry-run", false, "report only, do not write")
	flag.Parse()

	root, err := filepath.Abs(*dir)
	must(err)

	pkgs, err := sensorrename.Load(root)
	must(err)

	res := sensorrename.Collect(pkgs, sensorrename.Options{
		Target:   func(p string) bool { return sensorrename.InModule(sensorrename.SDKModule, p) },
		SkipFile: func(f string) bool { return skipFile(root, f) },
		Comments: true,
	})
	if len(res.Conflicts) > 0 {
		for _, c := range res.Conflicts {
			fmt.Fprintln(os.Stderr, "conflict:", c)
		}
		fail(fmt.Sprintf("%d conflicts; nothing written", len(res.Conflicts)))
	}

	fmt.Printf("sensorrename: %d edits in %d files\n", res.Count(), len(res.Edits))
	for _, f := range res.Files() {
		_, out, err := sensorrename.Apply(f, res.Edits[f])
		must(err)
		if *dry {
			rel, _ := filepath.Rel(root, f)
			fmt.Printf("  %s (%d)\n", rel, len(res.Edits[f]))
			continue
		}
		must(os.WriteFile(f, out, 0o644)) //nolint:gosec // source files are world-readable
	}
	if !*dry {
		must(movePaths(root))
	}
}

// skipFile excludes the rename tooling, the codemod (which names the old
// SDK identifiers on purpose) and the legacy protocol v1 package itself (its
// goldentest subpackage is renamed like any other caller).
func skipFile(root, file string) bool {
	rel, err := filepath.Rel(root, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return true // outside the module, e.g. a generated test main in the build cache
	}
	rel = filepath.ToSlash(rel)
	return strings.HasPrefix(rel, "scripts/rename/") ||
		strings.HasPrefix(rel, "internal/sensorrename/") ||
		strings.HasPrefix(rel, "cmd/sensor-migrate/") ||
		filepath.ToSlash(filepath.Dir(rel)) == "pkg/sensorproto/legacyv1"
}

// shouldMove limits path renames to Go files the SDK owns. The protocol v1
// schema (proto/openctemio/v1/agent.proto) keeps its name: the gRPC service
// and message names in it are wire.
func shouldMove(f string) bool {
	if !strings.Contains(strings.ToLower(f), "agent") || !strings.HasSuffix(f, ".go") {
		return false
	}
	switch {
	case strings.HasPrefix(f, "scripts/rename/"),
		strings.HasPrefix(f, "internal/sensorrename/"),
		strings.HasPrefix(f, "cmd/sensor-migrate/"),
		strings.Contains(f, "/testdata/"):
		return false
	}
	return true
}

// movePaths renames tracked Go files whose path contains "agent", with git mv
// so history follows the file.
func movePaths(root string) error {
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		return err
	}
	var srcs []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if shouldMove(f) && sensorrename.RenamePath(f) != f {
			srcs = append(srcs, f)
		}
	}
	sort.Strings(srcs)
	for _, from := range srcs {
		to := sensorrename.RenamePath(from)
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(to)), 0o755); err != nil { //nolint:gosec // repo dirs
			return err
		}
		cmd := exec.Command("git", "-C", root, "mv", from, to) //nolint:gosec // paths come from git ls-files
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git mv %s %s: %w: %s", from, to, err, stderr.String())
		}
	}
	fmt.Printf("sensorrename: moved %d files\n", len(srcs))
	return nil
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "sensorrename:", msg)
	os.Exit(1)
}
