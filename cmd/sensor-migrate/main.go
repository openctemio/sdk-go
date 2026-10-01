// Command sensor-migrate upgrades a Go module from the SDK's pre-sensor API
// (sdk-go v0.6 and older: core.BaseAgent, client.WithAgentID,
// platform.AgentCredentials, ...) to the sensor API (RFC-023 §9.5).
//
// Run it in the root of your module while it still builds against the old
// SDK:
//
//	go run github.com/openctemio/sdk-go/cmd/sensor-migrate@latest -dry-run   # show the diff
//	go run github.com/openctemio/sdk-go/cmd/sensor-migrate@latest            # rewrite + upgrade the SDK
//
// It type-checks your code (the go/packages loader gopls uses) and renames
// only identifiers that resolve to SDK objects: a variable of yours called
// `agent`, or your own type AgentPool, is never touched. It also renames
// the embedded field of a struct that embeds a renamed SDK type
// (x.BaseAgent -> x.BaseSensor). If a new name would collide with one of
// yours, it reports every collision and changes nothing. String literals,
// struct tags and comments are left alone.
//
// Files behind a build tag are only type-checked in a build that sets it:
// pass -tags once per extra build configuration (-tags platform, -tags
// "linux,cgo"). All configurations are checked against the old SDK before
// anything is written.
//
// After rewriting it runs `go get github.com/openctemio/sdk-go@<version>`,
// where version is the release the command was run from (@latest above) or
// -sdk-version. A second run on the upgraded module finds nothing to rename,
// so the command is idempotent.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/openctemio/sdk-go/internal/sensorrename"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sensor-migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "root of the module to migrate")
	dry := fs.Bool("dry-run", false, "print a unified diff and change nothing")
	sdkVersion := fs.String("sdk-version", "", "SDK version to upgrade to after rewriting (default: the version this command was built from; \"none\" skips the upgrade)")
	var tagSets multiFlag
	fs.Var(&tagSets, "tags", "an extra build configuration to rewrite, as a comma-separated build tag list (repeatable); the default build is always included")
	fs.Usage = func() {
		writef(stderr, "usage: sensor-migrate [-dry-run] [-dir path] [-sdk-version vX.Y.Z|none] [-tags t1,t2 ...] [packages]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	root, err := filepath.Abs(*dir)
	if err != nil {
		writeln(stderr, "sensor-migrate:", err)
		return 1
	}

	opts := sensorrename.Options{
		Target: func(p string) bool { return sensorrename.InModule(sensorrename.SDKModule, p) },
		SkipFile: func(f string) bool {
			rel, err := filepath.Rel(root, f)
			// Only files of the module being migrated: never the SDK in the
			// module cache, a replace target outside the module, or the
			// build cache.
			return err != nil || strings.HasPrefix(rel, "..")
		},
	}
	// Every build configuration is type-checked against the old SDK before
	// anything is written: a file shared by two configurations must not be
	// rewritten by the first while the second still needs the old names.
	res := &sensorrename.Result{Edits: map[string]map[int]sensorrename.Edit{}}
	for _, tags := range append([]string{""}, tagSets...) {
		pkgs, err := sensorrename.LoadTags(root, tags, fs.Args()...)
		if err != nil {
			if tags != "" {
				writef(stderr, "sensor-migrate: build tags %q: ", tags)
			}
			writeln(stderr, "sensor-migrate:", err)
			writeln(stderr, "sensor-migrate: run it while the module still builds against the old SDK; if it was already migrated, upgrade the SDK with: go get github.com/openctemio/sdk-go@<version>")
			return 1
		}
		res.Merge(sensorrename.Collect(pkgs, opts))
	}
	if len(res.Conflicts) > 0 {
		for _, c := range res.Conflicts {
			writeln(stderr, "conflict:", c)
		}
		writef(stderr, "sensor-migrate: %d conflicts; nothing changed. Rename your identifiers above, then run again.\n", len(res.Conflicts))
		return 1
	}

	if res.Count() == 0 {
		writeln(stdout, "sensor-migrate: nothing to rename")
	} else {
		writef(stdout, "sensor-migrate: %d renames in %d files\n", res.Count(), len(res.Edits))
	}
	for _, f := range res.Files() {
		before, after, err := sensorrename.Apply(f, res.Edits[f])
		if err != nil {
			writeln(stderr, "sensor-migrate:", err)
			return 1
		}
		rel, _ := filepath.Rel(root, f)
		if *dry {
			write(stdout, sensorrename.UnifiedDiff(rel, before, after))
			continue
		}
		info, err := os.Stat(f)
		if err != nil {
			writeln(stderr, "sensor-migrate:", err)
			return 1
		}
		if err := os.WriteFile(f, after, info.Mode().Perm()); err != nil {
			writeln(stderr, "sensor-migrate:", err)
			return 1
		}
	}
	if *dry || res.Count() == 0 {
		return 0
	}

	version := *sdkVersion
	if version == "" {
		version = ownVersion()
	}
	if version == "" || version == "none" {
		writeln(stdout, "sensor-migrate: rewritten. Now upgrade the SDK: go get github.com/openctemio/sdk-go@<sensor release>")
		return 0
	}
	writef(stdout, "sensor-migrate: go get %s@%s\n", sensorrename.SDKModule, version)
	cmd := exec.Command("go", "get", sensorrename.SDKModule+"@"+version) //nolint:gosec // version is a flag or our own build info
	cmd.Dir = root
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			writef(stderr, "sensor-migrate: the code is rewritten but the SDK upgrade failed; run: go get %s@%s\n", sensorrename.SDKModule, version)
		}
		return 1
	}
	return 0
}

// ownVersion is the SDK version this command was built from when it was run
// as `go run github.com/openctemio/sdk-go/cmd/sensor-migrate@vX`, or "" for a
// development build.
func ownVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Main.Path != sensorrename.SDKModule {
		return ""
	}
	v := bi.Main.Version
	if v == "" || v == "(devel)" {
		return ""
	}
	return v
}

// Console output is best effort: a closed stdout must not change the outcome.
func writef(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

func writeln(w io.Writer, a ...any) { _, _ = fmt.Fprintln(w, a...) }

func write(w io.Writer, a ...any) { _, _ = fmt.Fprint(w, a...) }

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, " ") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
