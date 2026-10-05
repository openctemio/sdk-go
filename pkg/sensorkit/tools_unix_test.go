//go:build unix

package sensorkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
)

const adapterScript = `#!/bin/sh
echo '{"version":"1.3","metadata":{"timestamp":"2026-10-05T00:00:00Z"},"findings":[{"type":"misconfiguration","title":"adapter finding","severity":"low"},{"type":"secret","title":"undeclared adapter finding","severity":"high"}]}'
`

func adapterManifestYAML(name string) string {
	return `apiVersion: openctem.io/tool/v1
name: ` + name + `
version: 0.1.0
class: target-scan
tier: T1
produces: ["finding:misconfiguration"]
permissions:
  network: none
run:
  profile: exec
  argv: ["./run.sh", "{{target.value}}"]
  output:
    format: ctis
    from: stdout
`
}

// writeAdapter installs one adapter tool in dir/name.
func writeAdapter(t *testing.T, dir, name, manifest string) string {
	t.Helper()
	d := filepath.Join(dir, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "run.sh"), []byte(adapterScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, manifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestKit_AdapterDirs: an operator-installed tool is loaded, reported and
// runs dispatched scans (its undeclared output quarantined); manifests
// another user could change, symbolic links, manifests without a run
// section and names the sensor already provides are refused.
func TestKit_AdapterDirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAdapter(t, dir, "good-adapter", adapterManifestYAML("good-adapter"))
	bad := writeAdapter(t, dir, "writable-adapter", adapterManifestYAML("writable-adapter"))
	if err := os.Chmod(filepath.Join(bad, manifestFile), 0o666); err != nil {
		t.Fatal(err)
	}
	badDir := writeAdapter(t, dir, "writable-dir", adapterManifestYAML("writable-dir"))
	if err := os.Chmod(badDir, 0o777); err != nil {
		t.Fatal(err)
	}
	badProg := writeAdapter(t, dir, "writable-program", adapterManifestYAML("writable-program"))
	if err := os.Chmod(filepath.Join(badProg, "run.sh"), 0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked-adapter")
	if err := os.MkdirAll(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "good-adapter", manifestFile), filepath.Join(link, manifestFile)); err != nil {
		t.Fatal(err)
	}
	writeAdapter(t, dir, "no-run", strings.Split(adapterManifestYAML("no-run"), "run:")[0])
	writeAdapter(t, dir, "shadow", adapterManifestYAML("kit-contract"))

	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	opts.AdapterDirs = []string{dir}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddTool(contractTool)
	f.QueueCommandPayload("0192a3b4-0000-7000-8000-0000000000d1", "scan", scanPayload("good-adapter", "1.1.1.1"))
	stop := runKit(t, k)
	waitCompleted(t, f, "0192a3b4-0000-7000-8000-0000000000d1", out, errw)
	waitFor(t, "findings delivered", func() bool { return len(acceptedTitles(f)) >= 1 })
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	titles := strings.Join(acceptedTitles(f), "\n")
	if !strings.Contains(titles, "adapter finding") || strings.Contains(titles, "undeclared adapter finding") {
		t.Fatalf("adapter output:\n%s", titles)
	}
	logs := out.String()
	if !strings.Contains(logs, "Adapter tool: good-adapter 0.1.0") {
		t.Errorf("stdout lacks the loaded adapter:\n%s", logs)
	}
	stderr := errw.String()
	for _, want := range []string{
		"writable-adapter/tool.yaml not loaded: " + filepath.Join(bad, manifestFile) + " is writable by group or others",
		"writable-dir/tool.yaml not loaded: " + badDir + " is writable by group or others",
		"writable-program/tool.yaml not loaded: " + filepath.Join(badProg, "run.sh") + " is writable by group or others",
		"linked-adapter/tool.yaml not loaded: " + filepath.Join(link, manifestFile) + " is a symbolic link",
		"no-run/tool.yaml not loaded: the manifest has no run section",
		"shadow/tool.yaml not loaded: tool kit-contract is already provided by the sensor",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	hb := lastBeat(t, f)
	var names []string
	for _, ti := range hb.Tools {
		names = append(names, ti.Name)
	}
	if got := strings.Join(names, ","); got != "kit-contract,good-adapter" {
		t.Fatalf("reported tools %s", got)
	}
	report := k.ConfigReport()
	refused := 0
	for _, c := range report.Checks {
		if c.Code == "adapter_refused" {
			refused++
		}
	}
	if refused != 6 {
		t.Errorf("config report has %d adapter_refused checks, want 6", refused)
	}
}

func TestCheckTrustedPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkTrustedPath(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o620); err != nil {
		t.Fatal(err)
	}
	if err := checkTrustedPath(p); err == nil {
		t.Fatal("a group-writable file passed")
	}
	if err := checkTrustedPath(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing file passed")
	}
}
