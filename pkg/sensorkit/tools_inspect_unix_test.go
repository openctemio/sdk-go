//go:build unix

package sensorkit

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
)

func inspectRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func refusalFor(rep AdapterReport, name string) (string, bool) {
	for _, r := range rep.Refused {
		if strings.Contains(r.Manifest, string(filepath.Separator)+name+string(filepath.Separator)) {
			return r.Reason, true
		}
	}
	return "", false
}

func TestInspectAdapterDirs(t *testing.T) {
	dir := inspectRoot(t)
	good := writeAdapter(t, dir, "good", adapterManifestYAML("good"))

	helper := writeAdapter(t, dir, "helper-open", adapterManifestYAML("helper-open"))
	hp := filepath.Join(helper, "openctem_tool.py")
	if err := os.WriteFile(hp, []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hp, 0o666); err != nil {
		t.Fatal(err)
	}

	linked := writeAdapter(t, dir, "helper-link", adapterManifestYAML("helper-link"))
	if err := os.Symlink("/etc/passwd", filepath.Join(linked, "wordlist.txt")); err != nil {
		t.Fatal(err)
	}

	deep := writeAdapter(t, dir, "deep", adapterManifestYAML("deep"))
	if err := os.MkdirAll(filepath.Join(deep, "a", "b", "c", "d", "e"), 0o755); err != nil {
		t.Fatal(err)
	}

	big := writeAdapter(t, dir, "big", adapterManifestYAML("big"))
	for i := 0; i <= maxAdapterTreeEntries; i++ {
		if err := os.WriteFile(filepath.Join(big, "f"+strconv.Itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeAdapter(t, dir, "shadow", adapterManifestYAML("taken-name"))

	rep := InspectAdapterDirs([]string{dir}, []string{"Taken-Name"})
	if len(rep.Loaded) != 1 || rep.Loaded[0].Name != "good" {
		t.Fatalf("loaded %+v", rep.Loaded)
	}
	l := rep.Loaded[0]
	if l.Digest == "" || l.Manifest != filepath.Join(good, manifestFile) || l.Class != "target-scan" || l.Tier != "T1" || l.Network != "none" || l.Version != "0.1.0" {
		t.Fatalf("listed tool %+v", l)
	}
	for name, want := range map[string]string{
		"helper-open": hp + " is writable by group or others",
		"helper-link": filepath.Join(linked, "wordlist.txt") + " is a symbolic link",
		"deep":        "deeper than",
		"big":         "more than",
		"shadow":      "already provided by the sensor",
	} {
		r, ok := refusalFor(rep, name)
		if !ok || !strings.Contains(r, want) {
			t.Errorf("%s: reason %q, want %q", name, r, want)
		}
	}
	if len(rep.Refused) != 5 {
		t.Errorf("refused %+v", rep.Refused)
	}
}

// TestInspectAdapterDirs_RootManifest: for a manifest directly in the
// adapter directory only the files it references are checked.
func TestInspectAdapterDirs_RootManifest(t *testing.T) {
	dir := inspectRoot(t)
	m := strings.Replace(adapterManifestYAML("rooted"), `"./run.sh"`, `"./bin/run.sh"`, 1)
	if err := os.WriteFile(filepath.Join(dir, manifestFile), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(dir, "bin", "run.sh")
	if err := os.WriteFile(prog, []byte(adapterScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if rep := InspectAdapterDirs([]string{dir}, nil); len(rep.Loaded) != 1 {
		t.Fatalf("%+v", rep.Refused)
	}
	if err := os.Chmod(prog, 0o777); err != nil {
		t.Fatal(err)
	}
	rep := InspectAdapterDirs([]string{dir}, nil)
	if len(rep.Loaded) != 0 || len(rep.Refused) != 1 || !strings.Contains(rep.Refused[0].Reason, prog) {
		t.Fatalf("%+v", rep)
	}
}

// TestKit_AgreesWithInspect: the kit loads and refuses exactly what the
// inspector reports.
func TestKit_AgreesWithInspect(t *testing.T) {
	dir := inspectRoot(t)
	writeAdapter(t, dir, "good", adapterManifestYAML("good"))
	bad := writeAdapter(t, dir, "bad", adapterManifestYAML("bad"))
	hp := filepath.Join(bad, "helper.py")
	if err := os.WriteFile(hp, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hp, 0o666); err != nil {
		t.Fatal(err)
	}
	rep := InspectAdapterDirs([]string{dir}, nil)

	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, errw := baseOptions(t, f)
	opts.AdapterDirs = []string{dir}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.loadAdapterTools()
	var names []string
	for _, e := range k.scanners {
		names = append(names, e.s.Name())
	}
	if len(rep.Loaded) != 1 || !slices.Contains(names, "good") || slices.Contains(names, "bad") {
		t.Fatalf("kit %v, inspector %+v", names, rep)
	}
	for _, r := range rep.Refused {
		if !strings.Contains(errw.String(), r.Manifest+" not loaded: "+r.Reason) {
			t.Errorf("kit stderr lacks %q:\n%s", r.Reason, errw.String())
		}
	}
}
