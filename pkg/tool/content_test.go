package tool

import (
	"path/filepath"
	"strings"
	"testing"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestContentSlotValidation(t *testing.T) {
	var errs []string
	add := func(p, f string, a ...any) { errs = append(errs, p) }
	validateContent([]ContentSlot{
		{Slot: "templates", Kind: "nuclei-templates", Modes: []string{"default", "merge"}, Selectors: []string{"tags"}},
		{Slot: "rules", Kind: "x-acme/rules", Format: "archive", Default: "none"},
	}, add)
	if len(errs) > 0 {
		t.Fatalf("valid slots refused: %v", errs)
	}
	bad := []ContentSlot{
		{Slot: "Bad Slot", Kind: "wordlist"},
		{Slot: "a", Kind: "made-up-kind"},
		{Slot: "b", Kind: "wordlist", Format: "zip"},
		{Slot: "c", Kind: "wordlist", Modes: []string{"replace"}},
		{Slot: "d", Kind: "wordlist", Selectors: []string{"regex"}},
		{Slot: "d", Kind: "wordlist"},
	}
	validateContent(bad, add)
	for _, want := range []string{"/content/0/slot", "/content/1/kind", "/content/2/format", "/content/3/modes/0", "/content/4/selectors/0", "/content/5/slot"} {
		if !strings.Contains(strings.Join(errs, " "), want) {
			t.Errorf("not refused: %s (%v)", want, errs)
		}
	}
}

// SECURITY (api RFC-061): a task's content is checked against the
// manifest, and a pack path must lie beneath the sensor's content cache: a
// job cannot make a task read another path.
func TestCheckTaskContent(t *testing.T) {
	root := t.TempDir()
	m := Manifest{Name: "acme", Content: []ContentSlot{{Slot: "templates", Kind: "nuclei-templates", Modes: []string{"default", "merge"}, Selectors: []string{"tags"}}}}
	ok := Task{Content: []TaskContent{{Slot: "templates", Mode: "merge", Selectors: map[string][]string{"tags": {"cve"}},
		Packs: []ContentPack{{Digest: digestA, Path: filepath.Join(root, "sha256-a")}}}}}
	paths, err := CheckTaskContent(m, ok, root)
	if err != nil || len(paths) != 1 || ok.ContentPaths("templates")[0] != paths[0] {
		t.Fatalf("valid content: %v %v", paths, err)
	}
	bad := map[string]Task{
		"undeclared slot":   {Content: []TaskContent{{Slot: "rules"}}},
		"unsupported mode":  {Content: []TaskContent{{Slot: "templates", Mode: "custom"}}},
		"unknown selector":  {Content: []TaskContent{{Slot: "templates", Selectors: map[string][]string{"ids": {"x"}}}}},
		"not a digest":      {Content: []TaskContent{{Slot: "templates", Packs: []ContentPack{{Digest: "latest"}}}}},
		"outside the cache": {Content: []TaskContent{{Slot: "templates", Packs: []ContentPack{{Digest: digestA, Path: "/etc"}}}}},
		"climbs out":        {Content: []TaskContent{{Slot: "templates", Packs: []ContentPack{{Digest: digestA, Path: filepath.Join(root, "..", "x")}}}}},
		"the cache itself":  {Content: []TaskContent{{Slot: "templates", Packs: []ContentPack{{Digest: digestA, Path: root}}}}},
		"relative":          {Content: []TaskContent{{Slot: "templates", Packs: []ContentPack{{Digest: digestA, Path: "sha256-a"}}}}},
	}
	for name, task := range bad {
		if _, err := CheckTaskContent(m, task, root); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := CheckTaskContent(m, ok, ""); err == nil {
		t.Error("a pack accepted with no content cache configured")
	}
}
