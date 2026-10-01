package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const otherTenantID = "9b1c2d3e-4f5a-4b6c-8d7e-0f1a2b3c4d5e"

func testTemplate(name, typ, content string) *EmbeddedTemplate {
	sum := sha256.Sum256([]byte(content))
	return &EmbeddedTemplate{
		ID:           "tpl-" + name,
		Name:         name,
		TemplateType: typ,
		Content:      base64.StdEncoding.EncodeToString([]byte(content)),
		ContentHash:  hex.EncodeToString(sum[:]),
	}
}

func newTestCache(t *testing.T) (*TemplateCache, string) {
	t.Helper()
	base := t.TempDir()
	cacheDir := filepath.Join(base, "cache")
	c, err := NewTemplateCache(&TemplateCacheConfig{CacheDir: cacheDir})
	if err != nil {
		t.Fatal(err)
	}
	return c, base
}

// listFiles returns every regular file under dir.
func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestTemplateCache_RejectsPathTraversal(t *testing.T) {
	cases := []struct {
		name     string
		tenantID string
		typ      string
	}{
		{"tenant traversal", "../../escaped", "nuclei"},
		{"tenant absolute", "/tmp/escaped", "nuclei"},
		{"tenant non-uuid", "tenant-abc", "nuclei"},
		{"tenant empty", "", "nuclei"},
		{"type traversal", testTenantID, "../../escaped"},
		{"type unknown", testTenantID, "bash"},
		{"type empty", testTenantID, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, base := newTestCache(t)
			tpl := testTemplate("evil", tc.typ, "id: x")
			if _, err := c.Put(tc.tenantID, tpl); err == nil {
				t.Fatal("Put accepted invalid scope")
			}
			if _, err := c.GetOrPut(tc.tenantID, tpl); err == nil {
				t.Fatal("GetOrPut accepted invalid scope")
			}
			// Nothing may be written anywhere — in particular not outside the cache dir.
			for _, f := range listFiles(t, base) {
				t.Errorf("unexpected file written: %s", f)
			}
		})
	}
}

func TestTemplateCache_ClearRejectsTraversal(t *testing.T) {
	c, base := newTestCache(t)
	victim := filepath.Join(base, "victim")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.Clear("../victim"); err == nil {
		t.Fatal("Clear accepted traversal tenant ID")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("Clear deleted a directory outside the cache: %v", err)
	}
}

// Same template content cached for tenant A must not make tenant B's
// GetTemplateDir return tenant A's folder.
func TestTemplateCache_TenantScopedHits(t *testing.T) {
	c, _ := newTestCache(t)

	tplA := testTemplate("shared", "nuclei", "id: shared-template")
	dirA, err := c.GetTemplateDir(testTenantID, "nuclei", []EmbeddedTemplate{*tplA})
	if err != nil {
		t.Fatal(err)
	}

	tplB := testTemplate("shared", "nuclei", "id: shared-template")
	dirB, err := c.GetTemplateDir(otherTenantID, "nuclei", []EmbeddedTemplate{*tplB})
	if err != nil {
		t.Fatal(err)
	}

	if dirA == dirB {
		t.Fatalf("tenant B got tenant A's template dir %s", dirA)
	}
	if !strings.Contains(dirB, otherTenantID) {
		t.Errorf("tenant B dir %s is not scoped to tenant B", dirB)
	}
	if files := listFiles(t, dirB); len(files) != 1 {
		t.Errorf("tenant B dir should hold its own copy, got %v", files)
	}

	// Mixed types in one call are rejected rather than silently split
	// across directories.
	semgrep := testTemplate("rule", "semgrep", "rules: []")
	if _, err := c.GetTemplateDir(testTenantID, "nuclei", []EmbeddedTemplate{*tplA, *semgrep}); err == nil {
		t.Error("GetTemplateDir accepted a template of a different type")
	}
}

// A tampered metadata.json must not make the cache act on paths outside
// its directory.
func TestTemplateCache_LoadDropsEscapingMetadata(t *testing.T) {
	base := t.TempDir()
	cacheDir := filepath.Join(base, "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(base, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	meta := []*CachedTemplateMetadata{{
		ContentHash: "deadbeef", TenantID: testTenantID, TemplateType: "nuclei", FilePath: victim,
	}, {
		ContentHash: "cafebabe", TenantID: "../..", TemplateType: "nuclei",
		FilePath: filepath.Join(cacheDir, "x.yaml"),
	}}
	raw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(cacheDir, "metadata.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := NewTemplateCache(&TemplateCacheConfig{CacheDir: cacheDir})
	if err != nil {
		t.Fatal(err)
	}
	if n := c.Stats().TemplateCount; n != 0 {
		t.Fatalf("escaping metadata entries loaded: %d", n)
	}
	if err := c.Remove("deadbeef"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("file outside cache removed: %v", err)
	}
}
