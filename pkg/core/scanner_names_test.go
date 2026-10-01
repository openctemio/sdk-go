package core

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCanonicalScannerName(t *testing.T) {
	for in, want := range map[string]string{
		"gitleaks":    ScannerBetterleaks,
		"Gitleaks ":   ScannerBetterleaks,
		"betterleaks": ScannerBetterleaks,
		"semgrep":     "semgrep",
		"":            "",
	} {
		if got := CanonicalScannerName(in); got != want {
			t.Errorf("CanonicalScannerName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRetiredTemplateTypeIsAcceptedAsBetterleaks(t *testing.T) {
	content := base64.StdEncoding.EncodeToString([]byte("[[rules]]\nid = \"x\"\nregex = '''x'''\n"))
	tpl := &EmbeddedTemplate{ID: "t1", Name: "custom", TemplateType: "gitleaks", Content: content}
	if err := ValidateTemplate(tpl); err != nil {
		t.Fatalf("gitleaks template rejected: %v", err)
	}
	c, err := NewTemplateCache(&TemplateCacheConfig{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.Put("11111111-1111-1111-1111-111111111111", tpl)
	if err != nil {
		t.Fatalf("cache gitleaks template: %v", err)
	}
	if !strings.HasSuffix(path, ".toml") || !strings.Contains(path, "/"+ScannerBetterleaks+"/") {
		t.Errorf("cached at %s, want a .toml under the betterleaks type dir", path)
	}
}
