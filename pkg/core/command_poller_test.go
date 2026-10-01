package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTemplate(t *testing.T) {
	tests := []struct {
		name      string
		template  *EmbeddedTemplate
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil template",
			template:  nil,
			wantError: true,
			errMsg:    "template is nil",
		},
		{
			name: "empty ID",
			template: &EmbeddedTemplate{
				Name:         "test.yaml",
				TemplateType: "nuclei",
				Content:      "test",
			},
			wantError: true,
			errMsg:    "template ID is required",
		},
		{
			name: "empty name",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				TemplateType: "nuclei",
				Content:      "test",
			},
			wantError: true,
			errMsg:    "template name is required",
		},
		{
			name: "path traversal with ..",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         "../../../etc/passwd",
				TemplateType: "nuclei",
				Content:      "test",
			},
			wantError: true,
			errMsg:    "path traversal not allowed",
		},
		{
			name: "path traversal with absolute path",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         "/etc/passwd",
				TemplateType: "nuclei",
				Content:      "test",
			},
			wantError: true,
			errMsg:    "path traversal not allowed",
		},
		{
			name: "path traversal with subdirectory",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         "subdir/template.yaml",
				TemplateType: "nuclei",
				Content:      "test",
			},
			wantError: true,
			errMsg:    "path traversal not allowed",
		},
		{
			name: "hidden file",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         ".hidden",
				TemplateType: "nuclei",
				Content:      "test",
			},
			wantError: true,
			errMsg:    "hidden files not allowed",
		},
		{
			name: "invalid template type",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         "test.yaml",
				TemplateType: "malicious",
				Content:      "test",
			},
			wantError: true,
			errMsg:    "invalid template type",
		},
		{
			name: "valid nuclei template",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         "test.yaml",
				TemplateType: "nuclei",
				Content:      "id: test\ninfo:\n  name: test",
			},
			wantError: false,
		},
		{
			name: "valid semgrep template",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         "test-rule",
				TemplateType: "semgrep",
				Content:      "rules:\n  - id: test",
			},
			wantError: false,
		},
		{
			name: "valid gitleaks template",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         "secrets",
				TemplateType: "gitleaks",
				Content:      "[[rules]]\nid = \"test\"",
			},
			wantError: false,
		},
		{
			name: "name too long",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         string(make([]byte, MaxTemplateNameLength+1)),
				TemplateType: "nuclei",
				Content:      "test",
			},
			wantError: true,
			errMsg:    "template name too long",
		},
		{
			name: "content too large",
			template: &EmbeddedTemplate{
				ID:           "test-id",
				Name:         "test.yaml",
				TemplateType: "nuclei",
				Content:      string(make([]byte, base64.StdEncoding.EncodedLen(MaxTemplateSize)+1)),
			},
			wantError: true,
			errMsg:    "template content too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.template)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateTemplate() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateTemplate() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateTemplate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestIsSubPath(t *testing.T) {
	// Create temp directory for testing
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		parent   string
		child    string
		expected bool
	}{
		{
			name:     "valid subpath",
			parent:   tmpDir,
			child:    filepath.Join(tmpDir, "file.txt"),
			expected: true,
		},
		{
			name:     "valid nested subpath",
			parent:   tmpDir,
			child:    filepath.Join(tmpDir, "subdir", "file.txt"),
			expected: true,
		},
		{
			name:     "parent equals child",
			parent:   tmpDir,
			child:    tmpDir,
			expected: false,
		},
		{
			name:     "child outside parent",
			parent:   tmpDir,
			child:    "/etc/passwd",
			expected: false,
		},
		{
			name:     "path traversal attempt",
			parent:   tmpDir,
			child:    filepath.Join(tmpDir, "..", "etc", "passwd"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSubPath(tt.parent, tt.child)
			if result != tt.expected {
				t.Errorf("isSubPath(%q, %q) = %v, want %v", tt.parent, tt.child, result, tt.expected)
			}
		})
	}
}

func TestWriteCustomTemplates_Security(t *testing.T) {
	executor := &DefaultCommandExecutor{}

	t.Run("rejects path traversal in template name", func(t *testing.T) {
		templates := []EmbeddedTemplate{
			{
				ID:           "test-id",
				Name:         "../../../etc/passwd",
				TemplateType: "nuclei",
				Content:      "test content",
			},
		}

		_, _, err := executor.writeCustomTemplates("nuclei", templates)
		if err == nil {
			t.Error("writeCustomTemplates() expected error for path traversal, got nil")
		}
	})

	t.Run("rejects too many templates", func(t *testing.T) {
		templates := make([]EmbeddedTemplate, MaxTemplatesPerCommand+1)
		for i := range templates {
			templates[i] = EmbeddedTemplate{
				ID:           "test-id",
				Name:         "test.yaml",
				TemplateType: "nuclei",
				Content:      "test",
			}
		}

		_, _, err := executor.writeCustomTemplates("nuclei", templates)
		if err == nil {
			t.Error("writeCustomTemplates() expected error for too many templates, got nil")
		}
	})

	t.Run("rejects duplicate filenames", func(t *testing.T) {
		templates := []EmbeddedTemplate{
			{
				ID:           "test-id-1",
				Name:         "duplicate.yaml",
				TemplateType: "nuclei",
				Content:      "content 1",
			},
			{
				ID:           "test-id-2",
				Name:         "duplicate.yaml",
				TemplateType: "nuclei",
				Content:      "content 2",
			},
		}

		_, _, err := executor.writeCustomTemplates("nuclei", templates)
		if err == nil {
			t.Error("writeCustomTemplates() expected error for duplicate filenames, got nil")
		}
	})

	t.Run("writes valid templates successfully", func(t *testing.T) {
		raw := "id: test\ninfo:\n  name: test"
		sum := sha256.Sum256([]byte(raw))
		templates := []EmbeddedTemplate{
			{
				ID:           "test-id",
				Name:         "valid-template",
				TemplateType: "nuclei",
				Content:      base64.StdEncoding.EncodeToString([]byte(raw)),
				ContentHash:  hex.EncodeToString(sum[:]),
			},
		}

		tmpDir, cleanup, err := executor.writeCustomTemplates("nuclei", templates)
		if err != nil {
			t.Fatalf("writeCustomTemplates() unexpected error: %v", err)
		}
		defer cleanup()

		// The scanner must get the decoded template, not its base64 text.
		got, err := os.ReadFile(filepath.Join(tmpDir, "valid-template.yaml"))
		if err != nil {
			t.Fatalf("Template file not written: %v", err)
		}
		if string(got) != raw {
			t.Errorf("template written as %q, want the decoded content %q", got, raw)
		}
	})

	// The platform's content_hash is SHA-256 over the decoded template; an
	// SDK that hashed the base64 text rejected every custom template.
	t.Run("hash is over decoded content, not the base64 text", func(t *testing.T) {
		raw := "id: canary\ninfo:\n  name: canary\n  severity: info"
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))
		overEncoded := sha256.Sum256([]byte(encoded))
		templates := []EmbeddedTemplate{{
			ID: "t", Name: "canary.yaml", TemplateType: "nuclei",
			Content: encoded, ContentHash: hex.EncodeToString(overEncoded[:]),
		}}
		if _, _, err := executor.writeCustomTemplates("nuclei", templates); err == nil {
			t.Fatal("a hash over the base64 text must not verify")
		}
	})

	t.Run("rejects content that is not base64", func(t *testing.T) {
		templates := []EmbeddedTemplate{{
			ID: "t", Name: "plain.yaml", TemplateType: "nuclei", Content: "id: plain\ninfo: {}",
		}}
		_, _, err := executor.writeCustomTemplates("nuclei", templates)
		if err == nil || !strings.Contains(err.Error(), "base64") {
			t.Fatalf("want a base64 error, got %v", err)
		}
	})

	t.Run("verifies content hash", func(t *testing.T) {
		templates := []EmbeddedTemplate{
			{
				ID:           "test-id",
				Name:         "test.yaml",
				TemplateType: "nuclei",
				Content:      base64.StdEncoding.EncodeToString([]byte("test content")),
				ContentHash:  "wrong-hash",
			},
		}

		_, _, err := executor.writeCustomTemplates("nuclei", templates)
		if err == nil {
			t.Error("writeCustomTemplates() expected error for hash mismatch, got nil")
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
