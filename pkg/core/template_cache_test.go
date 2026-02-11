package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestTemplateCache_Put_DecodesBase64(t *testing.T) {
	// Create temp directory for cache
	tempDir, err := os.MkdirTemp("", "template-cache-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create cache
	cache, err := NewTemplateCache(&TemplateCacheConfig{
		CacheDir: tempDir,
		Verbose:  true,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Original template content (YAML)
	originalContent := `id: test-template
info:
  name: Test Template
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}/test"
`

	// Compute hash of ORIGINAL content (not base64)
	hash := sha256.Sum256([]byte(originalContent))
	contentHash := hex.EncodeToString(hash[:])

	// Create embedded template with base64-encoded content (as API sends it)
	template := &EmbeddedTemplate{
		ID:           "tpl-123",
		Name:         "test-template.yaml",
		TemplateType: "nuclei",
		Content:      base64.StdEncoding.EncodeToString([]byte(originalContent)), // Base64 encoded
		ContentHash:  contentHash,
	}

	// Put template in cache
	filePath, err := cache.Put("tenant-abc", template)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatalf("template file was not created: %s", filePath)
	}

	// Read file content and verify it's decoded (not base64)
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read template file: %v", err)
	}

	if string(fileContent) != originalContent {
		t.Errorf("file content mismatch:\nexpected:\n%s\ngot:\n%s", originalContent, string(fileContent))
	}

	// Verify the content is NOT base64 (should be valid YAML starting with "id:")
	if string(fileContent[:3]) != "id:" {
		t.Errorf("file content appears to still be base64 encoded, starts with: %s", string(fileContent[:10]))
	}
}

func TestTemplateCache_Put_HashMismatch(t *testing.T) {
	// Create temp directory for cache
	tempDir, err := os.MkdirTemp("", "template-cache-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create cache
	cache, err := NewTemplateCache(&TemplateCacheConfig{
		CacheDir: tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	originalContent := "test content"

	// Create template with wrong hash
	template := &EmbeddedTemplate{
		ID:           "tpl-123",
		Name:         "test.yaml",
		TemplateType: "nuclei",
		Content:      base64.StdEncoding.EncodeToString([]byte(originalContent)),
		ContentHash:  "wrong-hash-value",
	}

	// Put should fail due to hash mismatch
	_, err = cache.Put("tenant-abc", template)
	if err == nil {
		t.Fatal("expected error for hash mismatch, got nil")
	}

	if !containsString(err.Error(), "hash mismatch") {
		t.Errorf("expected hash mismatch error, got: %v", err)
	}
}

func TestTemplateCache_Put_InvalidBase64(t *testing.T) {
	// Create temp directory for cache
	tempDir, err := os.MkdirTemp("", "template-cache-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create cache
	cache, err := NewTemplateCache(&TemplateCacheConfig{
		CacheDir: tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Create template with invalid base64
	template := &EmbeddedTemplate{
		ID:           "tpl-123",
		Name:         "test.yaml",
		TemplateType: "nuclei",
		Content:      "not-valid-base64!!!", // Invalid base64
		ContentHash:  "",
	}

	// Put should fail due to invalid base64
	_, err = cache.Put("tenant-abc", template)
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}

	if !containsString(err.Error(), "decode") && !containsString(err.Error(), "base64") {
		t.Errorf("expected base64 decode error, got: %v", err)
	}
}

func TestTemplateCache_GetOrPut_CacheHit(t *testing.T) {
	// Create temp directory for cache
	tempDir, err := os.MkdirTemp("", "template-cache-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create cache
	cache, err := NewTemplateCache(&TemplateCacheConfig{
		CacheDir: tempDir,
		Verbose:  true,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	originalContent := "test template content"
	hash := sha256.Sum256([]byte(originalContent))
	contentHash := hex.EncodeToString(hash[:])

	template := &EmbeddedTemplate{
		ID:           "tpl-123",
		Name:         "test.yaml",
		TemplateType: "nuclei",
		Content:      base64.StdEncoding.EncodeToString([]byte(originalContent)),
		ContentHash:  contentHash,
	}

	// First call - cache miss
	filePath1, err := cache.GetOrPut("tenant-abc", template)
	if err != nil {
		t.Fatalf("first GetOrPut failed: %v", err)
	}

	// Second call - should be cache hit
	filePath2, err := cache.GetOrPut("tenant-abc", template)
	if err != nil {
		t.Fatalf("second GetOrPut failed: %v", err)
	}

	// Should return same path
	if filePath1 != filePath2 {
		t.Errorf("cache hit returned different path: %s vs %s", filePath1, filePath2)
	}
}

func TestTemplateCache_GitleaksExtension(t *testing.T) {
	// Create temp directory for cache
	tempDir, err := os.MkdirTemp("", "template-cache-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create cache
	cache, err := NewTemplateCache(&TemplateCacheConfig{
		CacheDir: tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	tomlContent := `[[rules]]
id = "test-rule"
description = "Test rule"
regex = '''test'''
`

	template := &EmbeddedTemplate{
		ID:           "tpl-123",
		Name:         "gitleaks-config",
		TemplateType: "gitleaks",
		Content:      base64.StdEncoding.EncodeToString([]byte(tomlContent)),
		ContentHash:  "",
	}

	filePath, err := cache.Put("tenant-abc", template)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify .toml extension
	if filepath.Ext(filePath) != ".toml" {
		t.Errorf("expected .toml extension, got: %s", filepath.Ext(filePath))
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
