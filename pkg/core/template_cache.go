// Package core provides the core interfaces and base implementations for the OpenCTEM Scanner SDK.
package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// TemplateCacheConfig configures the template cache.
type TemplateCacheConfig struct {
	// CacheDir is the base directory for cached templates.
	// Default: ~/.openctem/templates
	CacheDir string

	// MaxCacheAge is the maximum age of cached templates before cleanup.
	// Default: 7 days
	MaxCacheAge time.Duration

	// MaxCacheSize is the maximum total size of the cache in bytes.
	// Default: 100MB
	MaxCacheSize int64

	// CleanupInterval is how often to run cleanup.
	// Default: 1 hour
	CleanupInterval time.Duration

	// Verbose enables verbose logging.
	Verbose bool
}

// DefaultTemplateCacheConfig returns default cache configuration.
func DefaultTemplateCacheConfig() *TemplateCacheConfig {
	homeDir, _ := os.UserHomeDir()
	return &TemplateCacheConfig{
		CacheDir:        filepath.Join(homeDir, ".openctem", "templates"),
		MaxCacheAge:     7 * 24 * time.Hour, // 7 days
		MaxCacheSize:    100 * 1024 * 1024,  // 100MB
		CleanupInterval: 1 * time.Hour,
	}
}

// TemplateCache provides persistent caching of custom templates.
// Templates are organized by: {cache_dir}/{tenant_id}/{template_type}/{template_name}
type TemplateCache struct {
	config       *TemplateCacheConfig
	mu           sync.RWMutex
	metadata     map[string]*CachedTemplateMetadata // key: hash
	metadataFile string
	lastCleanup  time.Time
}

// CachedTemplateMetadata stores metadata about a cached template.
type CachedTemplateMetadata struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	TemplateType string    `json:"template_type"`
	ContentHash  string    `json:"content_hash"`
	TenantID     string    `json:"tenant_id"`
	FilePath     string    `json:"file_path"`
	Size         int64     `json:"size"`
	CachedAt     time.Time `json:"cached_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
}

// NewTemplateCache creates a new template cache.
func NewTemplateCache(cfg *TemplateCacheConfig) (*TemplateCache, error) {
	if cfg == nil {
		cfg = DefaultTemplateCacheConfig()
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	cache := &TemplateCache{
		config:       cfg,
		metadata:     make(map[string]*CachedTemplateMetadata),
		metadataFile: filepath.Join(cfg.CacheDir, "metadata.json"),
		lastCleanup:  time.Now(),
	}

	// Load existing metadata
	if err := cache.loadMetadata(); err != nil && cfg.Verbose {
		fmt.Printf("[template-cache] Warning: failed to load metadata: %v\n", err)
	}

	return cache, nil
}

// Get retrieves a template from cache by content hash.
// Returns the file path if found and valid, empty string otherwise.
func (c *TemplateCache) Get(contentHash string) (string, bool) {
	c.mu.RLock()
	meta, ok := c.metadata[contentHash]
	c.mu.RUnlock()

	if !ok {
		return "", false
	}

	// Verify file exists
	if _, err := os.Stat(meta.FilePath); err != nil {
		// File doesn't exist, remove from metadata
		c.mu.Lock()
		delete(c.metadata, contentHash)
		c.mu.Unlock()
		return "", false
	}

	// Update last used time
	c.mu.Lock()
	meta.LastUsedAt = time.Now()
	c.mu.Unlock()

	return meta.FilePath, true
}

// Put stores a template in the cache.
// Returns the file path where the template was written.
func (c *TemplateCache) Put(tenantID string, template *EmbeddedTemplate) (string, error) {
	// Decode base64 content (API sends templates as base64 for safe JSON transport)
	decodedContent, err := base64.StdEncoding.DecodeString(template.Content)
	if err != nil {
		return "", fmt.Errorf("decode template %s base64 content: %w", template.Name, err)
	}

	// Verify content hash against decoded content
	hash := sha256.Sum256(decodedContent)
	computedHash := hex.EncodeToString(hash[:])

	if template.ContentHash != "" && computedHash != template.ContentHash {
		return "", fmt.Errorf("template %s hash mismatch: expected %s, got %s",
			template.Name, template.ContentHash, computedHash)
	}

	// Check if already cached
	if filePath, ok := c.Get(computedHash); ok {
		return filePath, nil
	}

	// Determine file extension based on template type
	ext := ".yaml"
	if template.TemplateType == "gitleaks" {
		ext = ".toml"
	}

	// Create directory structure: {cache_dir}/{tenant_id}/{template_type}/
	dir := filepath.Join(c.config.CacheDir, tenantID, template.TemplateType)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create template directory: %w", err)
	}

	// Use hash prefix + name as filename to avoid collisions
	filename := fmt.Sprintf("%s_%s%s", computedHash[:8], sanitizeFilename(template.Name), ext)
	filePath := filepath.Join(dir, filename)

	// Write decoded template content (binary YAML/TOML)
	if err := os.WriteFile(filePath, decodedContent, 0600); err != nil {
		return "", fmt.Errorf("write template file: %w", err)
	}

	// Store metadata
	c.mu.Lock()
	c.metadata[computedHash] = &CachedTemplateMetadata{
		ID:           template.ID,
		Name:         template.Name,
		TemplateType: template.TemplateType,
		ContentHash:  computedHash,
		TenantID:     tenantID,
		FilePath:     filePath,
		Size:         int64(len(decodedContent)), // Use decoded content size
		CachedAt:     time.Now(),
		LastUsedAt:   time.Now(),
	}
	c.mu.Unlock()

	// Persist metadata
	if err := c.saveMetadata(); err != nil && c.config.Verbose {
		fmt.Printf("[template-cache] Warning: failed to save metadata: %v\n", err)
	}

	// Run cleanup if needed
	c.maybeCleanup()

	if c.config.Verbose {
		fmt.Printf("[template-cache] Cached template: %s -> %s\n", template.Name, filePath)
	}

	return filePath, nil
}

// GetOrPut returns cached template path or caches the template.
func (c *TemplateCache) GetOrPut(tenantID string, template *EmbeddedTemplate) (string, error) {
	// Compute hash if not provided (must decode base64 first)
	contentHash := template.ContentHash
	if contentHash == "" {
		decodedContent, err := base64.StdEncoding.DecodeString(template.Content)
		if err != nil {
			return "", fmt.Errorf("decode template %s base64 content: %w", template.Name, err)
		}
		hash := sha256.Sum256(decodedContent)
		contentHash = hex.EncodeToString(hash[:])
	}

	// Try to get from cache
	if filePath, ok := c.Get(contentHash); ok {
		if c.config.Verbose {
			fmt.Printf("[template-cache] Cache hit: %s\n", template.Name)
		}
		return filePath, nil
	}

	// Cache the template
	return c.Put(tenantID, template)
}

// GetTemplateDir returns the directory for a specific tenant and template type.
// Creates the directory if it doesn't exist.
// Returns empty string if templates slice is empty.
func (c *TemplateCache) GetTemplateDir(tenantID, templateType string, templates []EmbeddedTemplate) (string, error) {
	if len(templates) == 0 {
		return "", nil
	}

	// Cache all templates and get the directory
	var dir string
	for _, tpl := range templates {
		filePath, err := c.GetOrPut(tenantID, &tpl)
		if err != nil {
			return "", fmt.Errorf("cache template %s: %w", tpl.Name, err)
		}
		if dir == "" {
			dir = filepath.Dir(filePath)
		}
	}

	return dir, nil
}

// Remove removes a template from cache by content hash.
func (c *TemplateCache) Remove(contentHash string) error {
	c.mu.Lock()
	meta, ok := c.metadata[contentHash]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	delete(c.metadata, contentHash)
	c.mu.Unlock()

	// Remove file
	if err := os.Remove(meta.FilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove template file: %w", err)
	}

	// Persist metadata
	return c.saveMetadata()
}

// Clear removes all cached templates for a tenant.
func (c *TemplateCache) Clear(tenantID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find and remove all templates for this tenant
	for hash, meta := range c.metadata {
		if meta.TenantID == tenantID {
			os.Remove(meta.FilePath) //nolint:errcheck
			delete(c.metadata, hash)
		}
	}

	// Remove tenant directory
	tenantDir := filepath.Join(c.config.CacheDir, tenantID)
	if err := os.RemoveAll(tenantDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove tenant directory: %w", err)
	}

	return c.saveMetadataLocked()
}

// Cleanup removes old and excess cached templates.
func (c *TemplateCache) Cleanup() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var totalSize int64
	var toRemove []string

	// Sort metadata by last used time (oldest first)
	type entry struct {
		hash string
		meta *CachedTemplateMetadata
	}
	entries := make([]entry, 0, len(c.metadata))
	for hash, meta := range c.metadata {
		entries = append(entries, entry{hash, meta})
		totalSize += meta.Size
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].meta.LastUsedAt.Before(entries[j].meta.LastUsedAt)
	})

	// Remove old templates
	for _, e := range entries {
		if now.Sub(e.meta.CachedAt) > c.config.MaxCacheAge {
			toRemove = append(toRemove, e.hash)
			totalSize -= e.meta.Size
		}
	}

	// Remove templates if cache size exceeds limit
	for _, e := range entries {
		if totalSize <= c.config.MaxCacheSize {
			break
		}
		// Don't remove recently used templates (within last hour)
		if now.Sub(e.meta.LastUsedAt) < time.Hour {
			continue
		}
		// Skip if already marked for removal
		found := false
		for _, h := range toRemove {
			if h == e.hash {
				found = true
				break
			}
		}
		if !found {
			toRemove = append(toRemove, e.hash)
			totalSize -= e.meta.Size
		}
	}

	// Remove templates
	for _, hash := range toRemove {
		meta := c.metadata[hash]
		if c.config.Verbose {
			fmt.Printf("[template-cache] Removing old template: %s\n", meta.Name)
		}
		os.Remove(meta.FilePath) //nolint:errcheck
		delete(c.metadata, hash)
	}

	c.lastCleanup = now

	return c.saveMetadataLocked()
}

// Stats returns cache statistics.
func (c *TemplateCache) Stats() *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := &CacheStats{
		TemplateCount: len(c.metadata),
		TenantCount:   make(map[string]int),
		TypeCount:     make(map[string]int),
	}

	for _, meta := range c.metadata {
		stats.TotalSize += meta.Size
		stats.TenantCount[meta.TenantID]++
		stats.TypeCount[meta.TemplateType]++
		if meta.CachedAt.After(stats.NewestEntry) {
			stats.NewestEntry = meta.CachedAt
		}
		if stats.OldestEntry.IsZero() || meta.CachedAt.Before(stats.OldestEntry) {
			stats.OldestEntry = meta.CachedAt
		}
	}

	return stats
}

// CacheStats contains cache statistics.
type CacheStats struct {
	TemplateCount int            `json:"template_count"`
	TotalSize     int64          `json:"total_size"`
	TenantCount   map[string]int `json:"tenant_count"`
	TypeCount     map[string]int `json:"type_count"`
	OldestEntry   time.Time      `json:"oldest_entry"`
	NewestEntry   time.Time      `json:"newest_entry"`
}

// maybeCleanup runs cleanup if enough time has passed.
func (c *TemplateCache) maybeCleanup() {
	if time.Since(c.lastCleanup) < c.config.CleanupInterval {
		return
	}

	go func() {
		if err := c.Cleanup(); err != nil && c.config.Verbose {
			fmt.Printf("[template-cache] Cleanup error: %v\n", err)
		}
	}()
}

// loadMetadata loads metadata from disk.
func (c *TemplateCache) loadMetadata() error {
	data, err := os.ReadFile(c.metadataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var metadataList []*CachedTemplateMetadata
	if err := json.Unmarshal(data, &metadataList); err != nil {
		return err
	}

	for _, meta := range metadataList {
		c.metadata[meta.ContentHash] = meta
	}

	return nil
}

// saveMetadata persists metadata to disk.
func (c *TemplateCache) saveMetadata() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.saveMetadataLocked()
}

// saveMetadataLocked persists metadata to disk (caller must hold lock).
func (c *TemplateCache) saveMetadataLocked() error {
	metadataList := make([]*CachedTemplateMetadata, 0, len(c.metadata))
	for _, meta := range c.metadata {
		metadataList = append(metadataList, meta)
	}

	data, err := json.MarshalIndent(metadataList, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(c.metadataFile, data, 0600)
}

// sanitizeFilename removes or replaces characters that are not safe for filenames.
func sanitizeFilename(name string) string {
	// Remove file extension if present
	ext := filepath.Ext(name)
	base := name[:len(name)-len(ext)]

	// Replace unsafe characters
	safe := make([]byte, 0, len(base))
	for i := 0; i < len(base); i++ {
		c := base[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			safe = append(safe, c)
		} else if c == ' ' || c == '.' {
			safe = append(safe, '_')
		}
	}

	if len(safe) == 0 {
		return "template"
	}

	// Limit length
	if len(safe) > 50 {
		safe = safe[:50]
	}

	return string(safe)
}
