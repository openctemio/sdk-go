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
	"regexp"
	"sort"
	"strings"
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
	metadata     map[string]*CachedTemplateMetadata // key: tenant/type/hash (see cacheKey)
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

	// Apply per-field defaults so a partially-populated config (e.g. only
	// CacheDir set) doesn't leave zero values that disable cleanup safety:
	// MaxCacheAge=0 would expire every entry immediately and CleanupInterval=0
	// would run a cleanup goroutine on every Put.
	if cfg.MaxCacheAge <= 0 {
		cfg.MaxCacheAge = 7 * 24 * time.Hour
	}
	if cfg.MaxCacheSize <= 0 {
		cfg.MaxCacheSize = 100 * 1024 * 1024
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 1 * time.Hour
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

// Get retrieves a template from cache by content hash, regardless of the
// tenant or template type it was cached for.
//
// Deprecated: Get is not tenant-scoped; a hit may be another tenant's file.
// Use GetFor.
func (c *TemplateCache) Get(contentHash string) (string, bool) {
	c.mu.RLock()
	var key string
	for k, meta := range c.metadata {
		if meta.ContentHash == contentHash {
			key = k
			break
		}
	}
	c.mu.RUnlock()
	if key == "" {
		return "", false
	}
	return c.getByKey(key)
}

// GetFor retrieves a cached template for one tenant and template type.
// Entries cached for other tenants are never returned.
func (c *TemplateCache) GetFor(tenantID, templateType, contentHash string) (string, bool) {
	return c.getByKey(cacheKey(tenantID, templateType, contentHash))
}

func (c *TemplateCache) getByKey(key string) (string, bool) {
	c.mu.RLock()
	meta, ok := c.metadata[key]
	c.mu.RUnlock()

	if !ok {
		return "", false
	}

	// Verify file exists and is still inside the cache directory.
	if !c.isInsideCacheDir(meta.FilePath) {
		c.mu.Lock()
		delete(c.metadata, key)
		c.mu.Unlock()
		return "", false
	}
	if _, err := os.Stat(meta.FilePath); err != nil {
		// File doesn't exist, remove from metadata
		c.mu.Lock()
		delete(c.metadata, key)
		c.mu.Unlock()
		return "", false
	}

	// Update last used time
	c.mu.Lock()
	meta.LastUsedAt = time.Now()
	c.mu.Unlock()

	return meta.FilePath, true
}

// tenantIDPattern is the canonical UUID form OpenCTEM uses for tenant IDs.
var tenantIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// validateCacheScope checks the two values that become path components.
// Both come from the server, so without this a tenant ID or template type
// of "../../x" writes outside the cache directory.
func validateCacheScope(tenantID, templateType string) error {
	if !tenantIDPattern.MatchString(tenantID) {
		return fmt.Errorf("invalid tenant ID %q: must be a UUID", tenantID)
	}
	if !ValidTemplateTypes[templateType] {
		return fmt.Errorf("invalid template type %q (allowed: nuclei, semgrep, gitleaks)", templateType)
	}
	return nil
}

func cacheKey(tenantID, templateType, contentHash string) string {
	return strings.ToLower(tenantID) + "/" + templateType + "/" + contentHash
}

// isInsideCacheDir reports whether path is strictly inside the cache dir.
func (c *TemplateCache) isInsideCacheDir(path string) bool {
	base, err := filepath.Abs(c.config.CacheDir)
	if err != nil {
		return false
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == "." || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Put stores a template in the cache.
// Returns the file path where the template was written.
//
// tenantID must be a UUID and template.TemplateType one of
// ValidTemplateTypes; the file is written under
// {cache_dir}/{tenant_id}/{template_type}/ and the resolved path is checked
// to stay inside the cache directory.
func (c *TemplateCache) Put(tenantID string, template *EmbeddedTemplate) (string, error) {
	if template == nil {
		return "", fmt.Errorf("template is nil")
	}
	if err := validateCacheScope(tenantID, template.TemplateType); err != nil {
		return "", err
	}

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

	// Check if already cached for this tenant and type
	if filePath, ok := c.GetFor(tenantID, template.TemplateType, computedHash); ok {
		return filePath, nil
	}

	// Determine file extension based on template type
	ext := ".yaml"
	if template.TemplateType == "gitleaks" {
		ext = ".toml"
	}

	// Create directory structure: {cache_dir}/{tenant_id}/{template_type}/
	dir := filepath.Join(c.config.CacheDir, strings.ToLower(tenantID), template.TemplateType)

	// Use hash prefix + name as filename to avoid collisions
	filename := fmt.Sprintf("%s_%s%s", computedHash[:8], sanitizeFilename(template.Name), ext)
	filePath := filepath.Join(dir, filename)

	// Defense in depth: the components are validated above, but check the
	// final path too so a future change cannot reintroduce traversal.
	if !c.isInsideCacheDir(filePath) {
		return "", fmt.Errorf("template path escapes cache directory")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create template directory: %w", err)
	}

	// Write decoded template content (binary YAML/TOML)
	if err := os.WriteFile(filePath, decodedContent, 0600); err != nil {
		return "", fmt.Errorf("write template file: %w", err)
	}

	// Store metadata
	c.mu.Lock()
	c.metadata[cacheKey(tenantID, template.TemplateType, computedHash)] = &CachedTemplateMetadata{
		ID:           template.ID,
		Name:         template.Name,
		TemplateType: template.TemplateType,
		ContentHash:  computedHash,
		TenantID:     strings.ToLower(tenantID),
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

// GetOrPut returns cached template path or caches the template. The lookup
// is scoped to tenantID and the template's type.
func (c *TemplateCache) GetOrPut(tenantID string, template *EmbeddedTemplate) (string, error) {
	if template == nil {
		return "", fmt.Errorf("template is nil")
	}
	if err := validateCacheScope(tenantID, template.TemplateType); err != nil {
		return "", err
	}

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
	if filePath, ok := c.GetFor(tenantID, template.TemplateType, contentHash); ok {
		if c.config.Verbose {
			fmt.Printf("[template-cache] Cache hit: %s\n", template.Name)
		}
		return filePath, nil
	}

	// Cache the template
	return c.Put(tenantID, template)
}

// GetTemplateDir returns the directory holding templates of templateType for
// tenantID, caching any that are missing. Every template must be of
// templateType (an empty TemplateType is treated as templateType), so all
// files land in the single returned directory:
// {cache_dir}/{tenant_id}/{template_type}. Returns empty string if
// templates slice is empty.
func (c *TemplateCache) GetTemplateDir(tenantID, templateType string, templates []EmbeddedTemplate) (string, error) {
	if len(templates) == 0 {
		return "", nil
	}
	if err := validateCacheScope(tenantID, templateType); err != nil {
		return "", err
	}
	dir := filepath.Join(c.config.CacheDir, strings.ToLower(tenantID), templateType)

	for i := range templates {
		tpl := templates[i]
		if tpl.TemplateType == "" {
			tpl.TemplateType = templateType
		}
		if tpl.TemplateType != templateType {
			return "", fmt.Errorf("template %s has type %q, expected %q", tpl.Name, tpl.TemplateType, templateType)
		}
		filePath, err := c.GetOrPut(tenantID, &tpl)
		if err != nil {
			return "", fmt.Errorf("cache template %s: %w", tpl.Name, err)
		}
		if filepath.Dir(filePath) != dir {
			return "", fmt.Errorf("cache template %s: unexpected location %s", tpl.Name, filePath)
		}
	}

	return dir, nil
}

// Remove removes every cached copy of a template (all tenants) by content
// hash.
func (c *TemplateCache) Remove(contentHash string) error {
	c.mu.Lock()
	var paths []string
	for key, meta := range c.metadata {
		if meta.ContentHash == contentHash {
			paths = append(paths, meta.FilePath)
			delete(c.metadata, key)
		}
	}
	c.mu.Unlock()
	if len(paths) == 0 {
		return nil
	}

	// Remove files
	for _, p := range paths {
		if !c.isInsideCacheDir(p) {
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove template file: %w", err)
		}
	}

	// Persist metadata
	return c.saveMetadata()
}

// Clear removes all cached templates for a tenant.
func (c *TemplateCache) Clear(tenantID string) error {
	// tenantID becomes a path for RemoveAll: validate it first, or "../.."
	// would delete arbitrary directories.
	if !tenantIDPattern.MatchString(tenantID) {
		return fmt.Errorf("invalid tenant ID %q: must be a UUID", tenantID)
	}
	tenantID = strings.ToLower(tenantID)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Find and remove all templates for this tenant
	for key, meta := range c.metadata {
		if meta.TenantID == tenantID {
			if c.isInsideCacheDir(meta.FilePath) {
				os.Remove(meta.FilePath) //nolint:errcheck
			}
			delete(c.metadata, key)
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
		if c.isInsideCacheDir(meta.FilePath) {
			os.Remove(meta.FilePath) //nolint:errcheck
		}
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
	// Read lastCleanup under the lock: Cleanup() writes it while holding
	// c.mu.Lock, and Put() calls maybeCleanup AFTER releasing the lock, so an
	// unguarded read here is a data race (torn read of a multi-word time.Time
	// and -race failures), and could spawn redundant cleanup goroutines.
	c.mu.RLock()
	notDue := time.Since(c.lastCleanup) < c.config.CleanupInterval
	c.mu.RUnlock()
	if notDue {
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

	// The metadata file is re-validated on load: an entry whose scope is
	// invalid or whose path points outside the cache directory (tampered or
	// written by an older, unvalidated version) is dropped, so Get/Remove/
	// Cleanup never act on an arbitrary path.
	for _, meta := range metadataList {
		if meta == nil || validateCacheScope(meta.TenantID, meta.TemplateType) != nil ||
			!c.isInsideCacheDir(meta.FilePath) {
			continue
		}
		c.metadata[cacheKey(meta.TenantID, meta.TemplateType, meta.ContentHash)] = meta
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
