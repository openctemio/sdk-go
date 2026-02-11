// Package kev provides KEV (Known Exploited Vulnerabilities) enrichment.
// KEV is maintained by CISA and lists vulnerabilities known to be actively exploited.
// Data source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

const (
	// DefaultKEVURL is the official CISA KEV catalog endpoint.
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// DefaultCacheTTL is the default cache TTL (KEV updates periodically).
	DefaultCacheTTL = 6 * time.Hour

	// DefaultTimeout is the default HTTP timeout.
	DefaultTimeout = 60 * time.Second
)

// KEVEntry represents a Known Exploited Vulnerability entry.
type KEVEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
	Notes             string `json:"notes"`

	// Parsed dates
	AddedAt  time.Time `json:"-"`
	Deadline time.Time `json:"-"`
}

// KEVCatalog represents the full CISA KEV catalog.
type KEVCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// Enricher implements the core.Enricher interface for KEV.
type Enricher struct {
	mu sync.RWMutex

	// Configuration
	KEVURL  string
	Timeout time.Duration
	Verbose bool

	// HTTP client
	client *http.Client

	// Cache - maps CVE ID to KEV entry
	cache       map[string]*KEVEntry
	catalogInfo *KEVCatalog
	cacheTTL    time.Duration
	cacheAt     time.Time
}

// NewEnricher creates a new KEV enricher with default settings.
func NewEnricher() *Enricher {
	return &Enricher{
		KEVURL:   DefaultKEVURL,
		Timeout:  DefaultTimeout,
		cache:    make(map[string]*KEVEntry),
		cacheTTL: DefaultCacheTTL,
		client: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// NewEnricherWithConfig creates a new KEV enricher with custom configuration.
func NewEnricherWithConfig(cfg *core.EnricherConfig) *Enricher {
	e := NewEnricher()
	if cfg != nil {
		if cfg.Endpoint != "" {
			e.KEVURL = cfg.Endpoint
		}
		if cfg.CacheTTL > 0 {
			e.cacheTTL = cfg.CacheTTL
		}
		e.Verbose = cfg.Verbose
	}
	return e
}

// Name returns the enricher name.
func (e *Enricher) Name() string {
	return "kev"
}

// Enrich adds KEV data to a single finding.
func (e *Enricher) Enrich(ctx context.Context, finding *ctis.Finding) (*ctis.Finding, error) {
	// Only enrich vulnerabilities with CVE IDs
	if finding.Type != ctis.FindingTypeVulnerability {
		return finding, nil
	}
	if finding.Vulnerability == nil || finding.Vulnerability.CVEID == "" {
		return finding, nil
	}

	// Ensure cache is loaded
	if err := e.ensureLoaded(ctx); err != nil {
		if e.Verbose {
			fmt.Printf("[kev] Warning: failed to load KEV catalog: %v\n", err)
		}
		return finding, nil // Don't fail on enrichment errors
	}

	cveID := finding.Vulnerability.CVEID
	kevEntry := e.getKEV(cveID)
	if kevEntry == nil {
		return finding, nil // Not in KEV catalog
	}

	// Add KEV data to finding
	finding.Vulnerability.InCISAKEV = true

	// Mark as actively exploited
	finding.Vulnerability.ExploitAvailable = true
	if kevEntry.KnownRansomware == "Known" {
		finding.Vulnerability.ExploitMaturity = "weaponized"
	} else {
		finding.Vulnerability.ExploitMaturity = "functional"
	}

	// Initialize properties if needed
	if finding.Properties == nil {
		finding.Properties = make(map[string]any)
	}
	finding.Properties["kev_in_catalog"] = true
	finding.Properties["kev_date_added"] = kevEntry.DateAdded
	finding.Properties["kev_due_date"] = kevEntry.DueDate
	finding.Properties["kev_vendor"] = kevEntry.VendorProject
	finding.Properties["kev_product"] = kevEntry.Product
	finding.Properties["kev_required_action"] = kevEntry.RequiredAction
	if kevEntry.KnownRansomware == "Known" {
		finding.Properties["kev_ransomware"] = true
	}

	// Increase severity for KEV entries
	if finding.Severity == ctis.SeverityMedium || finding.Severity == ctis.SeverityHigh {
		finding.Severity = ctis.SeverityCritical
		finding.Properties["severity_elevated_by_kev"] = true
	}

	return finding, nil
}

// EnrichBatch adds KEV data to multiple findings.
func (e *Enricher) EnrichBatch(ctx context.Context, findings []ctis.Finding) ([]ctis.Finding, error) {
	// Ensure cache is loaded
	if err := e.ensureLoaded(ctx); err != nil {
		if e.Verbose {
			fmt.Printf("[kev] Warning: failed to load KEV catalog: %v\n", err)
		}
		// Continue anyway, individual enrichments will return unchanged findings
	}

	// Enrich each finding
	enriched := make([]ctis.Finding, len(findings))
	for i, f := range findings {
		result, _ := e.Enrich(ctx, &f)
		enriched[i] = *result
	}

	return enriched, nil
}

// getKEV retrieves KEV data for a CVE from cache.
func (e *Enricher) getKEV(cveID string) *KEVEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cache[cveID]
}

// ensureLoaded ensures the KEV catalog is loaded.
func (e *Enricher) ensureLoaded(ctx context.Context) error {
	e.mu.RLock()
	if len(e.cache) > 0 && time.Since(e.cacheAt) < e.cacheTTL {
		e.mu.RUnlock()
		return nil
	}
	e.mu.RUnlock()

	return e.loadCatalog(ctx)
}

// loadCatalog fetches and parses the KEV catalog.
func (e *Enricher) loadCatalog(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.KEVURL, nil)
	if err != nil {
		return err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("KEV API returned status %d", resp.StatusCode)
	}

	var catalog KEVCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return err
	}

	// Build cache
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cache = make(map[string]*KEVEntry, len(catalog.Vulnerabilities))
	for i := range catalog.Vulnerabilities {
		entry := &catalog.Vulnerabilities[i]

		// Parse dates
		if entry.DateAdded != "" {
			entry.AddedAt, _ = time.Parse("2006-01-02", entry.DateAdded)
		}
		if entry.DueDate != "" {
			entry.Deadline, _ = time.Parse("2006-01-02", entry.DueDate)
		}

		e.cache[entry.CVEID] = entry
	}

	e.catalogInfo = &catalog
	e.cacheAt = time.Now()

	if e.Verbose {
		fmt.Printf("[kev] Loaded %d KEV entries (catalog version: %s)\n", len(e.cache), catalog.CatalogVersion)
	}

	return nil
}

// IsInKEV checks if a CVE is in the KEV catalog.
func (e *Enricher) IsInKEV(ctx context.Context, cveID string) (bool, error) {
	if err := e.ensureLoaded(ctx); err != nil {
		return false, err
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	_, exists := e.cache[cveID]
	return exists, nil
}

// GetKEVEntry retrieves the full KEV entry for a CVE.
func (e *Enricher) GetKEVEntry(ctx context.Context, cveID string) (*KEVEntry, error) {
	if err := e.ensureLoaded(ctx); err != nil {
		return nil, err
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cache[cveID], nil
}

// GetCatalogInfo returns the KEV catalog metadata.
func (e *Enricher) GetCatalogInfo(ctx context.Context) (*KEVCatalog, error) {
	if err := e.ensureLoaded(ctx); err != nil {
		return nil, err
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Return copy without vulnerabilities
	return &KEVCatalog{
		Title:          e.catalogInfo.Title,
		CatalogVersion: e.catalogInfo.CatalogVersion,
		DateReleased:   e.catalogInfo.DateReleased,
		Count:          e.catalogInfo.Count,
	}, nil
}

// ClearCache clears the KEV cache.
func (e *Enricher) ClearCache() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache = make(map[string]*KEVEntry)
	e.catalogInfo = nil
}

// CacheSize returns the current cache size.
func (e *Enricher) CacheSize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.cache)
}

// GetAllKEVCVEs returns all CVE IDs in the KEV catalog.
func (e *Enricher) GetAllKEVCVEs(ctx context.Context) ([]string, error) {
	if err := e.ensureLoaded(ctx); err != nil {
		return nil, err
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	cves := make([]string, 0, len(e.cache))
	for cve := range e.cache {
		cves = append(cves, cve)
	}
	return cves, nil
}
