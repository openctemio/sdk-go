// Package epss provides EPSS (Exploit Prediction Scoring System) enrichment for CVEs.
// EPSS provides data-driven estimates of the likelihood that a CVE will be exploited in the wild.
// Data source: https://www.first.org/epss
package epss

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

const (
	// DefaultEPSSURL is the official EPSS API endpoint.
	DefaultEPSSURL = "https://api.first.org/data/v1/epss"

	// DefaultCacheSize is the default LRU cache size.
	DefaultCacheSize = 10000

	// DefaultCacheTTL is the default cache TTL (EPSS updates daily).
	DefaultCacheTTL = 24 * time.Hour

	// DefaultTimeout is the default HTTP timeout.
	DefaultTimeout = 30 * time.Second
)

// EPSSData represents EPSS data for a CVE.
type EPSSData struct {
	CVE        string    `json:"cve"`
	EPSS       float64   `json:"epss"`       // Probability score (0-1)
	Percentile float64   `json:"percentile"` // Percentile rank (0-100)
	Date       time.Time `json:"date"`       // Score date
}

// Enricher implements the core.Enricher interface for EPSS.
type Enricher struct {
	mu sync.RWMutex

	// Configuration
	EPSSURL string
	Timeout time.Duration
	Verbose bool

	// HTTP client
	client *http.Client

	// Cache
	cache    map[string]*EPSSData
	cacheTTL time.Duration
	cacheAt  time.Time
}

// NewEnricher creates a new EPSS enricher with default settings.
func NewEnricher() *Enricher {
	return &Enricher{
		EPSSURL:  DefaultEPSSURL,
		Timeout:  DefaultTimeout,
		cache:    make(map[string]*EPSSData),
		cacheTTL: DefaultCacheTTL,
		// SSRF hygiene: EPSS endpoint can be overridden via
		// EnricherConfig.Endpoint. Dialer-level blocklist stops a
		// misconfigured endpoint landing on private ranges.
		client: httpsec.SafeHTTPClient(DefaultTimeout),
	}
}

// NewEnricherWithConfig creates a new EPSS enricher with custom configuration.
func NewEnricherWithConfig(cfg *core.EnricherConfig) *Enricher {
	e := NewEnricher()
	if cfg != nil {
		if cfg.Endpoint != "" {
			e.EPSSURL = cfg.Endpoint
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
	return "epss"
}

// Enrich adds EPSS data to a single finding.
func (e *Enricher) Enrich(ctx context.Context, finding *ctis.Finding) (*ctis.Finding, error) {
	// Only enrich vulnerabilities with CVE IDs
	if finding.Type != ctis.FindingTypeVulnerability {
		return finding, nil
	}
	if finding.Vulnerability == nil || finding.Vulnerability.CVEID == "" {
		return finding, nil
	}

	cveID := finding.Vulnerability.CVEID
	epssData, err := e.getEPSS(ctx, cveID)
	if err != nil {
		if e.Verbose {
			fmt.Printf("[epss] Warning: failed to get EPSS for %s: %v\n", cveID, err)
		}
		return finding, nil // Don't fail on enrichment errors
	}

	if epssData == nil {
		return finding, nil // No EPSS data available
	}

	// Add EPSS data to finding
	finding.Vulnerability.EPSSScore = epssData.EPSS
	finding.Vulnerability.EPSSPercentile = epssData.Percentile

	// Initialize properties if needed
	if finding.Properties == nil {
		finding.Properties = make(map[string]any)
	}
	finding.Properties["epss_score"] = epssData.EPSS
	finding.Properties["epss_percentile"] = epssData.Percentile
	finding.Properties["epss_date"] = epssData.Date.Format("2006-01-02")

	return finding, nil
}

// EnrichBatch adds EPSS data to multiple findings.
func (e *Enricher) EnrichBatch(ctx context.Context, findings []ctis.Finding) ([]ctis.Finding, error) {
	// Collect unique CVE IDs
	cveIDs := make(map[string]bool)
	for _, f := range findings {
		if f.Type == ctis.FindingTypeVulnerability && f.Vulnerability != nil && f.Vulnerability.CVEID != "" {
			cveIDs[f.Vulnerability.CVEID] = true
		}
	}

	if len(cveIDs) == 0 {
		return findings, nil
	}

	// Fetch EPSS data in batch
	cveList := make([]string, 0, len(cveIDs))
	for cve := range cveIDs {
		cveList = append(cveList, cve)
	}

	if err := e.fetchBatch(ctx, cveList); err != nil {
		if e.Verbose {
			fmt.Printf("[epss] Warning: batch fetch failed: %v\n", err)
		}
		// Continue with individual enrichment using cache
	}

	// Enrich each finding
	enriched := make([]ctis.Finding, len(findings))
	for i, f := range findings {
		result, _ := e.Enrich(ctx, &f)
		enriched[i] = *result
	}

	return enriched, nil
}

// getEPSS retrieves EPSS data for a single CVE from cache or API.
func (e *Enricher) getEPSS(ctx context.Context, cveID string) (*EPSSData, error) {
	// Check cache
	e.mu.RLock()
	if data, ok := e.cache[cveID]; ok {
		if time.Since(e.cacheAt) < e.cacheTTL {
			e.mu.RUnlock()
			return data, nil
		}
	}
	e.mu.RUnlock()

	// Fetch from API
	url := fmt.Sprintf("%s?cve=%s", e.EPSSURL, cveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var result struct {
		Status     string `json:"status"`
		StatusCode int    `json:"status-code"`
		Version    string `json:"version"`
		Total      int    `json:"total"`
		Data       []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Data) == 0 {
		return nil, nil // No data available
	}

	item := result.Data[0]
	epss, _ := strconv.ParseFloat(item.EPSS, 64)
	percentile, _ := strconv.ParseFloat(item.Percentile, 64)
	date, _ := time.Parse("2006-01-02", item.Date)

	data := &EPSSData{
		CVE:        item.CVE,
		EPSS:       epss,
		Percentile: percentile * 100, // Convert to percentage
		Date:       date,
	}

	// Update cache
	e.mu.Lock()
	e.cache[cveID] = data
	e.cacheAt = time.Now()
	e.mu.Unlock()

	return data, nil
}

// fetchBatch fetches EPSS data for multiple CVEs.
func (e *Enricher) fetchBatch(ctx context.Context, cveIDs []string) error {
	if len(cveIDs) == 0 {
		return nil
	}

	// Build URL with multiple CVEs
	url := fmt.Sprintf("%s?cve=%s", e.EPSSURL, strings.Join(cveIDs, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var result struct {
		Status     string `json:"status"`
		StatusCode int    `json:"status-code"`
		Version    string `json:"version"`
		Total      int    `json:"total"`
		Data       []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	// Update cache
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, item := range result.Data {
		epss, _ := strconv.ParseFloat(item.EPSS, 64)
		percentile, _ := strconv.ParseFloat(item.Percentile, 64)
		date, _ := time.Parse("2006-01-02", item.Date)

		e.cache[item.CVE] = &EPSSData{
			CVE:        item.CVE,
			EPSS:       epss,
			Percentile: percentile * 100,
			Date:       date,
		}
	}
	e.cacheAt = time.Now()

	return nil
}

// LoadFromCSV loads EPSS data from a CSV file (for offline use).
// The CSV should have columns: cve, epss, percentile
func (e *Enricher) LoadFromCSV(r io.Reader) error {
	reader := csv.NewReader(r)

	// Skip header
	_, err := reader.Read()
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(record) < 3 {
			continue
		}

		cve := record[0]
		epss, _ := strconv.ParseFloat(record[1], 64)
		percentile, _ := strconv.ParseFloat(record[2], 64)

		e.cache[cve] = &EPSSData{
			CVE:        cve,
			EPSS:       epss,
			Percentile: percentile * 100,
			Date:       time.Now(),
		}
	}

	e.cacheAt = time.Now()
	return nil
}

// ClearCache clears the EPSS cache.
func (e *Enricher) ClearCache() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache = make(map[string]*EPSSData)
}

// CacheSize returns the current cache size.
func (e *Enricher) CacheSize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.cache)
}
