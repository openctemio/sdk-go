package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// =============================================================================
// BaseCollector - Base implementation for collectors
// =============================================================================

// BaseCollector provides a base implementation for collectors.
// Embed this in your custom collector to get common functionality.
type BaseCollector struct {
	name       string
	sourceType string
	baseURL    string
	apiKey     string
	headers    map[string]string
	timeout    time.Duration
	httpClient *http.Client
	verbose    bool
}

// BaseCollectorConfig configures a BaseCollector.
type BaseCollectorConfig struct {
	Name       string            `yaml:"name" json:"name"`
	SourceType string            `yaml:"source_type" json:"source_type"`
	BaseURL    string            `yaml:"base_url" json:"base_url"`
	APIKey     string            `yaml:"api_key" json:"api_key"`
	Headers    map[string]string `yaml:"headers" json:"headers"`
	Timeout    time.Duration     `yaml:"timeout" json:"timeout"`
	Verbose    bool              `yaml:"verbose" json:"verbose"`
}

// NewBaseCollector creates a new base collector.
func NewBaseCollector(cfg *BaseCollectorConfig) *BaseCollector {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &BaseCollector{
		name:       cfg.Name,
		sourceType: cfg.SourceType,
		baseURL:    cfg.BaseURL,
		apiKey:     cfg.APIKey,
		headers:    cfg.Headers,
		timeout:    cfg.Timeout,
		// SSRF: BaseURL is caller-supplied config; SafeHTTPClient
		// refuses to dial RFC1918/link-local/CGNAT even if the
		// collector author forgets to validate.
		httpClient: httpsec.SafeHTTPClient(cfg.Timeout),
		verbose:    cfg.Verbose,
	}
}

// Name returns the collector name.
func (c *BaseCollector) Name() string {
	return c.name
}

// Type returns the source type.
func (c *BaseCollector) Type() string {
	return c.sourceType
}

// TestConnection tests the connection to the source.
func (c *BaseCollector) TestConnection(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}

// Collect is the base collect method - override in your implementation.
func (c *BaseCollector) Collect(ctx context.Context, opts *CollectOptions) (*CollectResult, error) {
	return nil, fmt.Errorf("Collect not implemented - override this method in your collector")
}

// FetchJSON makes an HTTP GET request and decodes JSON response.
func (c *BaseCollector) FetchJSON(ctx context.Context, path string, query map[string]string, result interface{}) error {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}

	// Add query parameters
	q := u.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	c.setHeaders(req)

	if c.verbose {
		fmt.Printf("[%s] GET %s\n", c.name, u.String())
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

// setHeaders sets common headers on the request.
func (c *BaseCollector) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sdk/1.0")

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
}

// SetVerbose sets verbose mode.
func (c *BaseCollector) SetVerbose(v bool) {
	c.verbose = v
}

// =============================================================================
// GitHub Collector - Pull from GitHub Advanced Security
// =============================================================================

// GitHubCollector pulls security alerts from GitHub Advanced Security.
type GitHubCollector struct {
	*BaseCollector
	owner string
	repo  string
}

// GitHubCollectorConfig configures a GitHub collector.
type GitHubCollectorConfig struct {
	Token   string `yaml:"token" json:"token"`
	Owner   string `yaml:"owner" json:"owner"`
	Repo    string `yaml:"repo" json:"repo"`
	Verbose bool   `yaml:"verbose" json:"verbose"`
}

// NewGitHubCollector creates a new GitHub collector.
func NewGitHubCollector(cfg *GitHubCollectorConfig) *GitHubCollector {
	return &GitHubCollector{
		BaseCollector: NewBaseCollector(&BaseCollectorConfig{
			Name:       "github",
			SourceType: "github",
			BaseURL:    "https://api.github.com",
			APIKey:     cfg.Token,
			Timeout:    30 * time.Second,
			Verbose:    cfg.Verbose,
		}),
		owner: cfg.Owner,
		repo:  cfg.Repo,
	}
}

// Collect pulls security alerts from GitHub.
func (c *GitHubCollector) Collect(ctx context.Context, opts *CollectOptions) (*CollectResult, error) {
	startTime := time.Now()
	result := &CollectResult{
		SourceName: c.name,
		SourceType: c.sourceType,
	}

	// Fetch code scanning alerts
	report := ctis.NewReport()
	report.Tool = &ctis.Tool{
		Name:         "GitHub Code Scanning",
		Capabilities: []string{"sast"},
	}

	// Add repository as asset
	repoFullName := fmt.Sprintf("%s/%s", c.owner, c.repo)
	report.Assets = append(report.Assets, ctis.Asset{
		ID:          "repo-1",
		Type:        ctis.AssetTypeRepository,
		Value:       fmt.Sprintf("https://github.com/%s", repoFullName),
		Name:        repoFullName,
		Criticality: ctis.CriticalityHigh,
	})

	// Fetch code scanning alerts
	path := fmt.Sprintf("/repos/%s/%s/code-scanning/alerts", c.owner, c.repo)
	var alerts []GitHubCodeScanningAlert

	if err := c.FetchJSON(ctx, path, nil, &alerts); err != nil {
		// Return partial result on error
		result.Reports = []*ctis.Report{report}
		result.CollectedAt = time.Now().Unix()
		result.DurationMs = time.Since(startTime).Milliseconds()
		return result, fmt.Errorf("fetch code scanning alerts: %w", err)
	}

	// Convert alerts to findings
	for i, alert := range alerts {
		finding := ctis.Finding{
			ID:          fmt.Sprintf("github-%d", alert.Number),
			Type:        ctis.FindingTypeVulnerability,
			Title:       alert.Rule.Description,
			Description: alert.MostRecentInstance.Message.Text,
			Severity:    mapGitHubSeverity(alert.Rule.Severity),
			Confidence:  mapGitHubConfidence(alert.Rule.SecuritySeverityLevel),
			RuleID:      alert.Rule.ID,
			AssetRef:    "repo-1",
			Location: &ctis.FindingLocation{
				Path:      alert.MostRecentInstance.Location.Path,
				StartLine: alert.MostRecentInstance.Location.StartLine,
				EndLine:   alert.MostRecentInstance.Location.EndLine,
			},
			References: []string{alert.HTMLURL},
		}

		// Add CWE if available
		if len(alert.Rule.Tags) > 0 {
			for _, tag := range alert.Rule.Tags {
				if len(tag) > 4 && tag[:4] == "cwe-" {
					finding.Vulnerability = &ctis.VulnerabilityDetails{
						CWEID: tag,
					}
					break
				}
			}
		}

		report.Findings = append(report.Findings, finding)
		_ = i // silence unused warning
	}

	result.Reports = []*ctis.Report{report}
	result.TotalItems = len(alerts)
	result.CollectedAt = time.Now().Unix()
	result.DurationMs = time.Since(startTime).Milliseconds()

	if c.verbose {
		fmt.Printf("[%s] Collected %d code scanning alerts\n", c.name, len(alerts))
	}

	return result, nil
}

// GitHub API types

// GitHubCodeScanningAlert represents a GitHub code scanning alert.
type GitHubCodeScanningAlert struct {
	Number             int                 `json:"number"`
	State              string              `json:"state"`
	HTMLURL            string              `json:"html_url"`
	Rule               GitHubAlertRule     `json:"rule"`
	Tool               GitHubAlertTool     `json:"tool"`
	MostRecentInstance GitHubAlertInstance `json:"most_recent_instance"`
	CreatedAt          string              `json:"created_at"`
}

// GitHubAlertRule represents the rule that triggered the alert.
type GitHubAlertRule struct {
	ID                    string   `json:"id"`
	Severity              string   `json:"severity"`
	SecuritySeverityLevel string   `json:"security_severity_level"`
	Description           string   `json:"description"`
	Tags                  []string `json:"tags"`
}

// GitHubAlertTool represents the tool that found the alert.
type GitHubAlertTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// GitHubAlertInstance represents an instance of the alert.
type GitHubAlertInstance struct {
	Ref      string              `json:"ref"`
	State    string              `json:"state"`
	Location GitHubAlertLocation `json:"location"`
	Message  GitHubAlertMessage  `json:"message"`
}

// GitHubAlertLocation represents the location of the alert.
type GitHubAlertLocation struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`
}

// GitHubAlertMessage represents the alert message.
type GitHubAlertMessage struct {
	Text string `json:"text"`
}

// mapGitHubSeverity maps GitHub severity to CTIS severity.
func mapGitHubSeverity(severity string) ctis.Severity {
	switch severity {
	case "critical":
		return ctis.SeverityCritical
	case "high":
		return ctis.SeverityHigh
	case "medium":
		return ctis.SeverityMedium
	case "low":
		return ctis.SeverityLow
	default:
		return ctis.SeverityInfo
	}
}

// mapGitHubConfidence maps GitHub security severity level to confidence.
func mapGitHubConfidence(level string) int {
	switch level {
	case "critical":
		return 95
	case "high":
		return 85
	case "medium":
		return 70
	case "low":
		return 50
	default:
		return 60
	}
}

// =============================================================================
// Webhook Collector - Receive data via webhooks
// =============================================================================

// WebhookCollector receives data via HTTP webhooks.
type WebhookCollector struct {
	*BaseCollector
	listenAddr string
	server     *http.Server
	dataChan   chan []byte
}

// WebhookCollectorConfig configures a webhook collector.
type WebhookCollectorConfig struct {
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
	Secret     string `yaml:"secret" json:"secret"`
	Verbose    bool   `yaml:"verbose" json:"verbose"`
}

// NewWebhookCollector creates a new webhook collector.
func NewWebhookCollector(cfg *WebhookCollectorConfig) *WebhookCollector {
	addr := cfg.ListenAddr
	if addr == "" {
		addr = ":8080"
	}

	return &WebhookCollector{
		BaseCollector: NewBaseCollector(&BaseCollectorConfig{
			Name:       "webhook",
			SourceType: "webhook",
			Verbose:    cfg.Verbose,
		}),
		listenAddr: addr,
		dataChan:   make(chan []byte, 100),
	}
}

// Collect waits for webhook data (blocking).
func (c *WebhookCollector) Collect(ctx context.Context, opts *CollectOptions) (*CollectResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data := <-c.dataChan:
		// Parse the received data
		report := ctis.NewReport()
		if err := json.Unmarshal(data, report); err != nil {
			return nil, fmt.Errorf("parse webhook data: %w", err)
		}

		return &CollectResult{
			SourceName:  c.name,
			SourceType:  c.sourceType,
			Reports:     []*ctis.Report{report},
			TotalItems:  len(report.Findings),
			CollectedAt: time.Now().Unix(),
		}, nil
	}
}

// Start starts the webhook server.
func (c *WebhookCollector) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", c.handleWebhook)
	mux.HandleFunc("/health", c.handleHealth)

	c.server = &http.Server{
		Addr:              c.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
	}

	if c.verbose {
		fmt.Printf("[%s] Starting webhook server on %s\n", c.name, c.listenAddr)
	}

	go func() {
		if err := c.server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("[%s] Server error: %v\n", c.name, err)
		}
	}()

	return nil
}

// Stop stops the webhook server.
func (c *WebhookCollector) Stop(ctx context.Context) error {
	if c.server != nil {
		return c.server.Shutdown(ctx)
	}
	return nil
}

func (c *WebhookCollector) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	if c.verbose {
		fmt.Printf("[%s] Received webhook: %d bytes\n", c.name, len(body))
	}

	select {
	case c.dataChan <- body:
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	default:
		http.Error(w, "Queue full", http.StatusServiceUnavailable)
	}
}

func (c *WebhookCollector) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy"}`))
}
