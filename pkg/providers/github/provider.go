// Package github provides a GitHub provider for the OpenCTEM SDK.
package github

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/connectors/github"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Provider is a complete GitHub integration bundle.
type Provider struct {
	name       string
	connector  *github.Connector
	collectors map[string]core.Collector
	config     *Config
	verbose    bool
	mu         sync.RWMutex
}

// Config holds GitHub provider configuration.
type Config struct {
	// Token is the GitHub personal access token.
	Token string `yaml:"token" json:"token"`

	// Organization to scope operations to.
	Organization string `yaml:"organization" json:"organization"`

	// BaseURL for GitHub API (default: https://api.github.com).
	BaseURL string `yaml:"base_url" json:"base_url"`

	// RateLimit in requests per hour.
	RateLimit int `yaml:"rate_limit" json:"rate_limit"`

	// EnabledCollectors specifies which collectors to enable (empty = all).
	EnabledCollectors []string `yaml:"enabled_collectors" json:"enabled_collectors"`

	// Verbose enables debug logging.
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// NewProvider creates a new GitHub provider.
func NewProvider(cfg *Config) *Provider {
	connector := github.NewConnector(&github.Config{
		Token:        cfg.Token,
		Organization: cfg.Organization,
		BaseURL:      cfg.BaseURL,
		RateLimit:    cfg.RateLimit,
		Verbose:      cfg.Verbose,
	})

	p := &Provider{
		name:       "github",
		connector:  connector,
		collectors: make(map[string]core.Collector),
		config:     cfg,
		verbose:    cfg.Verbose,
	}

	// Register collectors
	p.registerCollectors(cfg.EnabledCollectors)

	return p
}

// registerCollectors registers available collectors.
func (p *Provider) registerCollectors(enabled []string) {
	allCollectors := map[string]func() core.Collector{
		"repos":         func() core.Collector { return NewRepoCollector(p.connector, p.verbose) },
		"code-scanning": func() core.Collector { return NewCodeScanningCollector(p.connector, p.verbose) },
		"dependabot":    func() core.Collector { return NewDependabotCollector(p.connector, p.verbose) },
	}

	// If no specific collectors enabled, enable all
	if len(enabled) == 0 {
		for name, factory := range allCollectors {
			p.collectors[name] = factory()
		}
		return
	}

	// Enable only specified collectors
	for _, name := range enabled {
		if factory, ok := allCollectors[name]; ok {
			p.collectors[name] = factory()
		}
	}
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return p.name
}

// Connector returns the underlying connector.
func (p *Provider) Connector() core.Connector {
	return p.connector
}

// ListCollectors returns all available collectors.
func (p *Provider) ListCollectors() []core.Collector {
	p.mu.RLock()
	defer p.mu.RUnlock()

	collectors := make([]core.Collector, 0, len(p.collectors))
	for _, c := range p.collectors {
		collectors = append(collectors, c)
	}
	return collectors
}

// GetCollector returns a specific collector by name.
func (p *Provider) GetCollector(name string) (core.Collector, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if c, ok := p.collectors[name]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("collector not found: %s", name)
}

// Initialize sets up the provider.
func (p *Provider) Initialize(ctx context.Context, config *core.ProviderConfig) error {
	return p.connector.Connect(ctx)
}

// TestConnection tests the provider connection.
func (p *Provider) TestConnection(ctx context.Context) error {
	return p.connector.TestConnection(ctx)
}

// Close closes the provider.
func (p *Provider) Close() error {
	return p.connector.Close()
}

// =============================================================================
// Repo Collector
// =============================================================================

// RepoCollector collects repository information from GitHub.
type RepoCollector struct {
	connector *github.Connector
	verbose   bool
}

// NewRepoCollector creates a new repo collector.
func NewRepoCollector(connector *github.Connector, verbose bool) *RepoCollector {
	return &RepoCollector{connector: connector, verbose: verbose}
}

func (c *RepoCollector) Name() string { return "github-repos" }
func (c *RepoCollector) Type() string { return "scm" }

func (c *RepoCollector) Collect(ctx context.Context, opts *core.CollectOptions) (*core.CollectResult, error) {
	start := time.Now()

	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	maxPages := opts.MaxPages
	if maxPages <= 0 {
		maxPages = 10
	}

	var allRepos []github.Repository
	for page := 1; page <= maxPages; page++ {
		repos, err := c.connector.ListRepositories(ctx, page, pageSize)
		if err != nil {
			return nil, err
		}
		allRepos = append(allRepos, repos...)
		if len(repos) < pageSize {
			break
		}
	}

	// Convert to CTIS assets
	report := ctis.NewReport()
	report.Tool = &ctis.Tool{Name: c.Name(), Version: "1.0"}
	report.Metadata.SourceType = "collector"

	for _, repo := range allRepos {
		asset := ctis.Asset{
			ID:          fmt.Sprintf("repo-%d", repo.ID),
			Type:        ctis.AssetTypeRepository,
			Value:       repo.FullName,
			Name:        repo.Name,
			Description: repo.Description,
			Technical: &ctis.AssetTechnical{
				Repository: &ctis.RepositoryTechnical{
					Platform:      "github",
					Owner:         c.connector.Organization(),
					Name:          repo.Name,
					DefaultBranch: repo.DefaultBranch,
					Visibility:    repo.Visibility,
					URL:           repo.HTMLURL,
					CloneURL:      repo.CloneURL,
				},
			},
		}
		report.Assets = append(report.Assets, asset)
	}

	return &core.CollectResult{
		SourceName:  c.Name(),
		SourceType:  c.Type(),
		CollectedAt: time.Now().Unix(),
		DurationMs:  time.Since(start).Milliseconds(),
		Reports:     []*ctis.Report{report},
		TotalItems:  len(allRepos),
	}, nil
}

func (c *RepoCollector) TestConnection(ctx context.Context) error {
	return c.connector.TestConnection(ctx)
}

// =============================================================================
// Code Scanning Collector
// =============================================================================

// CodeScanningCollector collects code scanning alerts from GitHub.
type CodeScanningCollector struct {
	connector *github.Connector
	verbose   bool
}

// NewCodeScanningCollector creates a new code scanning collector.
func NewCodeScanningCollector(connector *github.Connector, verbose bool) *CodeScanningCollector {
	return &CodeScanningCollector{connector: connector, verbose: verbose}
}

func (c *CodeScanningCollector) Name() string { return "github-code-scanning" }
func (c *CodeScanningCollector) Type() string { return "vulnerability" }

func (c *CodeScanningCollector) Collect(ctx context.Context, opts *core.CollectOptions) (*core.CollectResult, error) {
	start := time.Now()

	// Get repository from options
	repo := opts.Repository
	if repo == "" {
		return nil, fmt.Errorf("repository is required")
	}

	// Parse owner/repo
	parts := splitRepo(repo)
	owner, repoName := parts[0], parts[1]

	alerts, err := c.connector.GetCodeScanningAlerts(ctx, owner, repoName, 1, 100)
	if err != nil {
		return nil, err
	}

	// Convert to CTIS findings
	report := ctis.NewReport()
	report.Tool = &ctis.Tool{Name: c.Name(), Version: "1.0"}
	report.Metadata.SourceType = "collector"

	for _, alert := range alerts {
		finding := ctis.Finding{
			ID:          fmt.Sprintf("github-cs-%d", alert.Number),
			Type:        ctis.FindingTypeVulnerability,
			Title:       alert.Rule.Name,
			Description: alert.Rule.Description,
			Severity:    mapSeverity(alert.Rule.Severity),
			RuleID:      alert.Rule.ID,
			RuleName:    alert.Rule.Name,
			Location: &ctis.FindingLocation{
				Path:        alert.MostRecentInstance.Location.Path,
				StartLine:   alert.MostRecentInstance.Location.StartLine,
				EndLine:     alert.MostRecentInstance.Location.EndLine,
				StartColumn: alert.MostRecentInstance.Location.StartColumn,
				EndColumn:   alert.MostRecentInstance.Location.EndColumn,
			},
			References: []string{alert.HTMLURL},
		}
		report.Findings = append(report.Findings, finding)
	}

	return &core.CollectResult{
		SourceName:  c.Name(),
		SourceType:  c.Type(),
		CollectedAt: time.Now().Unix(),
		DurationMs:  time.Since(start).Milliseconds(),
		Reports:     []*ctis.Report{report},
		TotalItems:  len(alerts),
	}, nil
}

func (c *CodeScanningCollector) TestConnection(ctx context.Context) error {
	return c.connector.TestConnection(ctx)
}

// =============================================================================
// Dependabot Collector
// =============================================================================

// DependabotCollector collects Dependabot alerts from GitHub.
type DependabotCollector struct {
	connector *github.Connector
	verbose   bool
}

// NewDependabotCollector creates a new Dependabot collector.
func NewDependabotCollector(connector *github.Connector, verbose bool) *DependabotCollector {
	return &DependabotCollector{connector: connector, verbose: verbose}
}

func (c *DependabotCollector) Name() string { return "github-dependabot" }
func (c *DependabotCollector) Type() string { return "sca" }

func (c *DependabotCollector) Collect(ctx context.Context, opts *core.CollectOptions) (*core.CollectResult, error) {
	start := time.Now()

	repo := opts.Repository
	if repo == "" {
		return nil, fmt.Errorf("repository is required")
	}

	parts := splitRepo(repo)
	owner, repoName := parts[0], parts[1]

	alerts, err := c.connector.GetDependabotAlerts(ctx, owner, repoName, 1, 100)
	if err != nil {
		return nil, err
	}

	// Convert to CTIS findings
	report := ctis.NewReport()
	report.Tool = &ctis.Tool{Name: c.Name(), Version: "1.0"}
	report.Metadata.SourceType = "collector"

	for _, alert := range alerts {
		finding := ctis.Finding{
			ID:          fmt.Sprintf("github-dep-%d", alert.Number),
			Type:        ctis.FindingTypeVulnerability,
			Title:       alert.SecurityAdvisory.Summary,
			Description: alert.SecurityAdvisory.Description,
			Severity:    mapSeverity(alert.SecurityAdvisory.Severity),
			Vulnerability: &ctis.VulnerabilityDetails{
				CVEID:                alert.SecurityAdvisory.CVEID,
				Package:              alert.Dependency.Package.Name,
				AffectedVersionRange: alert.SecurityVulnerability.VulnerableVersionRange,
				Ecosystem:            alert.Dependency.Package.Ecosystem,
			},
			Location: &ctis.FindingLocation{
				Path: alert.Dependency.ManifestPath,
			},
			References: []string{alert.HTMLURL, alert.SecurityAdvisory.GHSAID},
		}

		if alert.SecurityVulnerability.FirstPatchedVersion != nil {
			finding.Vulnerability.FixedVersion = alert.SecurityVulnerability.FirstPatchedVersion.Identifier
		}

		report.Findings = append(report.Findings, finding)
	}

	return &core.CollectResult{
		SourceName:  c.Name(),
		SourceType:  c.Type(),
		CollectedAt: time.Now().Unix(),
		DurationMs:  time.Since(start).Milliseconds(),
		Reports:     []*ctis.Report{report},
		TotalItems:  len(alerts),
	}, nil
}

func (c *DependabotCollector) TestConnection(ctx context.Context) error {
	return c.connector.TestConnection(ctx)
}

// =============================================================================
// Helper functions
// =============================================================================

func splitRepo(repo string) []string {
	parts := make([]string, 2)
	for i, p := range splitString(repo, "/") {
		if i < 2 {
			parts[i] = p
		}
	}
	return parts
}

func splitString(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func mapSeverity(severity string) ctis.Severity {
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
