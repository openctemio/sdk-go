// Package github provides a GitHub connector for the OpenCTEM SDK.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/openctemio/sdk-go/pkg/connectors"
	"github.com/openctemio/sdk-go/pkg/core"
)

const (
	// DefaultBaseURL is the default GitHub API base URL.
	DefaultBaseURL = "https://api.github.com"

	// DefaultRateLimit is the default rate limit for GitHub API (5000 req/hour for authenticated).
	DefaultRateLimit = 5000
)

// Connector is a GitHub API connector with rate limiting and authentication.
type Connector struct {
	*connectors.BaseConnector
	organization string
}

// Config holds GitHub connector configuration.
type Config struct {
	// Token is the GitHub personal access token or app token.
	Token string `yaml:"token" json:"token"`

	// Organization to scope operations to (optional).
	Organization string `yaml:"organization" json:"organization"`

	// BaseURL for GitHub API (default: https://api.github.com).
	BaseURL string `yaml:"base_url" json:"base_url"`

	// RateLimit in requests per hour (default: 5000 for authenticated users).
	RateLimit int `yaml:"rate_limit" json:"rate_limit"`

	// Verbose enables debug logging.
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// NewConnector creates a new GitHub connector.
func NewConnector(cfg *Config) *Connector {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = DefaultRateLimit
	}

	baseConnector := connectors.NewBaseConnector(&connectors.BaseConnectorConfig{
		Name:    "github",
		Type:    "scm",
		BaseURL: strings.TrimSuffix(cfg.BaseURL, "/"),
		Config: &core.ConnectorConfig{
			Token:      cfg.Token,
			RateLimit:  cfg.RateLimit,
			BurstLimit: 100,
		},
		Verbose: cfg.Verbose,
	})

	return &Connector{
		BaseConnector: baseConnector,
		organization:  cfg.Organization,
	}
}

// Connect establishes connection to GitHub.
func (c *Connector) Connect(ctx context.Context) error {
	if err := c.BaseConnector.Connect(ctx); err != nil {
		return err
	}

	// Verify connection by fetching user info
	return c.TestConnection(ctx)
}

// TestConnection verifies the GitHub API connection.
func (c *Connector) TestConnection(ctx context.Context) error {
	if err := c.WaitForRateLimit(ctx); err != nil {
		return err
	}

	req, err := c.NewRequest(ctx, "GET", "/user", nil)
	if err != nil {
		return err
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("github connection test: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github auth failed: %s - %s", resp.Status, string(body))
	}

	if c.Verbose() {
		var user struct {
			Login string `json:"login"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err == nil {
			fmt.Printf("[github] Authenticated as: %s\n", user.Login)
		}
	}

	return nil
}

// Organization returns the configured organization.
func (c *Connector) Organization() string {
	return c.organization
}

// =============================================================================
// GitHub API Helper Methods
// =============================================================================

// ListRepositories lists repositories for the organization.
func (c *Connector) ListRepositories(ctx context.Context, page, perPage int) ([]Repository, error) {
	if err := c.WaitForRateLimit(ctx); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/orgs/%s/repos?page=%d&per_page=%d", c.organization, page, perPage)
	if c.organization == "" {
		path = fmt.Sprintf("/user/repos?page=%d&per_page=%d", page, perPage)
	}

	req, err := c.NewRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list repositories failed: %s - %s", resp.Status, string(body))
	}

	var repos []Repository
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, fmt.Errorf("decode repositories: %w", err)
	}

	return repos, nil
}

// GetCodeScanningAlerts retrieves code scanning alerts for a repository.
func (c *Connector) GetCodeScanningAlerts(ctx context.Context, owner, repo string, page, perPage int) ([]CodeScanningAlert, error) {
	if err := c.WaitForRateLimit(ctx); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/repos/%s/%s/code-scanning/alerts?page=%d&per_page=%d", owner, repo, page, perPage)

	req, err := c.NewRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get code scanning alerts: %w", err)
	}
	defer resp.Body.Close()

	// 404 means code scanning is not enabled
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get code scanning alerts failed: %s - %s", resp.Status, string(body))
	}

	var alerts []CodeScanningAlert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		return nil, fmt.Errorf("decode alerts: %w", err)
	}

	return alerts, nil
}

// GetDependabotAlerts retrieves Dependabot alerts for a repository.
func (c *Connector) GetDependabotAlerts(ctx context.Context, owner, repo string, page, perPage int) ([]DependabotAlert, error) {
	if err := c.WaitForRateLimit(ctx); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?page=%d&per_page=%d", owner, repo, page, perPage)

	req, err := c.NewRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get dependabot alerts: %w", err)
	}
	defer resp.Body.Close()

	// 404 means dependabot is not enabled
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get dependabot alerts failed: %s - %s", resp.Status, string(body))
	}

	var alerts []DependabotAlert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		return nil, fmt.Errorf("decode dependabot alerts: %w", err)
	}

	return alerts, nil
}

// =============================================================================
// GitHub API Types
// =============================================================================

// Repository represents a GitHub repository.
type Repository struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Description   string `json:"description"`
	Private       bool   `json:"private"`
	HTMLURL       string `json:"html_url"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	Language      string `json:"language"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Visibility    string `json:"visibility"`
}

// CodeScanningAlert represents a GitHub code scanning alert.
type CodeScanningAlert struct {
	Number             int      `json:"number"`
	State              string   `json:"state"`
	Rule               Rule     `json:"rule"`
	Tool               Tool     `json:"tool"`
	MostRecentInstance Instance `json:"most_recent_instance"`
	HTMLURL            string   `json:"html_url"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
}

// Rule represents a code scanning rule.
type Rule struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Name        string   `json:"name"`
	Tags        []string `json:"tags"`
}

// Tool represents a code scanning tool.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Instance represents a code scanning alert instance.
type Instance struct {
	Ref       string   `json:"ref"`
	State     string   `json:"state"`
	CommitSHA string   `json:"commit_sha"`
	Message   Message  `json:"message"`
	Location  Location `json:"location"`
}

// Message in a code scanning alert.
type Message struct {
	Text string `json:"text"`
}

// Location of a code scanning alert.
type Location struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`
}

// DependabotAlert represents a GitHub Dependabot alert.
type DependabotAlert struct {
	Number                int                   `json:"number"`
	State                 string                `json:"state"`
	Dependency            Dependency            `json:"dependency"`
	SecurityAdvisory      SecurityAdvisory      `json:"security_advisory"`
	SecurityVulnerability SecurityVulnerability `json:"security_vulnerability"`
	HTMLURL               string                `json:"html_url"`
	CreatedAt             string                `json:"created_at"`
	UpdatedAt             string                `json:"updated_at"`
}

// Dependency in a Dependabot alert.
type Dependency struct {
	Package      Package `json:"package"`
	ManifestPath string  `json:"manifest_path"`
	Scope        string  `json:"scope"`
}

// Package in a Dependabot alert.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// SecurityAdvisory in a Dependabot alert.
type SecurityAdvisory struct {
	GHSAID      string  `json:"ghsa_id"`
	CVEID       string  `json:"cve_id"`
	Summary     string  `json:"summary"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score,omitempty"`
	CWEs        []CWE   `json:"cwes"`
}

// CWE in a security advisory.
type CWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// SecurityVulnerability in a Dependabot alert.
type SecurityVulnerability struct {
	Package                Package `json:"package"`
	Severity               string  `json:"severity"`
	VulnerableVersionRange string  `json:"vulnerable_version_range"`
	FirstPatchedVersion    *struct {
		Identifier string `json:"identifier"`
	} `json:"first_patched_version"`
}
