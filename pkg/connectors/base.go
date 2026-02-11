// Package connectors provides base implementations and utilities for external system connectors.
package connectors

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/sdk-go/pkg/core"
)

// BaseConnector provides a base implementation for connectors with common functionality
// like rate limiting, authentication, and HTTP client management.
type BaseConnector struct {
	name       string
	connType   string
	baseURL    string
	httpClient *http.Client
	config     *core.ConnectorConfig

	// Rate limiting
	rateLimiter *rate.Limiter

	// State
	connected bool
	mu        sync.RWMutex

	// Debug
	verbose bool
}

// BaseConnectorConfig holds configuration for creating a BaseConnector.
type BaseConnectorConfig struct {
	Name    string
	Type    string // "scm", "cloud", "ticketing", etc.
	BaseURL string
	Config  *core.ConnectorConfig
	Verbose bool
}

// NewBaseConnector creates a new BaseConnector with the given configuration.
func NewBaseConnector(cfg *BaseConnectorConfig) *BaseConnector {
	if cfg.Config == nil {
		cfg.Config = &core.ConnectorConfig{}
	}

	// Default timeout
	timeout := cfg.Config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	bc := &BaseConnector{
		name:     cfg.Name,
		connType: cfg.Type,
		baseURL:  cfg.BaseURL,
		config:   cfg.Config,
		verbose:  cfg.Verbose,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}

	// Setup rate limiter if configured
	if cfg.Config.RateLimit > 0 {
		// Convert requests per hour to rate per second
		rps := float64(cfg.Config.RateLimit) / 3600.0
		burst := cfg.Config.BurstLimit
		if burst <= 0 {
			burst = 10 // default burst
		}
		bc.rateLimiter = rate.NewLimiter(rate.Limit(rps), burst)
	}

	return bc
}

// Name returns the connector name.
func (c *BaseConnector) Name() string {
	return c.name
}

// Type returns the connector type.
func (c *BaseConnector) Type() string {
	return c.connType
}

// Connect establishes connection to the external system.
// Override this method for custom connection logic.
func (c *BaseConnector) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Base implementation just marks as connected
	// Subclasses should override for actual connection logic
	c.connected = true

	if c.verbose {
		fmt.Printf("[%s] Connected to %s\n", c.name, c.baseURL)
	}

	return nil
}

// Close closes the connection.
func (c *BaseConnector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = false

	if c.verbose {
		fmt.Printf("[%s] Disconnected\n", c.name)
	}

	return nil
}

// IsConnected returns true if connected.
func (c *BaseConnector) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// TestConnection verifies the connection is working.
// Override this method for actual connection testing.
func (c *BaseConnector) TestConnection(ctx context.Context) error {
	// Wait for rate limit if enabled
	if err := c.WaitForRateLimit(ctx); err != nil {
		return err
	}

	// Base implementation just checks if connected
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}

	return nil
}

// HTTPClient returns the configured HTTP client.
func (c *BaseConnector) HTTPClient() *http.Client {
	return c.httpClient
}

// RateLimited returns true if rate limiting is enabled.
func (c *BaseConnector) RateLimited() bool {
	return c.rateLimiter != nil
}

// WaitForRateLimit blocks until rate limit allows next request.
func (c *BaseConnector) WaitForRateLimit(ctx context.Context) error {
	if c.rateLimiter == nil {
		return nil
	}

	if c.verbose {
		fmt.Printf("[%s] Waiting for rate limit...\n", c.name)
	}

	return c.rateLimiter.Wait(ctx)
}

// BaseURL returns the base URL.
func (c *BaseConnector) BaseURL() string {
	return c.baseURL
}

// Config returns the connector configuration.
func (c *BaseConnector) Config() *core.ConnectorConfig {
	return c.config
}

// Verbose returns true if verbose mode is enabled.
func (c *BaseConnector) Verbose() bool {
	return c.verbose
}

// SetVerbose enables or disables verbose mode.
func (c *BaseConnector) SetVerbose(v bool) {
	c.verbose = v
}

// =============================================================================
// HTTP Helper Methods
// =============================================================================

// NewRequest creates a new HTTP request with authentication headers.
func (c *BaseConnector) NewRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Add authentication headers
	c.addAuthHeaders(req)

	return req, nil
}

// addAuthHeaders adds authentication headers to the request.
func (c *BaseConnector) addAuthHeaders(req *http.Request) {
	if c.config == nil {
		return
	}

	// Bearer token (most common)
	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
		return
	}

	// API key
	if c.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
		return
	}

	// Basic auth
	if c.config.Username != "" && c.config.Password != "" {
		req.SetBasicAuth(c.config.Username, c.config.Password)
	}
}

// Do executes an HTTP request with rate limiting.
func (c *BaseConnector) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Wait for rate limit
	if err := c.WaitForRateLimit(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}

	if c.verbose {
		fmt.Printf("[%s] %s %s\n", c.name, req.Method, req.URL.Path)
	}

	return c.httpClient.Do(req)
}

// Ensure BaseConnector implements core.Connector interface
var _ core.Connector = (*BaseConnector)(nil)
