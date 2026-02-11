// Package options provides functional options pattern for SDK configuration.
// This follows AWS SDK, gRPC, and other industry-standard Go SDKs.
package options

import (
	"time"
)

// =============================================================================
// Client Options
// =============================================================================

// ClientConfig holds the final client configuration.
type ClientConfig struct {
	BaseURL          string
	APIKey           string
	AgentID          string // Agent ID for tracking which agent is pushing
	Timeout          time.Duration
	MaxRetries       int
	RetryDelay       time.Duration
	EnableRetryQueue bool
	RetryQueueDir    string
	Verbose          bool
}

// ClientOption is a function that configures the client.
type ClientOption func(*ClientConfig)

// DefaultClientConfig returns default client configuration.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 2 * time.Second,
	}
}

// ApplyClientOptions applies options to config.
func ApplyClientOptions(cfg *ClientConfig, opts ...ClientOption) {
	for _, opt := range opts {
		opt(cfg)
	}
}

// WithBaseURL sets the API base URL.
func WithBaseURL(url string) ClientOption {
	return func(c *ClientConfig) {
		c.BaseURL = url
	}
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) ClientOption {
	return func(c *ClientConfig) {
		c.APIKey = key
	}
}

// WithAgentID sets the agent ID for tracking which agent is pushing data.
func WithAgentID(id string) ClientOption {
	return func(c *ClientConfig) {
		c.AgentID = id
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.Timeout = d
	}
}

// WithRetry sets retry configuration.
func WithRetry(maxRetries int, retryDelay time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.MaxRetries = maxRetries
		c.RetryDelay = retryDelay
	}
}

// WithRetryQueue enables the retry queue.
func WithRetryQueue(dir string) ClientOption {
	return func(c *ClientConfig) {
		c.EnableRetryQueue = true
		c.RetryQueueDir = dir
	}
}

// WithVerbose enables verbose logging.
func WithVerbose(v bool) ClientOption {
	return func(c *ClientConfig) {
		c.Verbose = v
	}
}

// =============================================================================
// Connector Options
// =============================================================================

// ConnectorConfig holds connector configuration.
type ConnectorConfig struct {
	Name       string
	Type       string
	BaseURL    string
	APIKey     string
	Token      string
	RateLimit  int
	BurstLimit int
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration
	Verbose    bool
}

// ConnectorOption is a function that configures a connector.
type ConnectorOption func(*ConnectorConfig)

// DefaultConnectorConfig returns default connector configuration.
func DefaultConnectorConfig() *ConnectorConfig {
	return &ConnectorConfig{
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 1 * time.Second,
		BurstLimit: 10,
	}
}

// ApplyConnectorOptions applies options to config.
func ApplyConnectorOptions(cfg *ConnectorConfig, opts ...ConnectorOption) {
	for _, opt := range opts {
		opt(cfg)
	}
}

// WithConnectorName sets the connector name.
func WithConnectorName(name string) ConnectorOption {
	return func(c *ConnectorConfig) {
		c.Name = name
	}
}

// WithConnectorType sets the connector type.
func WithConnectorType(t string) ConnectorOption {
	return func(c *ConnectorConfig) {
		c.Type = t
	}
}

// WithConnectorBaseURL sets the base URL.
func WithConnectorBaseURL(url string) ConnectorOption {
	return func(c *ConnectorConfig) {
		c.BaseURL = url
	}
}

// WithConnectorToken sets the auth token.
func WithConnectorToken(token string) ConnectorOption {
	return func(c *ConnectorConfig) {
		c.Token = token
	}
}

// WithConnectorRateLimit sets rate limiting.
func WithConnectorRateLimit(rps int, burst int) ConnectorOption {
	return func(c *ConnectorConfig) {
		c.RateLimit = rps
		c.BurstLimit = burst
	}
}

// =============================================================================
// gRPC Options
// =============================================================================

// GRPCConfig holds gRPC transport configuration.
type GRPCConfig struct {
	Address            string
	APIKey             string
	AgentID            string // Agent ID for tracking
	UseTLS             bool
	InsecureSkipVerify bool
	CertFile           string
	Timeout            time.Duration
	KeepAliveTime      time.Duration
	KeepAliveTimeout   time.Duration
	MaxRecvMsgSize     int
	MaxSendMsgSize     int
	Verbose            bool
}

// GRPCOption is a function that configures gRPC transport.
type GRPCOption func(*GRPCConfig)

// DefaultGRPCConfig returns default gRPC configuration.
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		Address:          "localhost:9090",
		UseTLS:           true,
		Timeout:          30 * time.Second,
		KeepAliveTime:    30 * time.Second,
		KeepAliveTimeout: 10 * time.Second,
		MaxRecvMsgSize:   50 * 1024 * 1024, // 50MB
		MaxSendMsgSize:   50 * 1024 * 1024, // 50MB
	}
}

// ApplyGRPCOptions applies options to config.
func ApplyGRPCOptions(cfg *GRPCConfig, opts ...GRPCOption) {
	for _, opt := range opts {
		opt(cfg)
	}
}

// WithGRPCAddress sets the server address.
func WithGRPCAddress(addr string) GRPCOption {
	return func(c *GRPCConfig) {
		c.Address = addr
	}
}

// WithGRPCAPIKey sets the API key.
func WithGRPCAPIKey(key string) GRPCOption {
	return func(c *GRPCConfig) {
		c.APIKey = key
	}
}

// WithGRPCAgentID sets the agent ID.
func WithGRPCAgentID(id string) GRPCOption {
	return func(c *GRPCConfig) {
		c.AgentID = id
	}
}

// WithGRPCTLS configures TLS.
func WithGRPCTLS(useTLS bool, insecureSkipVerify bool) GRPCOption {
	return func(c *GRPCConfig) {
		c.UseTLS = useTLS
		c.InsecureSkipVerify = insecureSkipVerify
	}
}

// WithGRPCCert sets the certificate file.
func WithGRPCCert(certFile string) GRPCOption {
	return func(c *GRPCConfig) {
		c.CertFile = certFile
	}
}

// WithGRPCTimeout sets the timeout.
func WithGRPCTimeout(d time.Duration) GRPCOption {
	return func(c *GRPCConfig) {
		c.Timeout = d
	}
}

// WithGRPCKeepalive sets keepalive parameters.
func WithGRPCKeepalive(time, timeout time.Duration) GRPCOption {
	return func(c *GRPCConfig) {
		c.KeepAliveTime = time
		c.KeepAliveTimeout = timeout
	}
}

// WithGRPCVerbose enables verbose logging.
func WithGRPCVerbose(v bool) GRPCOption {
	return func(c *GRPCConfig) {
		c.Verbose = v
	}
}

// =============================================================================
// Scan Options
// =============================================================================

// ScanConfig holds scan configuration.
type ScanConfig struct {
	Target      string
	Branches    []string
	Exclude     []string
	Include     []string
	MaxDepth    int
	Timeout     time.Duration
	Concurrency int
	Verbose     bool
}

// ScanOption is a function that configures a scan.
type ScanOption func(*ScanConfig)

// DefaultScanConfig returns default scan configuration.
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		MaxDepth:    -1,
		Concurrency: 4,
		Timeout:     30 * time.Minute,
	}
}

// ApplyScanOptions applies options to config.
func ApplyScanOptions(cfg *ScanConfig, opts ...ScanOption) {
	for _, opt := range opts {
		opt(cfg)
	}
}

// WithScanTarget sets the scan target.
func WithScanTarget(target string) ScanOption {
	return func(c *ScanConfig) {
		c.Target = target
	}
}

// WithScanBranches sets branches to scan.
func WithScanBranches(branches ...string) ScanOption {
	return func(c *ScanConfig) {
		c.Branches = branches
	}
}

// WithScanExclude sets paths to exclude.
func WithScanExclude(patterns ...string) ScanOption {
	return func(c *ScanConfig) {
		c.Exclude = patterns
	}
}

// WithScanInclude sets paths to include.
func WithScanInclude(patterns ...string) ScanOption {
	return func(c *ScanConfig) {
		c.Include = patterns
	}
}

// WithScanConcurrency sets concurrency level.
func WithScanConcurrency(n int) ScanOption {
	return func(c *ScanConfig) {
		c.Concurrency = n
	}
}

// WithScanTimeout sets the timeout.
func WithScanTimeout(d time.Duration) ScanOption {
	return func(c *ScanConfig) {
		c.Timeout = d
	}
}
