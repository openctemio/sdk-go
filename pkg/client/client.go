// Package client provides the OpenCTEM API client.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/chunk"
	"github.com/openctemio/sdk-go/pkg/compress"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/outbox"
	"github.com/openctemio/sdk-go/pkg/retry"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

// Client is the OpenCTEM API client.
// It implements the core.Pusher interface.
type Client struct {
	baseURL    string
	apiKey     string
	sensorID   string // Sensor ID for tracking which sensor is pushing
	httpClient *http.Client
	maxRetries int
	retryDelay time.Duration
	verbose    bool
	// userAgent is the product token (Config.UserAgent); empty: the
	// process-wide one (useragent.SetProduct).
	userAgent string

	// Compression configuration
	compressor       *compress.Compressor
	compressionLevel compress.Level
	analyzer         *compress.Analyzer

	// protocol is the results protocol setting (ProtocolAuto, V1, V2) and
	// v2 the decision auto mode took.
	protocol string
	v2       v2State

	// supp caches the v2 suppression list and its ETag.
	supp suppressionCache

	// Durable outbox (optional; EnableOutbox).
	obMu       sync.Mutex
	ob         *outbox.Outbox
	obCancel   context.CancelFunc
	obDone     chan struct{}
	obSyncWait time.Duration
	obLogf     func(format string, args ...any)

	// keyMu guards apiKey so it can be rotated at runtime (sensor key
	// auto-renewal) while push/heartbeat requests read it concurrently.
	keyMu sync.RWMutex

	// baseURLOnce/baseURLErr cache the one-time validation of baseURL
	// (see checkBaseURL). New/NewWithOptions cannot return an error without
	// breaking the public API, so the check runs on the first request.
	baseURLOnce sync.Once
	baseURLErr  error
}

// Response size limits. The API never legitimately returns more than a few
// MiB; an unbounded io.ReadAll lets a hostile or broken endpoint exhaust the
// sensor's memory. Error bodies are only used for diagnostics, so they are
// capped much lower and truncated before they reach an error string.
const (
	maxResponseBodyBytes = 10 << 20 // 10 MiB
	maxErrorBodyBytes    = 64 << 10 // 64 KiB
	// maxErrorMessageBytes bounds how much of an error body HTTPError.Error
	// prints, so a large HTML error page does not flood logs.
	maxErrorMessageBytes = 1 << 10 // 1 KiB
)

// Ensure Client implements core.Pusher
var _ core.Pusher = (*Client)(nil)

// Config holds client configuration.
type Config struct {
	BaseURL    string        `yaml:"base_url" json:"base_url"`
	APIKey     string        `yaml:"api_key" json:"api_key"`
	SensorID   string        `yaml:"sensor_id" json:"sensor_id"` // Registered sensor ID for audit trail; the pre-rename key agent_id is still read (config_compat.go)
	Timeout    time.Duration `yaml:"timeout" json:"timeout"`
	MaxRetries int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`
	Verbose    bool          `yaml:"verbose" json:"verbose"`

	// UserAgent is this client's product token, "name/version" (for example
	// "openctemio-sensor/0.3.1"), sent before the SDK's own token:
	// "openctemio-sensor/0.3.1 openctem-sdk-go/0.7.4". Empty: the process-wide
	// product set with useragent.SetProduct, if any.
	UserAgent string `yaml:"user_agent" json:"user_agent"`

	// Compression configuration
	EnableCompression bool   `yaml:"enable_compression" json:"enable_compression"` // Enable request compression (default: true)
	CompressionAlgo   string `yaml:"compression_algo" json:"compression_algo"`     // "zstd" or "gzip" (default: "zstd")
	CompressionLevel  int    `yaml:"compression_level" json:"compression_level"`   // 1-9 (default: 3)

	// Protocol selects the results protocol: "auto" (default: v2 when the
	// platform offers it, else v1), "v1" or "v2".
	Protocol string `yaml:"protocol" json:"protocol"`

	// OutboxDir enables the durable outbox (see EnableOutbox) in that
	// directory. New logs, and leaves the outbox off, when it cannot be
	// opened; call EnableOutbox yourself to handle the error.
	OutboxDir string `yaml:"outbox_dir" json:"outbox_dir"`
	// OutboxMaxBytes and OutboxMaxAge override the outbox caps.
	OutboxMaxBytes int64         `yaml:"outbox_max_bytes" json:"outbox_max_bytes"`
	OutboxMaxAge   time.Duration `yaml:"outbox_max_age" json:"outbox_max_age"`

	// Deprecated: the retry queue is replaced by the outbox. EnableRetryQueue
	// enables the outbox (in OutboxDir, else RetryQueueDir/outbox, else
	// ~/.openctem/outbox) and imports the reports an older SDK left in
	// RetryQueueDir. RetryInterval and RetryMaxAttempts are ignored: the
	// outbox retries with back-off until RetryTTL (OutboxMaxAge) evicts.
	EnableRetryQueue bool          `yaml:"enable_retry_queue" json:"enable_retry_queue"`
	RetryQueueDir    string        `yaml:"retry_queue_dir" json:"retry_queue_dir"`
	RetryInterval    time.Duration `yaml:"retry_interval" json:"retry_interval"`
	RetryMaxAttempts int           `yaml:"retry_max_attempts" json:"retry_max_attempts"`
	RetryTTL         time.Duration `yaml:"retry_ttl" json:"retry_ttl"`
}

// DefaultConfig returns default client config.
func DefaultConfig() *Config {
	return &Config{
		Timeout:           30 * time.Second,
		MaxRetries:        3,
		RetryDelay:        2 * time.Second,
		EnableCompression: true,
		CompressionAlgo:   "zstd",
		CompressionLevel:  3,
	}
}

// New creates a new OpenCTEM API client.
func New(cfg *Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 2 * time.Second
	}

	// Initialize compression if enabled
	var compressor *compress.Compressor
	var analyzer *compress.Analyzer
	compressionLevel := compress.Level(cfg.CompressionLevel)
	if compressionLevel == 0 {
		compressionLevel = compress.LevelDefault
	}

	if cfg.EnableCompression {
		algo := compress.AlgorithmZSTD
		if cfg.CompressionAlgo == "gzip" {
			algo = compress.AlgorithmGzip
		}
		compressor = compress.NewCompressor(algo, compressionLevel)
		analyzer = compress.NewAnalyzer(nil)
	}

	protocol, err := ParseProtocol(cfg.Protocol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[openctem] WARNING: %v; using auto\n", err)
		protocol = ProtocolAuto
	}
	c := &Client{
		baseURL:    cfg.BaseURL,
		apiKey:     cfg.APIKey,
		sensorID:   cfg.SensorID,
		maxRetries: cfg.MaxRetries,
		retryDelay: cfg.RetryDelay,
		// BaseURL is operator configuration, so the API client reaches a
		// platform on loopback or a private network; it still refuses
		// link-local (cloud metadata) destinations and every redirect, so
		// the bearer key never follows one. See httpsec.NewAPIClient.
		httpClient:       httpsec.NewAPIClient(cfg.Timeout),
		verbose:          cfg.Verbose,
		userAgent:        cfg.UserAgent,
		compressor:       compressor,
		compressionLevel: compressionLevel,
		analyzer:         analyzer,
		protocol:         protocol,
	}
	if cfg.OutboxDir != "" || cfg.EnableRetryQueue {
		ocfg := OutboxConfig{Dir: cfg.OutboxDir, MaxBytes: cfg.OutboxMaxBytes, MaxAge: cfg.OutboxMaxAge}
		if ocfg.MaxAge == 0 {
			ocfg.MaxAge = cfg.RetryTTL
		}
		if cfg.EnableRetryQueue {
			ocfg.LegacyRetryQueueDir = cfg.RetryQueueDir
			if ocfg.Dir == "" {
				ocfg.Dir = legacyOutboxDir(cfg.RetryQueueDir)
			}
		}
		if err := c.EnableOutbox(ocfg); err != nil {
			fmt.Fprintf(os.Stderr, "[openctem] WARNING: outbox not enabled: %v\n", err)
		}
	}
	return c
}

// legacyOutboxDir is where the deprecated EnableRetryQueue puts the outbox:
// inside the configured retry-queue directory, else ~/.openctem/outbox.
func legacyOutboxDir(retryDir string) string {
	if retryDir != "" {
		return filepath.Join(retryDir, "outbox")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "openctem-outbox")
	}
	return filepath.Join(home, ".openctem", "outbox")
}

// =============================================================================
// Functional Options Pattern (AWS SDK style)
// =============================================================================

// Option is a function that configures the client.
type Option func(*Client)

// NewWithOptions creates a new client using functional options.
// Example:
//
//	client := client.NewWithOptions(
//	    client.WithBaseURL("http://localhost:8080"),
//	    client.WithAPIKey("xxx"),
//	    client.WithSensorID("agent-1"),
//	    client.WithTimeout(30 * time.Second),
//	)
func NewWithOptions(opts ...Option) *Client {
	c := &Client{
		maxRetries: 3,
		retryDelay: 2 * time.Second,
		// SSRF: see the imperative constructor above for rationale.
		httpClient: httpsec.NewAPIClient(30 * time.Second),
		protocol:   ProtocolAuto,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithProtocol sets the results protocol: ProtocolAuto (default),
// ProtocolV1 or ProtocolV2. An unknown value keeps auto.
func WithProtocol(p string) Option {
	return func(c *Client) {
		if v, err := ParseProtocol(p); err == nil {
			c.protocol = v
		}
	}
}

// WithBaseURL sets the API base URL.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.apiKey = key
	}
}

// WithSensorID sets the sensor ID for tracking which sensor is pushing data.
func WithSensorID(id string) Option {
	return func(c *Client) {
		c.sensorID = id
	}
}

// WithTimeout sets the HTTP timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithRetry sets retry configuration.
func WithRetry(maxRetries int, retryDelay time.Duration) Option {
	return func(c *Client) {
		c.maxRetries = maxRetries
		c.retryDelay = retryDelay
	}
}

// WithUserAgent sets this client's product token, "name/version", sent
// before the SDK's own token in the User-Agent (see Config.UserAgent).
func WithUserAgent(product string) Option {
	return func(c *Client) {
		c.userAgent = product
	}
}

// userAgentHeader returns the User-Agent this client sends.
func (c *Client) userAgentHeader() string {
	if c.userAgent != "" {
		return useragent.WithProduct(c.userAgent)
	}
	return useragent.String()
}

// WithVerbose enables verbose logging.
func WithVerbose(v bool) Option {
	return func(c *Client) {
		c.verbose = v
	}
}

// WithCompression enables request compression with the specified algorithm.
// Supported algorithms: "zstd" (recommended), "gzip"
func WithCompression(algorithm string, level int) Option {
	return func(c *Client) {
		algo := compress.AlgorithmZSTD
		if algorithm == "gzip" {
			algo = compress.AlgorithmGzip
		}
		compressionLevel := compress.Level(level)
		if compressionLevel == 0 {
			compressionLevel = compress.LevelDefault
		}
		c.compressor = compress.NewCompressor(algo, compressionLevel)
		c.compressionLevel = compressionLevel
		c.analyzer = compress.NewAnalyzer(nil)
	}
}

// WithoutCompression disables request compression.
func WithoutCompression() Option {
	return func(c *Client) {
		c.compressor = nil
		c.analyzer = nil
	}
}

// IngestResponse is the response from ingest endpoints.
type IngestResponse struct {
	ScanID          string   `json:"scan_id"`
	AssetsCreated   int      `json:"assets_created"`
	AssetsUpdated   int      `json:"assets_updated"`
	FindingsCreated int      `json:"findings_created"`
	FindingsUpdated int      `json:"findings_updated"`
	FindingsSkipped int      `json:"findings_skipped"`
	Errors          []string `json:"errors,omitempty"`
}

// HeartbeatRequest is the heartbeat payload.
type HeartbeatRequest struct {
	Name       string           `json:"name,omitempty"`
	Status     core.SensorState `json:"status"`
	Version    string           `json:"version,omitempty"`
	Hostname   string           `json:"hostname,omitempty"`
	Message    string           `json:"message,omitempty"`
	Scanners   []string         `json:"scanners,omitempty"`
	Collectors []string         `json:"collectors,omitempty"`
	Uptime     int64            `json:"uptime_seconds,omitempty"`
	TotalScans int64            `json:"total_scans,omitempty"`
	Errors     int64            `json:"errors,omitempty"`

	// System Metrics
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryPercent float64 `json:"memory_percent,omitempty"`
	ActiveJobs    int     `json:"active_jobs,omitempty"`
	Region        string  `json:"region,omitempty"`
	// ActiveJobsReported sends active_jobs even when it is 0 (the sensor
	// measured it). Without it a 0 is left out, as before.
	ActiveJobsReported bool `json:"-"`

	// Outbox is the durable outbox's state (absent without an outbox).
	Outbox *HeartbeatOutbox `json:"outbox,omitempty"`

	// The sensor-reported capabilities (core.CapabilityReport): absent when
	// the sensor reports nothing, and an empty list when it reports none.
	Tools             []core.ToolInfo `json:"tools,omitzero"`
	Capabilities      []string        `json:"capabilities,omitzero"`
	MaxConcurrentJobs int             `json:"max_concurrent_jobs,omitempty"`
	OS                string          `json:"os,omitempty"`
	Arch              string          `json:"arch,omitempty"`
}

// MarshalJSON encodes the heartbeat. active_jobs is sent even when it is 0
// if ActiveJobsReported is set: an idle sensor then reports "0 running",
// which the platform's dispatch can trust, instead of leaving the field out.
func (r HeartbeatRequest) MarshalJSON() ([]byte, error) {
	type plain HeartbeatRequest // no MarshalJSON: no recursion
	if !r.ActiveJobsReported {
		return json.Marshal(plain(r))
	}
	// The outer field shadows the embedded one (shallower depth wins).
	return json.Marshal(struct {
		plain
		ActiveJobs int `json:"active_jobs"`
	}{plain(r), r.ActiveJobs})
}

// HeartbeatOutbox is the outbox state a heartbeat reports (additive to the
// v1 heartbeat; servers that do not know it ignore it).
type HeartbeatOutbox struct {
	PendingCount     int   `json:"pending_count"`
	PendingBytes     int64 `json:"pending_bytes"`
	OldestAgeSeconds int64 `json:"oldest_age_seconds"`
	DeadLetterCount  int   `json:"dead_letter_count"`
	EvictedCount     int64 `json:"evicted_count"`
}

// PushFindings sends a report's findings (and assets) to OpenCTEM, over
// protocol v2 when the platform offers it (Config.Protocol) and v1
// otherwise.
//
// With the outbox enabled (EnableOutbox) the report is first written to disk
// and this call waits up to OutboxConfig.SyncWait for its delivery: it
// returns the result when the platform accepted it, a *RefusedError when the
// platform refused it for good (dead letter), and Queued=true when the
// platform could not be reached yet; the outbox delivers it later, across
// restarts. Without the outbox the report is sent once (with the client's
// own retries) and an error means it was not delivered.
//
// A context from core.WithCommandID binds the results to that command.
func (c *Client) PushFindings(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	if ob := c.Outbox(); ob != nil {
		return c.enqueueReport(ctx, ob, report, false)
	}
	return c.pushReportDirect(ctx, report, false)
}

// PushAssets sends a report's assets (its findings are dropped). See
// PushFindings for the outbox behavior.
func (c *Client) PushAssets(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	if ob := c.Outbox(); ob != nil {
		return c.enqueueReport(ctx, ob, report, true)
	}
	return c.pushReportDirect(ctx, report, true)
}

// pushReportDirect sends a report without the outbox: v2 or v1 by protocol,
// with the client's retries (MaxRetries) on transient failures. v2 retries
// reuse the report id, so they never duplicate.
func (c *Client) pushReportDirect(ctx context.Context, report *ctis.Report, assetsOnly bool) (*core.PushResult, error) {
	r := report
	if assetsOnly {
		cp := *report
		cp.Findings = nil
		r = &cp
	}
	useV2, _, err := c.resultsProtocol(ctx)
	if err != nil && !errors.Is(err, ErrV2Unsupported) && c.protocol == ProtocolAuto {
		// Discovery failed (network): v1 is what an unknown platform speaks.
		useV2, err = false, nil
	}
	if err != nil {
		return nil, err
	}
	if !useV2 {
		return c.pushReportV1(ctx, r, assetsOnly, c.maxRetries)
	}
	opts := &V2PushOptions{CommandID: core.CommandIDFromContext(ctx)}
	var prog V2Progress
	opts.OnProgress = func(p V2Progress) error { prog = p; return nil }
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			wait := c.backoffFor(attempt)
			var ve *V2Error
			if errors.As(lastErr, &ve) && ve.RetryAfter > wait {
				wait = min(ve.RetryAfter, 5*time.Minute)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			p := prog
			opts.Progress = &p
		}
		st, err := c.PushResultsV2(ctx, r, opts)
		if err == nil {
			return v2PushResult(st), nil
		}
		lastErr = err
		if opts.ReportID == "" {
			opts.ReportID = prog.ReportID
		}
		var ve *V2Error
		switch {
		case errors.As(err, &ve) && c.protocol == ProtocolAuto && (ve.routeMissing() || ve.ProblemName() == protov2.ProblemScopeDenied):
			c.forceV1(!ve.routeMissing())
			return c.pushReportV1(ctx, r, assetsOnly, c.maxRetries)
		case errors.As(err, &ve) && ve.Transient():
		case errors.As(err, &ve), errors.Is(err, ErrV2NoTool), ctx.Err() != nil:
			return nil, err
		}
	}
	return nil, fmt.Errorf("request failed after %d retries: %w", c.maxRetries, lastErr)
}

// pushReportV1 posts a report to the v1 ingest route with up to retries
// retries.
func (c *Client) pushReportV1(ctx context.Context, report *ctis.Report, assetsOnly bool, retries int) (*core.PushResult, error) {
	url := c.baseURL + legacyv1.PathIngest
	if assetsOnly && len(report.Findings) > 0 {
		cp := *report
		cp.Findings = nil
		report = &cp
	}
	if c.verbose {
		fmt.Printf("[openctem] Pushing %d findings, %d assets to %s\n", len(report.Findings), len(report.Assets), url)
	}
	body, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	data, _, err := c.doRequestFull(ctx, "POST", url, body, nil, retries)
	if err != nil {
		return nil, err
	}
	var resp IngestResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	if c.verbose {
		fmt.Printf("[openctem] Push completed: %d findings created, %d updated\n",
			resp.FindingsCreated, resp.FindingsUpdated)
	}
	success := len(resp.Errors) == 0
	message := ""
	if !success {
		message = fmt.Sprintf("%d errors occurred", len(resp.Errors))
	}
	return &core.PushResult{
		Success:         success,
		Message:         message,
		FindingsCreated: resp.FindingsCreated,
		FindingsUpdated: resp.FindingsUpdated,
		AssetsCreated:   resp.AssetsCreated,
		AssetsUpdated:   resp.AssetsUpdated,
	}, nil
}

// SendHeartbeat sends a heartbeat to OpenCTEM. It does not announce the
// heartbeat doorbell and ignores the response body: a caller that acts on the
// platform's hints uses SendHeartbeatWithHints instead.
func (c *Client) SendHeartbeat(ctx context.Context, status *core.SensorStatus) error {
	_, paused, err := c.sendHeartbeat(ctx, status, nil)
	if err == nil && paused {
		// Protocol v2 tells a disabled sensor to pause with a 200; a caller
		// that does not act on hints must still see a refused key, as v1's
		// 401 told it.
		return errPausedHeartbeat()
	}
	return err
}

// SendHeartbeatWithHints sends a heartbeat that announces the doorbell
// (X-OpenCTEM-Sensor-Features: doorbell) and returns the hints the platform
// answered with. Against a server without the doorbell the hints have
// Present=false. Announcing the feature is a promise to act on it: a disabled
// sensor is then answered 200 with the pause action instead of 401. On
// protocol v2 the doorbell is always on.
func (c *Client) SendHeartbeatWithHints(ctx context.Context, status *core.SensorStatus) (*core.HeartbeatHints, error) {
	data, _, err := c.sendHeartbeat(ctx, status, http.Header{
		legacyv1.HeaderSensorFeatures: []string{legacyv1.FeatureDoorbell},
	})
	if err != nil {
		return nil, err
	}
	return core.ParseHeartbeatHints(data), nil
}

var _ core.DoorbellPusher = (*Client)(nil)

// sendHeartbeat sends one heartbeat on protocol v2 when the platform offers
// it (api RFC-029 §4.3) and on v1 otherwise. extra is v1-only (the doorbell
// feature header; v2 always has the doorbell). paused is true when v2 told a
// disabled sensor to pause.
func (c *Client) sendHeartbeat(ctx context.Context, status *core.SensorStatus, extra http.Header) ([]byte, bool, error) {
	url := c.baseURL + legacyv1.PathHeartbeat

	req := HeartbeatRequest{
		Name:       status.Name,
		Status:     status.Status,
		Scanners:   status.Scanners,
		Collectors: status.Collectors,
		Uptime:     status.Uptime,
		TotalScans: status.TotalScans,
		Errors:     status.Errors,
		Message:    status.Message,
		// System metrics
		CPUPercent:    status.CPUPercent,
		MemoryPercent: status.MemoryPercent,
		ActiveJobs:    status.ActiveJobs,
		Region:        status.Region,

		ActiveJobsReported: status.ActiveJobsReported,
		// Version and Hostname were declared on the request but never set, so
		// every sensor showed "No host info" on the platform.
		Version:  status.Version,
		Hostname: status.Hostname,
		// What the sensor reports it can do (nil: nothing reported).
		Tools:             status.Tools,
		Capabilities:      status.Capabilities,
		MaxConcurrentJobs: status.MaxConcurrentJobs,
		OS:                status.OS,
		Arch:              status.Arch,
	}
	ob := c.Outbox()
	if ob != nil {
		st := ob.Stats()
		req.Outbox = &HeartbeatOutbox{
			PendingCount:     st.PendingCount,
			PendingBytes:     st.PendingBytes,
			OldestAgeSeconds: int64(st.OldestAge(time.Now()) / time.Second),
			DeadLetterCount:  st.DeadLetterCount,
			EvictedCount:     st.Evicted,
		}
	}

	if useV2, _ := c.controlV2(ctx, protov2.FeatureHeartbeat); useV2 {
		raw, resp, err := c.heartbeatV2(ctx, &req)
		if err == nil {
			if ob != nil {
				ob.Wake()
			}
			if c.verbose {
				fmt.Printf("[openctem] Heartbeat sent (v2): %s\n", status.Status)
			}
			return raw, resp.Status == protov2.HeartbeatStatusPaused, nil
		}
		if !isRouteMissing(err) {
			return nil, false, err
		}
		c.renegotiate() // the platform listed v2 heartbeat but does not serve it
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, false, fmt.Errorf("marshal heartbeat: %w", err)
	}

	// Discovery of protocol v2 results (RFC-026, RFC-023 C3): the answer
	// carries X-OpenCTEM-Protocol: 2 when the platform offers it.
	announceV2 := c.protocol != ProtocolV1
	if announceV2 {
		h := http.Header{}
		for k, vs := range extra {
			for _, v := range vs {
				h.Add(k, v)
			}
		}
		h.Add(legacyv1.HeaderSensorFeatures, protov2.FeatureResultsV2)
		extra = h
	}

	data, hdr, err := c.doRequestFull(ctx, "POST", url, body, extra, c.maxRetries)
	if err != nil {
		return nil, false, err
	}
	if announceV2 {
		c.noteProtocolAdvert(hdr.Get(protov2.HeaderProtocolAdvert) == strconv.Itoa(protov2.ProtocolVersion))
	}
	// The platform answered: deliver what waits now (doorbell).
	if ob != nil {
		ob.Wake()
	}

	if c.verbose {
		fmt.Printf("[openctem] Heartbeat sent: %s\n", status.Status)
	}

	return data, false, nil
}

// TestConnection tests the API connection.
func (c *Client) TestConnection(ctx context.Context) error {
	status := &core.SensorStatus{
		Name:    "connection-test",
		Status:  core.SensorStateRunning,
		Message: "connection test",
	}
	return c.SendHeartbeat(ctx, status)
}

// checkFingerprintsRequest is the internal request for checking fingerprint existence.
type checkFingerprintsRequest struct {
	Fingerprints []string `json:"fingerprints"`
}

// checkFingerprintsResponse is the internal response for fingerprint check.
type checkFingerprintsResponse struct {
	Existing []string `json:"existing"` // Fingerprints that already exist
	Missing  []string `json:"missing"`  // Fingerprints that don't exist
}

// CheckFingerprints checks which fingerprints already exist on the server.
// This is used by the retry mechanism to avoid re-uploading data that already exists.
// It also serves as a connectivity check before processing the retry queue.
// This method implements retry.FingerprintChecker interface.
func (c *Client) CheckFingerprints(ctx context.Context, fingerprints []string) (*retry.FingerprintCheckResult, error) {
	if len(fingerprints) == 0 {
		return &retry.FingerprintCheckResult{
			Existing: []string{},
			Missing:  []string{},
		}, nil
	}

	if useV2, h := c.controlV2(ctx, protov2.FeatureFingerprints); useV2 {
		existing, missing, err := c.checkFingerprintsV2(ctx, fingerprints, h)
		if err == nil {
			return &retry.FingerprintCheckResult{Existing: existing, Missing: missing}, nil
		}
		if !isRouteMissing(err) {
			return nil, fmt.Errorf("check fingerprints: %w", err)
		}
		c.renegotiate()
	}

	req := checkFingerprintsRequest{
		Fingerprints: fingerprints,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + legacyv1.PathIngestCheck
	respBody, err := c.doRequest(ctx, "POST", url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("check fingerprints: %w", err)
	}

	var resp checkFingerprintsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Fingerprint check: %d existing, %d missing\n",
			len(resp.Existing), len(resp.Missing))
	}

	return &retry.FingerprintCheckResult{
		Existing: resp.Existing,
		Missing:  resp.Missing,
	}, nil
}

const (
	// maxRetryBackoff caps the per-attempt retry wait.
	maxRetryBackoff = 30 * time.Second
	// maxBackoffShift caps the exponent so 1<<shift can't overflow / explode.
	maxBackoffShift = 16
)

type baselineDiffRequest struct {
	Repository   string   `json:"repository"`
	BaseBranch   string   `json:"base_branch"`
	Fingerprints []string `json:"fingerprints"`
}

type baselineDiffResponse struct {
	New               []string `json:"new_fingerprints"`
	PreExisting       []string `json:"pre_existing_fingerprints"`
	BaseBranchScanned bool     `json:"base_branch_scanned"`
}

// BaselineDiff returns the subset of fingerprints that are NEW relative to a PR's
// base/target branch (not already open there). Used to focus a PR gate / inline
// comments on findings the PR introduces, not pre-existing tech debt. On error
// or no PR context the caller should treat all findings as new (fail-open for
// visibility). Returns the new fingerprints.
func (c *Client) BaselineDiff(ctx context.Context, repository, baseBranch string, fingerprints []string) ([]string, error) {
	if len(fingerprints) == 0 {
		return []string{}, nil
	}
	if useV2, h := c.controlV2(ctx, protov2.FeatureFingerprints); useV2 {
		out, err := c.baselineDiffV2(ctx, repository, baseBranch, fingerprints, h)
		if err == nil {
			return out, nil
		}
		if !isRouteMissing(err) {
			return nil, fmt.Errorf("baseline diff: %w", err)
		}
		c.renegotiate()
	}

	reqBody, err := json.Marshal(baselineDiffRequest{
		Repository:   repository,
		BaseBranch:   baseBranch,
		Fingerprints: fingerprints,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + legacyv1.PathIngestBaselineDiff
	respBody, err := c.doRequest(ctx, "POST", url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("baseline diff: %w", err)
	}

	var resp baselineDiffResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	if c.verbose {
		fmt.Printf("[openctem] Baseline diff: %d new, %d pre-existing (base scanned=%v)\n",
			len(resp.New), len(resp.PreExisting), resp.BaseBranchScanned)
	}
	return resp.New, nil
}

// doRequest performs an HTTP request with retry logic.
func (c *Client) doRequest(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	data, _, err := c.doRequestFull(ctx, method, url, body, nil, c.maxRetries)
	return data, err
}

// doRequestWithHeaders is doRequest with extra request headers.
func (c *Client) doRequestWithHeaders(ctx context.Context, method, url string, body []byte, extra http.Header) ([]byte, error) {
	data, _, err := c.doRequestFull(ctx, method, url, body, extra, c.maxRetries)
	return data, err
}

// backoffFor is the jittered exponential delay before retry attempt n (>=1).
func (c *Client) backoffFor(attempt int) time.Duration {
	// Exponential backoff with a cap + jitter. Uncapped `1<<(attempt-1)`
	// grows unbounded (and can overflow), and identical delays across many
	// sensors cause synchronized retry storms. Cap the shift, cap the
	// ceiling, then apply full jitter in [backoff/2, backoff].
	shift := max(attempt-1, 0)
	if shift > maxBackoffShift {
		shift = maxBackoffShift
	}
	backoff := c.retryDelay * time.Duration(1<<uint(shift))
	if backoff <= 0 || backoff > maxRetryBackoff {
		backoff = maxRetryBackoff
	}
	half := backoff / 2
	// G404: retry jitter only needs to de-correlate concurrent clients, not
	// resist prediction. crypto/rand would add a syscall per retry for no
	// security benefit.
	return half + time.Duration(rand.Int64N(int64(half)+1)) //nolint:gosec // jitter, not a secret
}

// doRequestFull performs an HTTP request with up to retries retries and
// returns the body and the response headers.
func (c *Client) doRequestFull(ctx context.Context, method, url string, body []byte, extra http.Header, retries int) ([]byte, http.Header, error) {
	if err := c.checkBaseURL(); err != nil {
		return nil, nil, err
	}

	var lastErr error

	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := c.backoffFor(attempt)
			if he, ok := IsHTTPError(lastErr); ok && he.RetryAfter > backoff {
				backoff = min(he.RetryAfter, 5*time.Minute)
			}
			if c.verbose {
				fmt.Printf("[openctem] Retrying request (attempt %d/%d) after %v\n", attempt, retries, backoff)
			}

			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		data, hdr, err := c.doRequestOnce(ctx, method, url, body, extra)
		if err == nil {
			return data, hdr, nil
		}

		lastErr = err

		// Don't retry on client errors (4xx) except 429 (rate limit)
		if isClientError(err) && !isRateLimitError(err) {
			return nil, nil, err
		}

		// Don't retry on context errors
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
	}

	if retries == 0 {
		return nil, nil, lastErr
	}
	return nil, nil, fmt.Errorf("request failed after %d retries: %w", retries, lastErr)
}

// doRequestOnce performs a single HTTP request.
func (c *Client) doRequestOnce(ctx context.Context, method, url string, body []byte, extra http.Header) ([]byte, http.Header, error) {
	// Compress body if compression is enabled and body is large enough
	requestBody := body
	var contentEncoding string

	if c.compressor != nil && len(body) > 1024 { // Only compress if > 1KB
		compressed, stats, err := c.compressor.CompressWithStats(body)
		if err == nil && len(compressed) < len(body) {
			// Only use compressed if it's actually smaller
			requestBody = compressed
			contentEncoding = c.compressor.ContentEncoding()
			if c.verbose {
				fmt.Printf("[openctem] Compressed request: %d -> %d bytes (%.1f%% savings)\n",
					stats.OriginalSize, stats.CompressedSize, stats.Savings)
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(requestBody))
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.getAPIKey())
	req.Header.Set("User-Agent", c.userAgentHeader())

	// Add Content-Encoding header if compressed
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}

	// Add sensor ID header for audit trail
	if c.sensorID != "" {
		req.Header.Set(legacyv1.HeaderSensorID, c.sensorID)
	}
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	c.noteV1Deprecation(resp.Header)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Best effort: a truncated or failed read still yields a useful error.
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, resp.Header, &HTTPError{
			StatusCode: resp.StatusCode,
			Body:       string(errBody),
			RequestID:  resp.Header.Get("X-Request-ID"),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	}

	// Read one byte past the cap so an oversized body is detected rather than
	// silently truncated into invalid JSON.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	if len(data) > maxResponseBodyBytes {
		return nil, nil, fmt.Errorf("response body exceeds %d bytes", maxResponseBodyBytes)
	}

	return data, resp.Header, nil
}

// checkBaseURL validates the configured base URL once per client. A
// non-http(s) scheme, missing host or embedded credentials is an error; a
// plain-http URL to a non-loopback host only prints a warning so existing
// in-cluster deployments keep working.
func (c *Client) checkBaseURL() error {
	c.baseURLOnce.Do(func() {
		warning, err := httpsec.CheckAPIBaseURL(c.baseURL)
		if err != nil {
			c.baseURLErr = err
			return
		}
		if warning != "" && httpsec.FirstWarning(c.baseURL) {
			fmt.Fprintf(os.Stderr, "[openctem] WARNING: %s\n", warning)
		}
	})
	return c.baseURLErr
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
	RequestID  string `json:"request_id,omitempty"`
	// RetryAfter is the server's Retry-After (429/503), 0 when absent.
	RetryAfter time.Duration `json:"retry_after,omitempty"`
}

func (e *HTTPError) Error() string {
	body := truncateForError(e.Body, maxErrorMessageBytes)
	if e.RequestID != "" {
		return fmt.Sprintf("http %d: %s (request_id: %s)", e.StatusCode, body, e.RequestID)
	}
	return fmt.Sprintf("http %d: %s", e.StatusCode, body)
}

// HTTPStatusCode returns the response status. pkg/core uses it to tell a
// rejected API key (401/403) from other failures without importing this
// package.
func (e *HTTPError) HTTPStatusCode() int { return e.StatusCode }

// truncateForError shortens s to at most limit bytes (on a UTF-8 boundary)
// and marks the cut.
func truncateForError(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("... (truncated, %d bytes total)", len(s))
}

// =============================================================================
// Error Checking Helpers (Public API)
// =============================================================================

// IsHTTPError checks if err is an HTTPError and returns it.
func IsHTTPError(err error) (*HTTPError, bool) {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr, true
	}
	return nil, false
}

// IsClientError checks if the error is a 4xx client error.
func IsClientError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode >= 400 && httpErr.StatusCode < 500
	}
	return false
}

// IsServerError checks if the error is a 5xx server error.
func IsServerError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode >= 500
	}
	return false
}

// IsRateLimitError checks if the error is a 429 rate limit error.
func IsRateLimitError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == 429
	}
	return false
}

// IsAuthenticationError checks if the error is a 401 authentication error.
func IsAuthenticationError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == 401
	}
	return false
}

// IsAuthorizationError checks if the error is a 403 authorization error.
func IsAuthorizationError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == 403
	}
	return false
}

// IsNotFoundError checks if the error is a 404 not found error.
func IsNotFoundError(err error) bool {
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode == 404
	}
	return false
}

// IsRetryable checks if the error should be retried.
func IsRetryable(err error) bool {
	// Rate limit errors are retryable
	if IsRateLimitError(err) {
		return true
	}
	// Server errors (except 501) are retryable
	if httpErr, ok := IsHTTPError(err); ok {
		return httpErr.StatusCode >= 500 && httpErr.StatusCode != 501
	}
	return false
}

// Private helpers (keep backward compatibility)
func isClientError(err error) bool    { return IsClientError(err) }
func isRateLimitError(err error) bool { return IsRateLimitError(err) }

// SetVerbose sets verbose mode.
func (c *Client) SetVerbose(v bool) {
	c.verbose = v
}

// SetAPIKey atomically replaces the API key used by subsequent requests.
// Safe to call concurrently with in-flight pushes (sensor key auto-renewal).
func (c *Client) SetAPIKey(key string) {
	c.keyMu.Lock()
	c.apiKey = key
	c.keyMu.Unlock()
	// Delivery paused on a rejected key tries again with the new one.
	if ob := c.Outbox(); ob != nil {
		ob.Resume()
	}
}

// APIKeyHint names the client's API key in log lines without revealing it
// (core.APIKeyHint: at most its first 8 characters).
func (c *Client) APIKeyHint() string {
	return core.APIKeyHint(c.getAPIKey())
}

// getAPIKey returns the current API key under a read lock.
func (c *Client) getAPIKey() string {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	return c.apiKey
}

// ============================================================================
// Retry queue (deprecated: wrappers around the outbox)
// ============================================================================

// RetryQueueConfig configures the retry queue.
//
// Deprecated: use EnableOutbox with an OutboxConfig. Dir is where the old
// queue's files are imported from (the outbox lives in Dir/outbox); TTL
// becomes the outbox's MaxAge; the other fields are ignored.
type RetryQueueConfig struct {
	Dir         string
	MaxSize     int
	Interval    time.Duration
	BatchSize   int
	MaxAttempts int
	TTL         time.Duration
	Backoff     *retry.BackoffConfig
	AutoStart   bool
}

// DefaultRetryQueueConfig returns a configuration with default values.
//
// Deprecated: use EnableOutbox.
func DefaultRetryQueueConfig() *RetryQueueConfig {
	return &RetryQueueConfig{
		MaxSize:     retry.DefaultMaxQueueSize,
		Interval:    retry.DefaultRetryInterval,
		BatchSize:   retry.DefaultBatchSize,
		MaxAttempts: retry.DefaultMaxAttempts,
		TTL:         retry.DefaultTTL,
		Backoff:     retry.DefaultBackoffConfig(),
		AutoStart:   true,
	}
}

// EnableRetryQueue enables the durable outbox in cfg.Dir/outbox (default
// ~/.openctem/outbox) and imports the reports an older SDK queued in
// cfg.Dir.
//
// Deprecated: use EnableOutbox.
func (c *Client) EnableRetryQueue(_ context.Context, cfg *RetryQueueConfig) error {
	if cfg == nil {
		cfg = DefaultRetryQueueConfig()
	}
	if c.Outbox() != nil {
		return nil
	}
	return c.EnableOutbox(OutboxConfig{
		Dir:                 legacyOutboxDir(cfg.Dir),
		MaxAge:              cfg.TTL,
		LegacyRetryQueueDir: cfg.Dir,
	})
}

// StartRetryWorker is a no-op: the outbox delivers in the background from
// EnableOutbox on. It fails when no outbox is enabled.
//
// Deprecated: use EnableOutbox.
func (c *Client) StartRetryWorker(_ context.Context) error {
	if c.Outbox() == nil {
		return errors.New("outbox not enabled")
	}
	return nil
}

// StopRetryWorker is a no-op; Close stops the outbox.
//
// Deprecated: use Close.
func (c *Client) StopRetryWorker(_ context.Context) error { return nil }

// DisableRetryQueue stops and closes the outbox.
//
// Deprecated: use Close.
func (c *Client) DisableRetryQueue(_ context.Context) error { return c.closeOutbox() }

// GetRetryQueueStats returns the outbox's state in the old shape.
//
// Deprecated: use OutboxStats.
func (c *Client) GetRetryQueueStats(_ context.Context) (*retry.QueueStats, error) {
	st, ok := c.OutboxStats()
	if !ok {
		return nil, errors.New("outbox not enabled")
	}
	return &retry.QueueStats{
		TotalItems:     st.PendingCount + st.DeadLetterCount,
		PendingItems:   st.PendingCount,
		FailedItems:    st.DeadLetterCount,
		OldestItem:     st.OldestPending,
		TotalRetries:   st.Attempts,
		SuccessfulPush: st.Delivered,
	}, nil
}

// GetRetryWorkerStats returns the outbox's delivery counters in the old
// shape.
//
// Deprecated: use OutboxStats.
func (c *Client) GetRetryWorkerStats() (*retry.WorkerStats, error) {
	st, ok := c.OutboxStats()
	if !ok {
		return nil, errors.New("outbox not enabled")
	}
	return &retry.WorkerStats{
		TotalAttempts:  st.Attempts,
		SuccessfulPush: st.Delivered,
		FailedAttempts: st.Attempts - st.Delivered,
		ExhaustedItems: st.DeadLetters,
		IsRunning:      true,
	}, nil
}

// ProcessRetryQueueNow delivers what the outbox can deliver now.
//
// Deprecated: use FlushOutbox.
func (c *Client) ProcessRetryQueueNow(ctx context.Context) error {
	if c.Outbox() == nil {
		return errors.New("outbox not enabled")
	}
	return c.FlushOutbox(ctx)
}

// PushReport pushes a report directly (no outbox), findings and assets
// alike. It implemented the old retry worker's interface.
//
// Deprecated: use PushFindings.
func (c *Client) PushReport(ctx context.Context, report *ctis.Report) error {
	_, err := c.pushReportDirect(ctx, report, len(report.Findings) == 0)
	return err
}

// Close stops the outbox's delivery and releases its directory. Items not
// delivered yet stay on disk for the next process.
func (c *Client) Close() error {
	return c.closeOutbox()
}

// =============================================================================
// Exposure Events API
// =============================================================================

// ExposureEvent represents an attack surface change event.
type ExposureEvent struct {
	// Event type: new_asset, asset_removed, exposure_detected, exposure_resolved
	Type string `json:"type"`

	// Asset identifier
	AssetID   string `json:"asset_id,omitempty"`
	AssetType string `json:"asset_type,omitempty"`
	AssetName string `json:"asset_name,omitempty"`

	// Exposure details
	ExposureType string `json:"exposure_type,omitempty"` // port_open, service_exposed, etc.
	Protocol     string `json:"protocol,omitempty"`
	Port         int    `json:"port,omitempty"`
	Service      string `json:"service,omitempty"`

	// Detection info
	DetectedAt  time.Time `json:"detected_at"`
	DetectedBy  string    `json:"detected_by,omitempty"` // scan source
	Severity    string    `json:"severity,omitempty"`
	Description string    `json:"description,omitempty"`

	// Resolution
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`

	// Metadata
	Tags       []string       `json:"tags,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// PushExposuresResult is the result of pushing exposure events.
type PushExposuresResult struct {
	EventsCreated int `json:"events_created"`
	EventsUpdated int `json:"events_updated"`
	EventsSkipped int `json:"events_skipped"`
}

// PushExposures sends exposure events to OpenCTEM.
func (c *Client) PushExposures(ctx context.Context, events []ExposureEvent) (*PushExposuresResult, error) {
	url := fmt.Sprintf("%s/api/v1/exposures/ingest", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Pushing %d exposure events to %s\n", len(events), url)
	}

	input := struct {
		SensorID string          `json:"agent_id,omitempty"`
		Events   []ExposureEvent `json:"events"`
	}{
		SensorID: c.sensorID,
		Events:   events,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal events: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp PushExposuresResult
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Exposure push completed: %d created, %d updated\n",
			resp.EventsCreated, resp.EventsUpdated)
	}

	return &resp, nil
}

// =============================================================================
// Threat Intelligence API
// =============================================================================

// EPSSScore represents an EPSS score for a CVE.
type EPSSScore struct {
	CVEID      string    `json:"cve_id"`
	Score      float64   `json:"score"`      // 0.0 to 1.0
	Percentile float64   `json:"percentile"` // 0.0 to 100.0
	Date       time.Time `json:"date"`
}

// GetEPSSScores fetches EPSS scores for the given CVE IDs.
func (c *Client) GetEPSSScores(ctx context.Context, cveIDs []string) ([]EPSSScore, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	url := fmt.Sprintf("%s/api/v1/threatintel/epss", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Fetching EPSS scores for %d CVEs\n", len(cveIDs))
	}

	input := struct {
		CVEIDs []string `json:"cve_ids"`
	}{
		CVEIDs: cveIDs,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Scores []EPSSScore `json:"scores"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return resp.Scores, nil
}

// KEVEntry represents a CISA Known Exploited Vulnerabilities entry.
type KEVEntry struct {
	CVEID                      string    `json:"cve_id"`
	VendorProject              string    `json:"vendor_project"`
	Product                    string    `json:"product"`
	VulnerabilityName          string    `json:"vulnerability_name"`
	DateAdded                  time.Time `json:"date_added"`
	ShortDescription           string    `json:"short_description"`
	RequiredAction             string    `json:"required_action"`
	DueDate                    time.Time `json:"due_date"`
	KnownRansomwareCampaignUse string    `json:"known_ransomware_campaign_use"`
}

// GetKEVEntries fetches CISA KEV entries for the given CVE IDs.
func (c *Client) GetKEVEntries(ctx context.Context, cveIDs []string) ([]KEVEntry, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	url := fmt.Sprintf("%s/api/v1/threatintel/kev", c.baseURL)

	if c.verbose {
		fmt.Printf("[openctem] Fetching KEV entries for %d CVEs\n", len(cveIDs))
	}

	input := struct {
		CVEIDs []string `json:"cve_ids"`
	}{
		CVEIDs: cveIDs,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	data, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Entries []KEVEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return resp.Entries, nil
}

// =============================================================================
// Chunked Upload API
// =============================================================================

// ChunkUploadResponse is the response from chunk upload endpoint.
type ChunkUploadResponse struct {
	ChunkID         string `json:"chunk_id"`
	ReportID        string `json:"report_id"`
	ChunkIndex      int    `json:"chunk_index"`
	Status          string `json:"status"`
	AssetsCreated   int    `json:"assets_created"`
	AssetsUpdated   int    `json:"assets_updated"`
	FindingsCreated int    `json:"findings_created"`
	FindingsUpdated int    `json:"findings_updated"`
	FindingsSkipped int    `json:"findings_skipped"`
}

// UploadChunk uploads a single chunk of a large report.
// This implements the chunk.Uploader interface.
func (c *Client) UploadChunk(ctx context.Context, data *chunk.ChunkData) error {
	url := c.baseURL + legacyv1.PathIngestChunk

	if c.verbose {
		fmt.Printf("[openctem] Uploading chunk %d/%d for report %s\n",
			data.ChunkIndex+1, data.TotalChunks, data.ReportID)
	}

	// Serialize chunk data
	chunkJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal chunk data: %w", err)
	}

	// Compress chunk data using ZSTD (default)
	var compressedData []byte
	compressionAlgo := "zstd"

	if c.compressor != nil {
		compressedData, err = c.compressor.Compress(chunkJSON)
		if err != nil {
			return fmt.Errorf("compress chunk data: %w", err)
		}
		compressionAlgo = string(c.compressor.Algorithm())
	} else {
		// Use default ZSTD compressor
		compressedData, err = compress.QuickCompress(chunkJSON)
		if err != nil {
			return fmt.Errorf("compress chunk data: %w", err)
		}
	}

	// Base64 encode compressed data
	encodedData := base64.StdEncoding.EncodeToString(compressedData)

	// Build request body
	reqBody := struct {
		ReportID    string `json:"report_id"`
		ChunkIndex  int    `json:"chunk_index"`
		TotalChunks int    `json:"total_chunks"`
		Compression string `json:"compression"`
		Data        string `json:"data"`
		IsFinal     bool   `json:"is_final"`
	}{
		ReportID:    data.ReportID,
		ChunkIndex:  data.ChunkIndex,
		TotalChunks: data.TotalChunks,
		Compression: compressionAlgo,
		Data:        encodedData,
		IsFinal:     data.IsFinal,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// Send request (the body itself is not compressed at HTTP level since data is base64)
	respBody, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return fmt.Errorf("upload chunk: %w", err)
	}

	var resp ChunkUploadResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Chunk %d/%d uploaded: %d findings, %d assets\n",
			data.ChunkIndex+1, data.TotalChunks, resp.FindingsCreated, resp.AssetsCreated)
	}

	return nil
}

// AsChunkUploader returns the client as a chunk.Uploader interface.
// This is useful for passing to chunk.Manager.
func (c *Client) AsChunkUploader() chunk.Uploader {
	return c
}

// =============================================================================
// Suppression API
// =============================================================================

// SuppressionRule represents a platform-controlled suppression rule.
type SuppressionRule struct {
	RuleID      string  `json:"rule_id,omitempty"`
	ToolName    string  `json:"tool_name,omitempty"`
	PathPattern string  `json:"path_pattern,omitempty"`
	AssetID     *string `json:"asset_id,omitempty"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// GetSuppressions fetches the tenant's active suppression rules from the
// platform, for the security gate to leave out findings the platform has
// suppressed.
//
// It calls the sensor route (legacyv1.PathSuppressions). An API that predates
// that route answers 404; the client then tries the user route
// (legacyv1.PathSuppressionsUser) once, which only accepts a user token.
//
// A failure is returned, never swallowed: the caller decides whether a gate
// may run without suppressions, and should say so where the operator sees it.
func (c *Client) GetSuppressions(ctx context.Context) ([]SuppressionRule, error) {
	if c.verbose {
		fmt.Println("[openctem] Fetching suppression rules")
	}

	if useV2, _ := c.controlV2(ctx, protov2.FeatureSuppressions); useV2 {
		rules, err := c.suppressionsV2(ctx)
		if err == nil {
			if c.verbose {
				fmt.Printf("[openctem] Fetched %d suppression rules (v2)\n", len(rules))
			}
			return rules, nil
		}
		if !isRouteMissing(err) {
			return nil, fmt.Errorf("fetch suppression rules: %w", err)
		}
		c.renegotiate()
	}

	data, err := c.doRequest(ctx, http.MethodGet, c.baseURL+legacyv1.PathSuppressions, nil)
	if err != nil && IsNotFoundError(err) {
		data, err = c.doRequest(ctx, http.MethodGet, c.baseURL+legacyv1.PathSuppressionsUser, nil)
	}
	if err != nil {
		if IsAuthenticationError(err) || IsAuthorizationError(err) {
			return nil, fmt.Errorf("fetch suppression rules: the platform refused this key (%w); "+
				"the platform needs %s (OpenCTEM API with sensor suppressions)", err, legacyv1.PathSuppressions)
		}
		return nil, fmt.Errorf("fetch suppression rules: %w", err)
	}

	var resp struct {
		Rules []SuppressionRule `json:"rules"`
		Count int               `json:"count"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal suppressions response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Fetched %d suppression rules\n", resp.Count)
	}

	return resp.Rules, nil
}

// FilterSuppressedFindings removes findings that match suppression rules.
// This is used by the security gate to exclude false positives.
func (c *Client) FilterSuppressedFindings(findings []ctis.Finding, rules []SuppressionRule) []ctis.Finding {
	if len(rules) == 0 {
		return findings
	}

	var filtered []ctis.Finding
	for _, f := range findings {
		if !c.isFiningSuppressed(f, rules) {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

// isFiningSuppressed checks if a finding matches any suppression rule.
func (c *Client) isFiningSuppressed(f ctis.Finding, rules []SuppressionRule) bool {
	for _, rule := range rules {
		if c.matchesSuppressionRule(f, rule) {
			return true
		}
	}
	return false
}

// matchesSuppressionRule checks if a finding matches a specific suppression rule.
// Note: ToolName is not checked here because Finding doesn't have Tool info;
// it should be checked at the Report level before calling this function.
func (c *Client) matchesSuppressionRule(f ctis.Finding, rule SuppressionRule) bool {
	// Track whether at least one finding-level matcher actually applied. A rule
	// with no RuleID and no PathPattern (e.g. an asset-only rule, handled
	// elsewhere) must NOT match every finding — returning true here would
	// silently drop the entire result set (fail-open in a security gate).
	matched := false

	// Check rule ID (supports wildcard suffix)
	if rule.RuleID != "" {
		if strings.HasSuffix(rule.RuleID, "*") {
			prefix := strings.TrimSuffix(rule.RuleID, "*")
			if !strings.HasPrefix(f.RuleID, prefix) {
				return false
			}
		} else if rule.RuleID != f.RuleID {
			return false
		}
		matched = true
	}

	// Check path pattern. A path rule can only match a finding that has a path.
	if rule.PathPattern != "" {
		if f.Location == nil || f.Location.Path == "" {
			return false
		}
		if !matchGlobPattern(rule.PathPattern, f.Location.Path) {
			return false
		}
		matched = true
	}

	return matched
}

// matchGlobPattern provides simple glob matching with ** support.
func matchGlobPattern(pattern, path string) bool {
	// Handle ** patterns
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			if prefix != "" && !strings.HasPrefix(path, prefix) {
				return false
			}
			if suffix != "" && !strings.HasSuffix(path, suffix) {
				return false
			}
			return true
		}
	}

	// Simple wildcard matching
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}

	return pattern == path
}

// =============================================================================
// Finding Enrichment API
// =============================================================================

// EnrichFindings adds EPSS and KEV data to findings with CVE IDs.
func (c *Client) EnrichFindings(ctx context.Context, findings []ctis.Finding) ([]ctis.Finding, error) {
	// Collect CVE IDs
	cveIDs := make([]string, 0)
	for _, f := range findings {
		if f.Vulnerability != nil && f.Vulnerability.CVEID != "" {
			cveIDs = append(cveIDs, f.Vulnerability.CVEID)
		}
	}

	if len(cveIDs) == 0 {
		return findings, nil
	}

	// Fetch EPSS scores
	epssScores, _ := c.GetEPSSScores(ctx, cveIDs)
	epssMap := make(map[string]EPSSScore)
	for _, score := range epssScores {
		epssMap[score.CVEID] = score
	}

	// Fetch KEV entries
	kevEntries, _ := c.GetKEVEntries(ctx, cveIDs)
	kevMap := make(map[string]bool)
	for _, entry := range kevEntries {
		kevMap[entry.CVEID] = true
	}

	// Enrich findings
	result := make([]ctis.Finding, len(findings))
	for i, f := range findings {
		result[i] = f
		if f.Vulnerability != nil && f.Vulnerability.CVEID != "" {
			// Vulnerability is a pointer, so the struct copy above shares it.
			// Deep-copy before writing, else we'd mutate the CALLER's original
			// finding's Vulnerability (EPSS/KEV) in place.
			v := *f.Vulnerability
			result[i].Vulnerability = &v
			cveID := v.CVEID
			if epss, ok := epssMap[cveID]; ok {
				result[i].Vulnerability.EPSSScore = epss.Score
				result[i].Vulnerability.EPSSPercentile = epss.Percentile
			}
			if kevMap[cveID] {
				result[i].Vulnerability.InCISAKEV = true
			}
		}
	}

	return result, nil
}
