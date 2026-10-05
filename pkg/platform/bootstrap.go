package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Non-retryable registration errors. A bad bootstrap token or a name conflict
// will never succeed on retry, so the loop stops immediately on these.
var (
	ErrBootstrapTokenInvalid = errors.New("invalid or expired bootstrap token")
	ErrSensorAlreadyExists   = errors.New("sensor with this name already exists")
)

// RegistrationRequest contains the data for registering a new platform sensor.
type RegistrationRequest struct {
	// Name is the sensor's display name.
	Name string `json:"name"`

	// Capabilities are the scanner/collector capabilities (e.g., "sast", "sca", "dast").
	Capabilities []string `json:"capabilities"`

	// Tools are the specific tools available (e.g., "semgrep", "trivy", "nuclei").
	Tools []string `json:"tools,omitempty"`

	// Region is the deployment region (e.g., "us-east-1", "ap-southeast-1").
	Region string `json:"region,omitempty"`

	// Labels are optional key-value labels for filtering.
	Labels map[string]string `json:"labels,omitempty"`

	// MaxConcurrentJobs is the maximum number of concurrent jobs.
	MaxConcurrentJobs int `json:"max_concurrent_jobs,omitempty"`
}

// RegistrationResponse contains the response from sensor registration.
type RegistrationResponse struct {
	// SensorID is the pre-rename "agent_id" key (legacyv1.FieldSensorID).
	SensorID  string `json:"agent_id"`
	APIKey    string `json:"api_key"`    // Only returned once - store securely!
	APIPrefix string `json:"api_prefix"` // Prefix for display/logging (safe to log)
	Message   string `json:"message,omitempty"`
}

// BootstrapConfig configures the Bootstrapper.
type BootstrapConfig struct {
	// Timeout for the registration request.
	Timeout time.Duration

	// RetryAttempts is the number of times to retry on failure.
	RetryAttempts int

	// RetryDelay is the delay between retry attempts.
	RetryDelay time.Duration

	// Verbose enables debug logging.
	Verbose bool
}

// Bootstrapper handles platform sensor registration using bootstrap tokens.
//
// Bootstrap tokens are short-lived tokens that allow new sensors to register
// themselves with the platform. The flow is:
//
//  1. Admin creates a bootstrap token via CLI or API
//  2. Token is provided to the sensor deployment (e.g., via environment variable)
//  3. Sensor uses Bootstrapper to register and receive permanent API credentials
//  4. Sensor stores credentials securely and uses them for all future API calls
//
// Example:
//
//	bootstrapper := platform.NewBootstrapper(baseURL, os.Getenv("BOOTSTRAP_TOKEN"))
//	creds, err := bootstrapper.Register(ctx, &platform.RegistrationRequest{
//	    Name: "scanner-001",
//	    Capabilities: []string{"sast", "sca"},
//	    Region: "us-east-1",
//	})
//
// No server for this flow: no OpenCTEM API serves POST
// /api/v1/platform/register (bootstrap tokens were never built; api RFC-032
// §3.4). Sensors authenticate with the API key an administrator issues;
// enrollment tokens (api RFC-032 Phase 2) replace this flow. Kept so code
// that compiles against it keeps compiling, until it is removed.
type Bootstrapper struct {
	baseURL        string
	bootstrapToken string
	config         *BootstrapConfig
	httpClient     *http.Client
}

// NewBootstrapper creates a new Bootstrapper.
func NewBootstrapper(baseURL, bootstrapToken string, config *BootstrapConfig) *Bootstrapper {
	if config == nil {
		config = &BootstrapConfig{}
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultBootstrapTimeout
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 2 * time.Second
	}

	return &Bootstrapper{
		baseURL:        baseURL,
		bootstrapToken: bootstrapToken,
		config:         config,
		// SSRF: bootstrap endpoint URL comes from operator config; the
		// token is one-shot-high-value so we add dialer-level guarding
		// to prevent a rebind-style leak of the token into private
		// space during enrolment.
		httpClient: newAPIHTTPClient(config.Timeout),
	}
}

// Register registers a new platform sensor and returns the API credentials.
//
// IMPORTANT: The returned API key is only provided once. Store it securely
// (e.g., in a secrets manager or encrypted file). If lost, the sensor must
// be deleted and re-registered with a new bootstrap token.
func (b *Bootstrapper) Register(ctx context.Context, req *RegistrationRequest) (*RegistrationResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("sensor name is required")
	}
	if len(req.Capabilities) == 0 {
		return nil, fmt.Errorf("at least one capability is required")
	}

	// Auto-detect region if not specified
	if req.Region == "" {
		req.Region = detectRegion()
	}

	// Get hostname for default name suffix
	if hostname, err := os.Hostname(); err == nil && req.Labels == nil {
		req.Labels = map[string]string{"hostname": hostname}
	}

	var lastErr error
	for attempt := 0; attempt <= b.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			if b.config.Verbose {
				fmt.Printf("[bootstrap] Retry attempt %d/%d after %v\n",
					attempt, b.config.RetryAttempts, b.config.RetryDelay)
			}
			// Honor cancellation while backing off (a draining sensor must
			// not block on a fixed sleep).
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(b.config.RetryDelay):
			}
		}

		resp, err := b.doRegister(ctx, req)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if b.config.Verbose {
			fmt.Printf("[bootstrap] Registration failed: %v\n", err)
		}

		// Don't waste attempts on errors that can never succeed on retry.
		if errors.Is(err, ErrBootstrapTokenInvalid) || errors.Is(err, ErrSensorAlreadyExists) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("registration failed after %d attempts: %w", b.config.RetryAttempts+1, lastErr)
}

func (b *Bootstrapper) doRegister(ctx context.Context, req *RegistrationRequest) (*RegistrationResponse, error) {
	url, err := apiURL(b.baseURL, "/api/v1/platform/register")
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+b.bootstrapToken)

	if b.config.Verbose {
		fmt.Printf("[bootstrap] Registering sensor %q with capabilities %v\n", req.Name, req.Capabilities)
	}

	resp, err := b.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrBootstrapTokenInvalid
	}
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrSensorAlreadyExists
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if b.config.Verbose {
		fmt.Printf("[bootstrap] Registration successful! Sensor ID: %s, API Key Prefix: %s\n",
			result.SensorID, result.APIPrefix)
	}

	return &result, nil
}

// detectRegion tries to detect the deployment region from environment variables.
func detectRegion() string {
	envVars := []string{
		"REGION",
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
		"GOOGLE_CLOUD_REGION",
		"AZURE_REGION",
	}

	for _, env := range envVars {
		if val := os.Getenv(env); val != "" {
			return val
		}
	}

	return ""
}

// =============================================================================
// Credential Storage Helpers
// =============================================================================

// CredentialStore interface for storing sensor credentials.
type CredentialStore interface {
	Save(creds *SensorCredentials) error
	Load() (*SensorCredentials, error)
	Exists() bool
}

// FileCredentialStore stores credentials in a file.
type FileCredentialStore struct {
	Path string
}

// NewFileCredentialStore creates a new file-based credential store.
func NewFileCredentialStore(path string) *FileCredentialStore {
	return &FileCredentialStore{Path: path}
}

// Save saves credentials to the file.
//
// The write is atomic and owner-only: the JSON goes to a 0600 temp file in
// the same directory, is fsynced, then renamed over Path. A crash or full
// disk mid-write therefore never leaves a truncated credentials file (which
// would lose the only copy of a rotated key), and a pre-existing file with
// looser permissions is replaced by a 0600 one rather than rewritten in
// place with its old mode.
func (s *FileCredentialStore) Save(creds *SensorCredentials) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := writeFileAtomic(s.Path, data); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}

	return nil
}

// writeFileAtomic writes data to path via temp file + fsync + rename, with
// mode 0600. The parent directory is created 0700 if missing.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp already uses 0600; Chmod makes it explicit and independent
	// of platform defaults.
	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	// Persist the rename itself. Best effort: not supported on every OS.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Load loads credentials from the file.
func (s *FileCredentialStore) Load() (*SensorCredentials, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}

	var creds SensorCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}

	return &creds, nil
}

// Exists checks if the credentials file exists.
func (s *FileCredentialStore) Exists() bool {
	_, err := os.Stat(s.Path)
	return err == nil
}

// =============================================================================
// Bootstrap-Or-Load Helper
// =============================================================================

// EnsureRegistered ensures the sensor is registered, either by loading existing
// credentials or registering with a bootstrap token.
//
// This is the recommended way to initialize a platform sensor:
//
//	creds, err := platform.EnsureRegistered(ctx, &platform.EnsureRegisteredConfig{
//	    BaseURL: "http://localhost:8080",
//	    BootstrapToken: os.Getenv("BOOTSTRAP_TOKEN"),
//	    CredentialsFile: "/etc/openctem/credentials.json",
//	    Registration: &platform.RegistrationRequest{
//	        Name: "scanner-001",
//	        Capabilities: []string{"sast", "sca"},
//	    },
//	})
//
// With an empty CredentialsFile the default ~/.openctem/sensor-credentials.json
// is used, and a credentials file left by a sensor from before the agent ->
// sensor rename (~/.openctem/agent-credentials.json) is moved there first, so
// the sensor keeps its identity and key and does not register again (see
// ResolveCredentialsFile). An explicit path is used as is.
//
// No server for this flow: no OpenCTEM API serves POST
// /api/v1/platform/register (bootstrap tokens were never built; api RFC-032
// §3.4). Sensors authenticate with the API key an administrator issues;
// enrollment tokens (api RFC-032 Phase 2) replace this flow. Kept so code
// that compiles against it keeps compiling, until it is removed.
func EnsureRegistered(ctx context.Context, config *EnsureRegisteredConfig) (*SensorCredentials, error) {
	path, err := ResolveCredentialsFile(config.CredentialsFile)
	if err != nil {
		return nil, err
	}
	config.CredentialsFile = path

	store := NewFileCredentialStore(config.CredentialsFile)

	// Try to load existing credentials
	if store.Exists() {
		creds, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials: %w", err)
		}
		if config.Verbose {
			fmt.Printf("[bootstrap] Loaded existing credentials for sensor %s\n", creds.SensorID)
		}
		return creds, nil
	}

	// Need to register with bootstrap token
	if config.BootstrapToken == "" {
		return nil, fmt.Errorf("no credentials file found and no bootstrap token provided")
	}
	if config.Registration == nil {
		return nil, fmt.Errorf("registration request is required when bootstrapping")
	}

	// Register the sensor
	bootstrapper := NewBootstrapper(config.BaseURL, config.BootstrapToken, &BootstrapConfig{
		Verbose: config.Verbose,
	})

	resp, err := bootstrapper.Register(ctx, config.Registration)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// Save credentials
	creds := &SensorCredentials{
		SensorID:  resp.SensorID,
		APIKey:    resp.APIKey,
		APIPrefix: resp.APIPrefix,
	}

	if err := store.Save(creds); err != nil {
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}

	if config.Verbose {
		fmt.Printf("[bootstrap] Saved credentials to %s\n", config.CredentialsFile)
	}

	return creds, nil
}

// EnsureRegisteredConfig configures EnsureRegistered.
type EnsureRegisteredConfig struct {
	// BaseURL is the API base URL.
	BaseURL string

	// BootstrapToken is the bootstrap token for registration.
	// Only needed if credentials don't exist.
	BootstrapToken string

	// CredentialsFile is the path to store/load credentials. Empty means
	// DefaultCredentialsFile (with the pre-rename file migrated); on return
	// EnsureRegistered has set it to the path actually used.
	CredentialsFile string

	// Registration is the registration request.
	// Only needed if credentials don't exist.
	Registration *RegistrationRequest

	// Verbose enables debug logging.
	Verbose bool
}
