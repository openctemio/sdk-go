package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// RegistrationRequest contains the data for registering a new platform agent.
type RegistrationRequest struct {
	// Name is the agent's display name.
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

// RegistrationResponse contains the response from agent registration.
type RegistrationResponse struct {
	AgentID   string `json:"agent_id"`
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

// Bootstrapper handles platform agent registration using bootstrap tokens.
//
// Bootstrap tokens are short-lived tokens that allow new agents to register
// themselves with the platform. The flow is:
//
//  1. Admin creates a bootstrap token via CLI or API
//  2. Token is provided to the agent deployment (e.g., via environment variable)
//  3. Agent uses Bootstrapper to register and receive permanent API credentials
//  4. Agent stores credentials securely and uses them for all future API calls
//
// Example:
//
//	bootstrapper := platform.NewBootstrapper(baseURL, os.Getenv("BOOTSTRAP_TOKEN"))
//	creds, err := bootstrapper.Register(ctx, &platform.RegistrationRequest{
//	    Name: "scanner-001",
//	    Capabilities: []string{"sast", "sca"},
//	    Region: "us-east-1",
//	})
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
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// Register registers a new platform agent and returns the API credentials.
//
// IMPORTANT: The returned API key is only provided once. Store it securely
// (e.g., in a secrets manager or encrypted file). If lost, the agent must
// be deleted and re-registered with a new bootstrap token.
func (b *Bootstrapper) Register(ctx context.Context, req *RegistrationRequest) (*RegistrationResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("agent name is required")
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
			time.Sleep(b.config.RetryDelay)
		}

		resp, err := b.doRegister(ctx, req)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if b.config.Verbose {
			fmt.Printf("[bootstrap] Registration failed: %v\n", err)
		}
	}

	return nil, fmt.Errorf("registration failed after %d attempts: %w", b.config.RetryAttempts+1, lastErr)
}

func (b *Bootstrapper) doRegister(ctx context.Context, req *RegistrationRequest) (*RegistrationResponse, error) {
	url := fmt.Sprintf("%s/api/v1/platform/register", b.baseURL)

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
		fmt.Printf("[bootstrap] Registering agent %q with capabilities %v\n", req.Name, req.Capabilities)
	}

	resp, err := b.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid or expired bootstrap token")
	}
	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("agent with this name already exists")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if b.config.Verbose {
		fmt.Printf("[bootstrap] Registration successful! Agent ID: %s, API Key Prefix: %s\n",
			result.AgentID, result.APIPrefix)
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

// CredentialStore interface for storing agent credentials.
type CredentialStore interface {
	Save(creds *AgentCredentials) error
	Load() (*AgentCredentials, error)
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
func (s *FileCredentialStore) Save(creds *AgentCredentials) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	// Write with restricted permissions (owner read/write only)
	if err := os.WriteFile(s.Path, data, 0600); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}

	return nil
}

// Load loads credentials from the file.
func (s *FileCredentialStore) Load() (*AgentCredentials, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}

	var creds AgentCredentials
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

// EnsureRegistered ensures the agent is registered, either by loading existing
// credentials or registering with a bootstrap token.
//
// This is the recommended way to initialize a platform agent:
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
func EnsureRegistered(ctx context.Context, config *EnsureRegisteredConfig) (*AgentCredentials, error) {
	if config.CredentialsFile == "" {
		return nil, fmt.Errorf("credentials file path is required")
	}

	store := NewFileCredentialStore(config.CredentialsFile)

	// Try to load existing credentials
	if store.Exists() {
		creds, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials: %w", err)
		}
		if config.Verbose {
			fmt.Printf("[bootstrap] Loaded existing credentials for agent %s\n", creds.AgentID)
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

	// Register the agent
	bootstrapper := NewBootstrapper(config.BaseURL, config.BootstrapToken, &BootstrapConfig{
		Verbose: config.Verbose,
	})

	resp, err := bootstrapper.Register(ctx, config.Registration)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// Save credentials
	creds := &AgentCredentials{
		AgentID:   resp.AgentID,
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

	// CredentialsFile is the path to store/load credentials.
	CredentialsFile string

	// Registration is the registration request.
	// Only needed if credentials don't exist.
	Registration *RegistrationRequest

	// Verbose enables debug logging.
	Verbose bool
}
