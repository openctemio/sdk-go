// Package client provides the OpenCTEM API client.
package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/retry"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", cfg.MaxRetries)
	}
	if cfg.RetryDelay != 2*time.Second {
		t.Errorf("RetryDelay = %v, want 2s", cfg.RetryDelay)
	}
}

func TestNew(t *testing.T) {
	cfg := &Config{
		BaseURL:    "https://localhost:8080",
		APIKey:     "test-key",
		AgentID:    "agent-123",
		Timeout:    10 * time.Second,
		MaxRetries: 5,
		RetryDelay: 1 * time.Second,
	}

	c := New(cfg)

	if c.baseURL != cfg.BaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, cfg.BaseURL)
	}
	if c.apiKey != cfg.APIKey {
		t.Errorf("apiKey = %q, want %q", c.apiKey, cfg.APIKey)
	}
	if c.agentID != cfg.AgentID {
		t.Errorf("agentID = %q, want %q", c.agentID, cfg.AgentID)
	}
	if c.maxRetries != cfg.MaxRetries {
		t.Errorf("maxRetries = %d, want %d", c.maxRetries, cfg.MaxRetries)
	}
}

func TestNew_DefaultValues(t *testing.T) {
	// Test that zero values get defaults
	cfg := &Config{
		BaseURL: "https://localhost:8080",
		APIKey:  "test-key",
	}

	c := New(cfg)

	if c.maxRetries != 3 {
		t.Errorf("maxRetries should default to 3, got %d", c.maxRetries)
	}
	if c.retryDelay != 2*time.Second {
		t.Errorf("retryDelay should default to 2s, got %v", c.retryDelay)
	}
}

func TestNewWithOptions(t *testing.T) {
	c := NewWithOptions(
		WithBaseURL("https://custom.api.com"),
		WithAPIKey("custom-key"),
		WithAgentID("agent-456"),
		WithTimeout(15*time.Second),
		WithRetry(5, 3*time.Second),
		WithVerbose(true),
	)

	if c.baseURL != "https://custom.api.com" {
		t.Errorf("baseURL = %q, want 'https://custom.api.com'", c.baseURL)
	}
	if c.apiKey != "custom-key" {
		t.Errorf("apiKey = %q, want 'custom-key'", c.apiKey)
	}
	if c.agentID != "agent-456" {
		t.Errorf("agentID = %q, want 'agent-456'", c.agentID)
	}
	if c.maxRetries != 5 {
		t.Errorf("maxRetries = %d, want 5", c.maxRetries)
	}
	if c.retryDelay != 3*time.Second {
		t.Errorf("retryDelay = %v, want 3s", c.retryDelay)
	}
	if !c.verbose {
		t.Error("verbose should be true")
	}
}

func TestClient_PushFindings(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/agent/ingest" {
			t.Errorf("Path = %s, want /api/v1/agent/ingest", r.URL.Path)
		}

		// Check authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key" {
			t.Errorf("Authorization = %q, want 'Bearer test-key'", auth)
		}

		// Return success response
		resp := IngestResponse{
			ScanID:          "scan-123",
			FindingsCreated: 2,
			FindingsUpdated: 1,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})

	report := ctis.NewReport()
	report.Findings = []ctis.Finding{
		{ID: "finding-1", Title: "Test Finding", Severity: ctis.SeverityHigh},
		{ID: "finding-2", Title: "Another Finding", Severity: ctis.SeverityMedium},
	}

	result, err := c.PushFindings(context.Background(), report)
	if err != nil {
		t.Fatalf("PushFindings() error = %v", err)
	}

	if result.FindingsCreated != 2 {
		t.Errorf("FindingsCreated = %d, want 2", result.FindingsCreated)
	}
	if result.FindingsUpdated != 1 {
		t.Errorf("FindingsUpdated = %d, want 1", result.FindingsUpdated)
	}
}

func TestClient_PushFindings_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server error"}`))
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		MaxRetries: 1, // Reduce retries for faster test
		RetryDelay: 10 * time.Millisecond,
	})

	report := ctis.NewReport()
	report.Findings = []ctis.Finding{{ID: "f1"}}

	_, err := c.PushFindings(context.Background(), report)
	if err == nil {
		t.Error("PushFindings() should return error on server error")
	}
}

func TestClient_PushAssets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IngestResponse{
			ScanID:        "scan-456",
			AssetsCreated: 3,
			AssetsUpdated: 0,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})

	report := ctis.NewReport()
	report.Assets = []ctis.Asset{
		{ID: "asset-1", Type: ctis.AssetTypeRepository, Value: "github.com/test/repo"},
	}

	result, err := c.PushAssets(context.Background(), report)
	if err != nil {
		t.Fatalf("PushAssets() error = %v", err)
	}

	if result.AssetsCreated != 3 {
		t.Errorf("AssetsCreated = %d, want 3", result.AssetsCreated)
	}
}

func TestClient_SendHeartbeat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/heartbeat" {
			t.Errorf("Path = %s, want /api/v1/agent/heartbeat", r.URL.Path)
		}

		resp := map[string]interface{}{
			"status":    "ok",
			"agent_id":  "agent-123",
			"tenant_id": "tenant-456",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
		AgentID: "agent-123",
	})

	status := &core.AgentStatus{
		Name:     "test-agent",
		Status:   core.AgentStateRunning,
		Scanners: []string{"semgrep", "trivy"},
	}

	err := c.SendHeartbeat(context.Background(), status)
	if err != nil {
		t.Errorf("SendHeartbeat() error = %v", err)
	}
}

func TestClient_TestConnection(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"success", http.StatusOK, false},
		{"unauthorized", http.StatusUnauthorized, true},
		{"server error", http.StatusInternalServerError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
				}
			}))
			defer server.Close()

			c := New(&Config{
				BaseURL:    server.URL,
				APIKey:     "test-key",
				MaxRetries: 1,
				RetryDelay: 10 * time.Millisecond,
			})

			err := c.TestConnection(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("TestConnection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_CheckFingerprints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/ingest/check" {
			t.Errorf("Path = %s, want /api/v1/agent/ingest/check", r.URL.Path)
		}

		// Parse request
		var req struct {
			Fingerprints []string `json:"fingerprints"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		// Return some as existing, some as missing
		resp := map[string]interface{}{
			"existing": []string{req.Fingerprints[0]},
			"missing":  req.Fingerprints[1:],
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})

	fingerprints := []string{"fp1", "fp2", "fp3"}
	result, err := c.CheckFingerprints(context.Background(), fingerprints)
	if err != nil {
		t.Fatalf("CheckFingerprints() error = %v", err)
	}

	if len(result.Existing) != 1 || result.Existing[0] != "fp1" {
		t.Errorf("existing = %v, want [fp1]", result.Existing)
	}
	if len(result.Missing) != 2 {
		t.Errorf("missing = %v, want [fp2, fp3]", result.Missing)
	}
}

func TestClient_Headers(t *testing.T) {
	var capturedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL: server.URL,
		APIKey:  "my-api-key",
		AgentID: "agent-xyz",
	})

	c.TestConnection(context.Background())

	// Verify headers
	if auth := capturedHeaders.Get("Authorization"); auth != "Bearer my-api-key" {
		t.Errorf("Authorization = %q, want 'Bearer my-api-key'", auth)
	}
	if agentID := capturedHeaders.Get("X-Agent-ID"); agentID != "agent-xyz" {
		t.Errorf("X-Agent-ID = %q, want 'agent-xyz'", agentID)
	}
	if contentType := capturedHeaders.Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Content-Type = %q, want 'application/json'", contentType)
	}
}

func TestIsHTTPError(t *testing.T) {
	tests := []struct {
		err        error
		wantCode   int
		wantResult bool
	}{
		{&HTTPError{StatusCode: 401}, 401, true},
		{&HTTPError{StatusCode: 500}, 500, true},
		{&HTTPError{StatusCode: 404}, 404, true},
		{nil, 0, false},
	}

	for _, tt := range tests {
		httpErr, ok := IsHTTPError(tt.err)
		if ok != tt.wantResult {
			t.Errorf("IsHTTPError() ok = %v, want %v", ok, tt.wantResult)
		}
		if ok && httpErr.StatusCode != tt.wantCode {
			t.Errorf("IsHTTPError() code = %d, want %d", httpErr.StatusCode, tt.wantCode)
		}
	}
}

func TestIsClientError(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   bool
	}{
		{400, true},
		{401, true},
		{403, true},
		{404, true},
		{499, true},
		{500, false},
		{200, false},
	}

	for _, tt := range tests {
		err := &HTTPError{StatusCode: tt.statusCode}
		if got := IsClientError(err); got != tt.expected {
			t.Errorf("IsClientError(%d) = %v, want %v", tt.statusCode, got, tt.expected)
		}
	}
}

func TestIsServerError(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   bool
	}{
		{500, true},
		{502, true},
		{503, true},
		{504, true},
		{400, false},
		{404, false},
	}

	for _, tt := range tests {
		err := &HTTPError{StatusCode: tt.statusCode}
		if got := IsServerError(err); got != tt.expected {
			t.Errorf("IsServerError(%d) = %v, want %v", tt.statusCode, got, tt.expected)
		}
	}
}

func TestIsRateLimitError(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   bool
	}{
		{429, true},
		{400, false},
		{500, false},
	}

	for _, tt := range tests {
		err := &HTTPError{StatusCode: tt.statusCode}
		if got := IsRateLimitError(err); got != tt.expected {
			t.Errorf("IsRateLimitError(%d) = %v, want %v", tt.statusCode, got, tt.expected)
		}
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{"429 rate limit", 429, true},
		{"500 server error", 500, true},
		{"502 bad gateway", 502, true},
		{"503 unavailable", 503, true},
		{"504 timeout", 504, true},
		{"400 bad request", 400, false},
		{"401 unauthorized", 401, false},
		{"403 forbidden", 403, false},
		{"404 not found", 404, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &HTTPError{StatusCode: tt.statusCode}
			if got := IsRetryable(err); got != tt.expected {
				t.Errorf("IsRetryable(%d) = %v, want %v", tt.statusCode, got, tt.expected)
			}
		})
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay to simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		MaxRetries: 1,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := c.TestConnection(ctx)
	if err == nil {
		t.Error("Expected error when context is canceled")
	}
}

func TestClient_SetVerbose(t *testing.T) {
	c := New(&Config{
		BaseURL: "https://localhost:8080",
		APIKey:  "test-key",
	})

	if c.verbose {
		t.Error("verbose should default to false")
	}

	c.SetVerbose(true)
	if !c.verbose {
		t.Error("SetVerbose(true) should set verbose to true")
	}

	c.SetVerbose(false)
	if c.verbose {
		t.Error("SetVerbose(false) should set verbose to false")
	}
}

func TestClient_PushReport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IngestResponse{
			ScanID:          "scan-789",
			FindingsCreated: 1,
			AssetsCreated:   1,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})

	report := ctis.NewReport()
	report.Findings = []ctis.Finding{{ID: "f1"}}
	report.Assets = []ctis.Asset{{ID: "a1", Type: ctis.AssetTypeRepository, Value: "test"}}

	err := c.PushReport(context.Background(), report)
	if err != nil {
		t.Errorf("PushReport() error = %v", err)
	}
}

func TestHTTPError_Error(t *testing.T) {
	err := &HTTPError{
		StatusCode: 401,
		Body:       "Unauthorized",
	}

	msg := err.Error()
	if msg == "" {
		t.Error("HTTPError.Error() should not return empty string")
	}
}

// Test that FingerprintCheckResult is properly returned
func TestClient_CheckFingerprints_EmptyInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := retry.FingerprintCheckResult{
			Existing: []string{},
			Missing:  []string{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := New(&Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})

	result, err := c.CheckFingerprints(context.Background(), []string{})
	if err != nil {
		t.Fatalf("CheckFingerprints() error = %v", err)
	}

	if len(result.Existing) != 0 {
		t.Errorf("Existing should be empty, got %v", result.Existing)
	}
	if len(result.Missing) != 0 {
		t.Errorf("Missing should be empty, got %v", result.Missing)
	}
}

// Benchmark tests
func BenchmarkClient_New(b *testing.B) {
	cfg := &Config{
		BaseURL:    "https://localhost:8080",
		APIKey:     "test-key",
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = New(cfg)
	}
}

func BenchmarkClient_NewWithOptions(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewWithOptions(
			WithBaseURL("https://localhost:8080"),
			WithAPIKey("test-key"),
			WithTimeout(30*time.Second),
		)
	}
}
