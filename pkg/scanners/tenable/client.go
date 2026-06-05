package tenable

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NOTE ON VERIFICATION
// --------------------
// The REST endpoint shapes below follow Tenable's published Nessus REST API
// (scans create/launch/status/export). They are exercised by httptest mocks in
// client_test.go, which proves request/response *wiring* but NOT correctness
// against a live appliance. Verify against a real Nessus instance before relying
// on this in production (RFC-007 Phase 2 spike). Tenable.sc (/rest) has a
// different surface and is a follow-up (see scParams/Engine).

// Engine identifies the Tenable product the client talks to.
type Engine string

const (
	EngineNessusPro Engine = "nessus_pro"
	EngineTenableSC Engine = "tenable_sc"
)

// ScanState is the normalized lifecycle state of a launched scan.
type ScanState string

const (
	ScanPending   ScanState = "pending"
	ScanRunning   ScanState = "running"
	ScanCompleted ScanState = "completed"
	ScanFailed    ScanState = "failed"
)

// Credentials holds Tenable API keys. On a runner these are configured locally
// and never leave the customer's environment.
type Credentials struct {
	AccessKey string
	SecretKey string
}

// ScanRef identifies a launched scan for polling/export.
type ScanRef struct {
	ScanID string
	FileID string // set after Export is requested (Nessus export file handle)
}

// LaunchRequest describes a scan to launch.
type LaunchRequest struct {
	// Targets are IPs/CIDRs/hostnames to scan.
	Targets []string
	// PolicyID / TemplateUUID selects the scan policy (engine-specific).
	TemplateUUID string
	// Name for the scan in the appliance.
	Name string
}

// Client is the engine-agnostic Tenable scan client.
type Client interface {
	Engine() Engine
	TestConnection(ctx context.Context) error
	Launch(ctx context.Context, req LaunchRequest) (ScanRef, error)
	Poll(ctx context.Context, ref ScanRef) (ScanState, error)
	// Export requests + downloads the .nessus for a completed scan.
	Export(ctx context.Context, ref ScanRef) (io.ReadCloser, error)
}

// NessusProClient talks to a standalone Nessus Professional/Expert appliance.
type NessusProClient struct {
	baseURL string
	creds   Credentials
	http    *http.Client
}

// NewNessusProClient builds a client. httpClient is injected so the caller
// controls TLS / SSRF-safety / timeouts; nil → a 60s default.
func NewNessusProClient(baseURL string, creds Credentials, httpClient *http.Client) (*NessusProClient, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("tenable: base URL required")
	}
	if creds.AccessKey == "" || creds.SecretKey == "" {
		return nil, fmt.Errorf("tenable: access key and secret key required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	return &NessusProClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		creds:   creds,
		http:    httpClient,
	}, nil
}

func (c *NessusProClient) Engine() Engine { return EngineNessusPro }

func (c *NessusProClient) apiKeyHeader() string {
	return fmt.Sprintf("accessKey=%s; secretKey=%s", c.creds.AccessKey, c.creds.SecretKey)
}

func (c *NessusProClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-ApiKeys", c.apiKeyHeader())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// TestConnection verifies credentials via the server properties endpoint.
func (c *NessusProClient) TestConnection(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/server/properties", nil)
	if err != nil {
		return fmt.Errorf("tenable connection failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tenable authentication failed (status %d)", resp.StatusCode)
	}
	return nil
}

// Launch creates a scan with the given targets and launches it.
func (c *NessusProClient) Launch(ctx context.Context, req LaunchRequest) (ScanRef, error) {
	uuid := req.TemplateUUID
	if uuid == "" {
		// "basic network scan" custom template uuid varies per install; the
		// caller normally supplies it. Empty is rejected by the appliance.
		return ScanRef{}, fmt.Errorf("tenable: template uuid required")
	}
	name := req.Name
	if name == "" {
		name = "openctem-coverage"
	}

	createBody := map[string]any{
		"uuid": uuid,
		"settings": map[string]any{
			"name":         name,
			"text_targets": strings.Join(req.Targets, ","),
		},
	}
	resp, err := c.do(ctx, http.MethodPost, "/scans", createBody)
	if err != nil {
		return ScanRef{}, fmt.Errorf("create scan: %w", err)
	}
	var created struct {
		Scan struct {
			ID int `json:"id"`
		} `json:"scan"`
	}
	if err := decodeJSON(resp, &created); err != nil {
		return ScanRef{}, fmt.Errorf("create scan: %w", err)
	}
	scanID := fmt.Sprintf("%d", created.Scan.ID)

	lresp, err := c.do(ctx, http.MethodPost, "/scans/"+scanID+"/launch", nil)
	if err != nil {
		return ScanRef{}, fmt.Errorf("launch scan: %w", err)
	}
	_ = lresp.Body.Close()
	if lresp.StatusCode != http.StatusOK {
		return ScanRef{}, fmt.Errorf("launch scan: status %d", lresp.StatusCode)
	}
	return ScanRef{ScanID: scanID}, nil
}

// Poll returns the normalized state of the scan.
func (c *NessusProClient) Poll(ctx context.Context, ref ScanRef) (ScanState, error) {
	resp, err := c.do(ctx, http.MethodGet, "/scans/"+ref.ScanID, nil)
	if err != nil {
		return "", fmt.Errorf("poll scan: %w", err)
	}
	var st struct {
		Info struct {
			Status string `json:"status"`
		} `json:"info"`
	}
	if err := decodeJSON(resp, &st); err != nil {
		return "", fmt.Errorf("poll scan: %w", err)
	}
	switch st.Info.Status {
	case "completed":
		return ScanCompleted, nil
	case "running", "pending", "processing":
		return ScanRunning, nil
	case "canceled", "aborted", "error":
		return ScanFailed, nil
	default:
		return ScanRunning, nil
	}
}

// Export requests a .nessus export, waits for it to be ready, and downloads it.
func (c *NessusProClient) Export(ctx context.Context, ref ScanRef) (io.ReadCloser, error) {
	resp, err := c.do(ctx, http.MethodPost, "/scans/"+ref.ScanID+"/export", map[string]any{"format": "nessus"})
	if err != nil {
		return nil, fmt.Errorf("request export: %w", err)
	}
	var ex struct {
		File int `json:"file"`
	}
	if err := decodeJSON(resp, &ex); err != nil {
		return nil, fmt.Errorf("request export: %w", err)
	}
	fileID := fmt.Sprintf("%d", ex.File)

	// Poll export readiness (bounded).
	for i := 0; i < 60; i++ {
		sresp, serr := c.do(ctx, http.MethodGet, "/scans/"+ref.ScanID+"/export/"+fileID+"/status", nil)
		if serr != nil {
			return nil, fmt.Errorf("export status: %w", serr)
		}
		var s struct {
			Status string `json:"status"`
		}
		if err := decodeJSON(sresp, &s); err != nil {
			return nil, fmt.Errorf("export status: %w", err)
		}
		if s.Status == "ready" {
			break
		}
		if err := sleep(ctx, time.Second); err != nil {
			return nil, err
		}
	}

	dl, err := c.do(ctx, http.MethodGet, "/scans/"+ref.ScanID+"/export/"+fileID+"/download", nil)
	if err != nil {
		return nil, fmt.Errorf("download export: %w", err)
	}
	if dl.StatusCode != http.StatusOK {
		_ = dl.Body.Close()
		return nil, fmt.Errorf("download export: status %d", dl.StatusCode)
	}
	return dl.Body, nil
}

func decodeJSON(resp *http.Response, v any) error {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var _ Client = (*NessusProClient)(nil)
