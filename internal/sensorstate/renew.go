package sensorstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

// RenewClient renews an API-key sensor's key (POST /api/v2/sensor/keys,
// api RFC-029 §4.7). It satisfies KeyRenewer.
type RenewClient struct {
	baseURL string
	http    *http.Client

	mu     sync.RWMutex
	apiKey string
}

var _ KeyRenewer = (*RenewClient)(nil)

// NewRenewClient creates a RenewClient for the platform at baseURL that
// presents apiKey. Its HTTP client is SSRF-guarded, follows no redirects
// (following one would forward the key) and sends the SDK User-Agent.
func NewRenewClient(baseURL, apiKey string) *RenewClient {
	c := httpsec.NewAPIClient(15 * time.Second)
	c.Transport = useragent.Transport(c.Transport)
	return &RenewClient{baseURL: baseURL, apiKey: apiKey, http: c}
}

// RenewKeyResponse is the result of a renewal. ExpiresAt is nil when the
// server has no key TTL configured (the key never expires).
type RenewKeyResponse struct {
	APIKey    string     `json:"api_key"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ErrRenewUnsupported: the platform does not serve sensor protocol v2 key
// renewal (an OpenCTEM API from before 2026-10); upgrade the platform.
var ErrRenewUnsupported = errors.New("the platform does not serve sensor protocol v2 key renewal " +
	"(upgrade the OpenCTEM API: protocol v1 is retired)")

// RenewError is a refused key renewal. It satisfies the HTTPStatusCode
// interface pkg/core uses to tell a rejected key from other failures.
type RenewError struct{ StatusCode int }

func (e *RenewError) Error() string { return fmt.Sprintf("unexpected status: %d", e.StatusCode) }

// HTTPStatusCode returns the response status.
func (e *RenewError) HTTPStatusCode() int { return e.StatusCode }

// RenewKey rotates the key by presenting the current one. A platform that
// does not serve the route (404/405 without a problem document) answers
// ErrRenewUnsupported. It does NOT swap the key in: the caller decides when
// to call SetAPIKey (and persist), so a failed persist never leaves the
// running client on a key the sensor cannot recover after a restart. It
// never retries: without a key TTL the platform replaces the presented key,
// so a repeated renewal after a lost answer would be refused.
func (c *RenewClient) RenewKey(ctx context.Context) (*RenewKeyResponse, error) {
	url, err := apiURL(c.baseURL, protov2.PathPrefix+protov2.KeysPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.currentAPIKey())

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) &&
		!protov2.IsProblemContentType(resp.Header.Get("Content-Type")):
		return nil, ErrRenewUnsupported
	case resp.StatusCode != http.StatusCreated:
		return nil, &RenewError{StatusCode: resp.StatusCode}
	}

	var out RenewKeyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if out.APIKey == "" {
		return nil, fmt.Errorf("renew returned an empty key")
	}
	return &out, nil
}

// SetAPIKey swaps the key presented by later renewals. Safe for concurrent
// use.
func (c *RenewClient) SetAPIKey(key string) {
	c.mu.Lock()
	c.apiKey = key
	c.mu.Unlock()
}

func (c *RenewClient) currentAPIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey
}

// apiURL validates baseURL and returns baseURL + path (httpsec.CheckAPIBaseURL:
// non-http(s) schemes, missing hosts and embedded credentials are rejected;
// plain http to a non-loopback host is allowed but warned about once).
func apiURL(baseURL, path string) (string, error) {
	warning, err := httpsec.CheckAPIBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	// Printed once per process per base URL, shared with pkg/client.
	if warning != "" && httpsec.FirstWarning(baseURL) {
		fmt.Fprintf(os.Stderr, "[sensor] WARNING: %s\n", warning)
	}
	return strings.TrimRight(baseURL, "/") + path, nil
}
