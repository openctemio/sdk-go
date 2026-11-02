package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/openctemio/sdk-go/pkg/feedrelay"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

var _ feedrelay.Platform = (*Client)(nil)

// NextFeedRelay asks the platform for the next feed relay round (api
// RFC-142). With no round (204) it returns nil and the platform's
// Retry-After (0 when absent).
func (c *Client) NextFeedRelay(ctx context.Context) (*feedrelay.Round, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+protov2.PathPrefix+feedrelay.NextPath, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.doContent(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		return nil, parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()), nil
	}
	if err := feedRelayStatus(resp); err != nil {
		return nil, 0, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, feedrelay.MaxRoundBody+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read feed relay round: %w", err)
	}
	if len(b) > feedrelay.MaxRoundBody {
		return nil, 0, errors.New("feed relay round over the size limit")
	}
	var r feedrelay.Round
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, 0, fmt.Errorf("decode feed relay round: %w", err)
	}
	return &r, 0, nil
}

// UploadFeedRelayFile streams one file of a round with its Content-Length
// and Content-Digest (RFC 9530, sha-256).
func (c *Client) UploadFeedRelayFile(ctx context.Context, roundID, name string, body io.Reader, size int64, sha256Hex string) error {
	sum, err := hex.DecodeString(sha256Hex)
	if err != nil || len(sum) != 32 {
		return errors.New("upload: sha256 must be 64 hex characters")
	}
	u := c.baseURL + protov2.PathPrefix + feedrelay.RoundPath + url.PathEscape(roundID) + "/files/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum)+":")
	resp, err := c.doContent(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return feedRelayStatus(resp)
}

// FeedRelayDone reports a round's outcome.
func (c *Client) FeedRelayDone(ctx context.Context, roundID string, rep feedrelay.Report) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	u := c.baseURL + protov2.PathPrefix + feedrelay.RoundPath + url.PathEscape(roundID) + "/done"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doContent(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return feedRelayStatus(resp)
}

func feedRelayStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	return &HTTPError{StatusCode: resp.StatusCode, Body: string(errBody), RequestID: resp.Header.Get("X-Request-ID"),
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
}
