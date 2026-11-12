package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/openctemio/sdk-go/pkg/lookupjob"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

var _ lookupjob.Platform = (*Client)(nil)

// NextLookup asks the platform for the next lookup job (a platform-owned
// sensor answering a passive question for an organization). With no job
// (204) it returns nil and the platform's Retry-After (0 when absent).
func (c *Client) NextLookup(ctx context.Context) (*lookupjob.Job, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+protov2.PathPrefix+lookupjob.NextPath, nil)
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
	b, err := io.ReadAll(io.LimitReader(resp.Body, lookupjob.MaxJobBody+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read lookup job: %w", err)
	}
	if len(b) > lookupjob.MaxJobBody {
		return nil, 0, errors.New("lookup job over the size limit")
	}
	var j lookupjob.Job
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, 0, fmt.Errorf("decode lookup job: %w", err)
	}
	return &j, 0, nil
}

// LookupDone reports a lookup job's result.
func (c *Client) LookupDone(ctx context.Context, id string, r lookupjob.Result) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b) > lookupjob.MaxResultBody {
		return errors.New("lookup result over the size limit")
	}
	u := c.baseURL + protov2.PathPrefix + lookupjob.JobPath + url.PathEscape(id) + "/done"
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
