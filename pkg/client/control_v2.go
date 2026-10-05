package client

// Protocol v2 control plane (api RFC-029,
// docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md): heartbeat,
// commands, suppressions, fingerprint queries. Protocol v2 is the only
// sensor protocol (v1 is retired): a platform that does not serve a route
// answers ErrV2Unsupported (v2Missing), never a fall-back to an older
// protocol. Identity is the key alone.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// controlError is a non-2xx answer of a v2 control-plane route. It unwraps to
// both a *V2Error (the problem) and an *HTTPError, so callers that classify
// errors with IsHTTPError, IsAuthenticationError, IsRateLimitError or
// core.AuthFailureStatus work on every route.
type controlError struct {
	v2   *V2Error
	http *HTTPError
}

func (e *controlError) Error() string                { return e.v2.Error() }
func (e *controlError) Unwrap() []error              { return []error{e.v2, e.http} }
func (e *controlError) HTTPStatusCode() int          { return e.v2.Status }
func (e *controlError) problem() protov2.ProblemType { return e.v2.ProblemName() }

func asControlError(err error) error {
	var ve *V2Error
	if !errors.As(err, &ve) {
		return err
	}
	body := ve.Body
	if ve.Problem != nil {
		if raw, mErr := json.Marshal(ve.Problem); mErr == nil {
			body = string(raw)
		}
	}
	return &controlError{v2: ve, http: &HTTPError{StatusCode: ve.Status, Body: body, RequestID: ve.RequestID, RetryAfter: ve.RetryAfter}}
}

// v2JSON sends one control-plane request with a JSON body (nil: none),
// decodes a 2xx answer into out (nil: ignore it) and retries what api
// RFC-029 §4.1 says is retryable (429, 500, 502, 503, 504, network errors),
// honoring Retry-After, up to retries times. Every v2 control request is
// safe to retry: reads, last-write-wins heartbeats and idempotent
// transitions (§4.10). extra adds request headers.
func (c *Client) v2JSON(ctx context.Context, method, path string, in, out any, extra http.Header, retries int) (http.Header, error) {
	var body []byte
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		body = raw
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
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
		}
		data, hdr, err := c.v2DoHeaders(ctx, method, path, body, extra)
		if err == nil {
			if out != nil && len(bytes.TrimSpace(data)) > 0 {
				if err := json.Unmarshal(data, out); err != nil {
					return hdr, fmt.Errorf("decode %s %s: %w", method, path, err)
				}
			}
			return hdr, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var ve *V2Error
		if errors.As(err, &ve) && !ve.Transient() {
			return hdr, asControlError(err)
		}
	}
	return nil, asControlError(lastErr)
}

// v2DoHeaders is v2Do for a JSON body with extra request headers.
func (c *Client) v2DoHeaders(ctx context.Context, method, path string, body []byte, extra http.Header) ([]byte, http.Header, error) {
	if len(extra) == 0 {
		return c.v2Do(ctx, method, path, body, "", "")
	}
	return c.v2DoWith(ctx, method, path, body, "", "", extra)
}

// isRouteMissing reports a 404/405 without a problem document: the platform
// does not serve the v2 route (it listed the feature but was downgraded, or a
// proxy strips /api/v2).
func isRouteMissing(err error) bool {
	var ve *V2Error
	return errors.As(err, &ve) && ve.routeMissing()
}

// =============================================================================
// Heartbeat
// =============================================================================

// heartbeatV2 sends POST /heartbeat. core.ParseHeartbeatHints reads the
// answer's hint members.
func (c *Client) heartbeatV2(ctx context.Context, req *HeartbeatRequest) ([]byte, *protov2.HeartbeatResponse, error) {
	var raw json.RawMessage
	if _, err := c.v2JSON(ctx, http.MethodPost, protov2.PathPrefix+protov2.HeartbeatPath, req, &raw, nil, min(c.maxRetries, controlRetries)); err != nil {
		return nil, nil, err
	}
	var resp protov2.HeartbeatResponse
	_ = json.Unmarshal(raw, &resp)
	return raw, &resp, nil
}

// PutManifest registers the sensor manifest (api RFC-033) when the platform
// lists "manifest" on hello; core.ErrManifestUnsupported otherwise. It
// implements core.ManifestPusher.
func (c *Client) PutManifest(ctx context.Context, m *core.Manifest) (*core.ManifestAck, error) {
	if !c.PlatformSupports(ctx, protov2.FeatureManifest) {
		return nil, core.ErrManifestUnsupported
	}
	// The local policy report goes only to a platform that announces it.
	if m != nil && m.LocalPolicy != nil && !c.PlatformSupports(ctx, protov2.FeatureLocalPolicy) {
		cp := *m
		cp.LocalPolicy = nil
		m = &cp
	}
	var resp protov2.ManifestResponse
	if _, err := c.v2JSON(ctx, http.MethodPut, protov2.PathPrefix+protov2.ManifestPath, m, &resp, nil, c.maxRetries); err != nil {
		if isRouteMissing(err) {
			c.renegotiate() // listed on hello but not served
			return nil, core.ErrManifestUnsupported
		}
		return nil, err
	}
	ack := &core.ManifestAck{
		Digest:               resp.ManifestDigest,
		Changed:              resp.Changed,
		AcceptedTools:        resp.Accepted.Tools,
		AcceptedCapabilities: resp.Accepted.Capabilities,
		Policy:               policyOf(resp.Policy),
		OmitInventory:        resp.Heartbeat.OmitInventory,
	}
	for _, i := range resp.Ignored {
		ack.Ignored = append(ack.Ignored, core.ManifestIgnored{Path: i.Path, Value: i.Value, Reason: i.Reason})
	}
	return ack, nil
}

var _ core.ManifestPusher = (*Client)(nil)

// PutConfigReport sends the sensor's config report (api RFC-033, config
// report) when the platform lists "config_report" on hello;
// core.ErrConfigReportUnsupported otherwise. The report must be finalized
// (core.ConfigReport.Finalize): it carries no setting values and is at most
// protov2.MaxConfigReportBytes. It implements core.ConfigReportPusher.
func (c *Client) PutConfigReport(ctx context.Context, r *core.ConfigReport) (*core.ConfigReportAck, error) {
	if r == nil {
		return nil, errors.New("nil config report")
	}
	if !c.PlatformSupports(ctx, protov2.FeatureConfigReport) {
		return nil, core.ErrConfigReportUnsupported
	}
	var resp protov2.ConfigReportResponse
	if _, err := c.v2JSON(ctx, http.MethodPut, protov2.PathPrefix+protov2.ConfigReportPath, r, &resp, nil, min(c.maxRetries, controlRetries)); err != nil {
		if isRouteMissing(err) {
			c.renegotiate() // listed on hello but not served
			return nil, core.ErrConfigReportUnsupported
		}
		return nil, err
	}
	ack := &core.ConfigReportAck{Digest: resp.ConfigReportDigest, Changed: resp.Changed}
	for _, i := range resp.Ignored {
		ack.Ignored = append(ack.Ignored, core.ManifestIgnored{Path: i.Path, Value: i.Value, Reason: i.Reason})
	}
	return ack, nil
}

var _ core.ConfigReportPusher = (*Client)(nil)

// GetManifestState re-reads the platform's view of the registered manifest
// (GET /manifest, api RFC-033 §6.12): its digest, the policy as it stands
// now and the heartbeat form. core.ErrManifestNotRegistered when the
// platform has none, core.ErrManifestUnsupported when it does not serve
// manifests. It implements core.ManifestStateReader.
func (c *Client) GetManifestState(ctx context.Context) (*core.ManifestAck, error) {
	if !c.PlatformSupports(ctx, protov2.FeatureManifest) {
		return nil, core.ErrManifestUnsupported
	}
	var resp protov2.ManifestStateResponse
	if _, err := c.v2JSON(ctx, http.MethodGet, protov2.PathPrefix+protov2.ManifestPath, nil, &resp, nil, c.maxRetries); err != nil {
		var ve *V2Error
		if errors.As(err, &ve) && ve.Problem != nil && ve.ProblemName() == protov2.ProblemManifestNotFound {
			return nil, core.ErrManifestNotRegistered
		}
		if isRouteMissing(err) {
			// A platform from before api RFC-033 Phase 2 serves PUT only.
			return nil, core.ErrManifestUnsupported
		}
		return nil, err
	}
	return &core.ManifestAck{Digest: resp.ManifestDigest, Policy: policyOf(resp.Policy),
		OmitInventory: resp.Heartbeat.OmitInventory}, nil
}

var _ core.ManifestStateReader = (*Client)(nil)

func policyOf(p *protov2.ManifestPolicy) *core.ManifestPolicy {
	if p == nil {
		return nil
	}
	return &core.ManifestPolicy{AllowedTools: p.AllowedTools, AllowedCapabilities: p.AllowedCapabilities, MaxJobs: p.MaxJobs}
}

// errPausedHeartbeat is what SendHeartbeat (which does not act on the
// doorbell) returns for a disabled sensor: v2 answers a disabled sensor's
// heartbeat with 200 and the pause action. A caller that ignores hints, such
// as a one-shot run's connection test, must still learn that the key is not
// accepted.
func errPausedHeartbeat() error {
	return &controlError{
		v2:   &V2Error{Status: http.StatusUnauthorized, Body: "the platform disabled this sensor (heartbeat answered pause)"},
		http: &HTTPError{StatusCode: http.StatusUnauthorized, Body: "the platform disabled this sensor (heartbeat answered pause)"},
	}
}

// =============================================================================
// Commands
// =============================================================================

// claimOnPoll reports whether polls ask the platform to claim (claim-N):
// the platform offers the capacity feature and the client did not opt out.
func (c *Client) claimOnPoll(ctx context.Context) bool {
	if c.noClaimOnPoll {
		return false
	}
	return c.PlatformSupports(ctx, protov2.FeatureCapacity)
}

func (c *Client) pollCommandsV2(ctx context.Context, limit int) ([]Command, error) {
	var list protov2.CommandList
	path := protov2.PathPrefix + protov2.CommandsPath + "?limit=" + strconv.Itoa(limit)
	// Claim-N: against a platform that offers it, the poll claims what it
	// returns, so the platform counts the slots and no second sensor polls
	// the same command.
	var extra http.Header
	if c.claimOnPoll(ctx) {
		extra = http.Header{protov2.HeaderSensorFeatures: []string{protov2.FeatureCapacity}}
	}
	if _, err := c.v2JSON(ctx, http.MethodGet, path, nil, &list, extra, c.maxRetries); err != nil {
		return nil, err
	}
	out := make([]Command, 0, len(list.Commands))
	for _, v := range list.Commands {
		cmd := Command{
			ID: v.ID, Type: v.Type, Priority: v.Priority, Status: v.Status, Payload: v.Payload,
			ErrorMessage: v.ErrorMessage, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt,
			AcknowledgedAt: v.AcknowledgedAt, StartedAt: v.StartedAt, CompletedAt: v.CompletedAt, Result: v.Result,
			LeaseEpoch: v.LeaseEpoch, LeaseExpiresAt: v.LeaseExpiresAt,
		}
		if v.SensorID != nil {
			cmd.SourceID = *v.SensorID
		}
		out = append(out, cmd)
	}
	return out, nil
}

// transitionV2 posts one command transition. A replay of a transition the
// platform already applied answers 200 (api RFC-029 D5), so retries are safe.
// out (nil: ignore) receives the command as the answer returns it and
// extra adds request headers.
func (c *Client) transitionV2(ctx context.Context, cmdID, action string, body, out any, extra http.Header, retries int) error {
	_, err := c.v2JSON(ctx, http.MethodPost, protov2.CommandActionPath(url.PathEscape(cmdID), action), body, out, extra, retries)
	return err
}

// IsCommandGone reports whether err says the command can no longer be worked
// on by this sensor: another sensor claimed it, it was canceled or expired,
// it already finished, or it is not (or no longer) this sensor's. The poller
// drops such a command instead of retrying it.
func IsCommandGone(err error) bool {
	var ce *controlError
	if !errors.As(err, &ce) {
		return false
	}
	switch ce.problem() {
	case protov2.ProblemInvalidTransition, protov2.ProblemCommandClaimed, protov2.ProblemCommandNotFound:
		return true
	}
	return false
}

// =============================================================================
// Suppressions
// =============================================================================

// suppressionCache keeps the last suppression list and its ETag, revalidated
// with If-None-Match.
type suppressionCache struct {
	mu    sync.Mutex
	etag  string
	rules []SuppressionRule
}

func (c *Client) suppressionsV2(ctx context.Context) ([]SuppressionRule, error) {
	c.supp.mu.Lock()
	etag, cached := c.supp.etag, c.supp.rules
	c.supp.mu.Unlock()
	var extra http.Header
	if etag != "" {
		extra = http.Header{"If-None-Match": []string{etag}}
	}
	var list protov2.SuppressionList
	hdr, err := c.v2JSON(ctx, http.MethodGet, protov2.PathPrefix+protov2.SuppressionsPath, nil, &list, extra, c.maxRetries)
	if err != nil {
		var ve *V2Error
		if errors.As(err, &ve) && ve.Status == http.StatusNotModified {
			return append([]SuppressionRule(nil), cached...), nil
		}
		return nil, err
	}
	rules := make([]SuppressionRule, 0, len(list.Rules))
	for _, r := range list.Rules {
		rules = append(rules, SuppressionRule{RuleID: r.RuleID, ToolName: r.ToolName, PathPattern: r.PathPattern, AssetID: r.AssetID, ExpiresAt: r.ExpiresAt})
	}
	c.supp.mu.Lock()
	c.supp.etag, c.supp.rules = hdr.Get("ETag"), rules
	c.supp.mu.Unlock()
	return append([]SuppressionRule(nil), rules...), nil
}

// =============================================================================
// Fingerprint queries
// =============================================================================

// fingerprintBatches splits fps into requests of at most the platform's
// limit (each fingerprint is answered independently).
func fingerprintBatches(fps []string, h *protov2.Hello) [][]string {
	limit := protov2.DefaultMaxFingerprintsPerRequest
	if h != nil && h.Limits.MaxFingerprintsPerRequest > 0 {
		limit = h.Limits.MaxFingerprintsPerRequest
	}
	var out [][]string
	for len(fps) > limit {
		out = append(out, fps[:limit])
		fps = fps[limit:]
	}
	return append(out, fps)
}

func (c *Client) checkFingerprintsV2(ctx context.Context, fps []string, h *protov2.Hello) (existing, missing []string, err error) {
	existing, missing = []string{}, []string{}
	for _, batch := range fingerprintBatches(fps, h) {
		var resp protov2.FingerprintsCheckResponse
		if _, err := c.v2JSON(ctx, http.MethodPost, protov2.PathPrefix+protov2.FingerprintsCheckPath,
			protov2.FingerprintsCheckRequest{Fingerprints: batch}, &resp, nil, c.maxRetries); err != nil {
			return nil, nil, err
		}
		existing = append(existing, resp.Existing...)
		missing = append(missing, resp.Missing...)
	}
	return existing, missing, nil
}

func (c *Client) baselineDiffV2(ctx context.Context, repository, baseBranch string, fps []string, h *protov2.Hello) ([]string, error) {
	out := []string{}
	for _, batch := range fingerprintBatches(fps, h) {
		var resp protov2.BaselineDiffResponse
		if _, err := c.v2JSON(ctx, http.MethodPost, protov2.PathPrefix+protov2.BaselineDiffPath,
			protov2.BaselineDiffRequest{Repository: repository, BaseBranch: baseBranch, Fingerprints: batch}, &resp, nil, c.maxRetries); err != nil {
			return nil, err
		}
		out = append(out, resp.NewFingerprints...)
	}
	return out, nil
}
