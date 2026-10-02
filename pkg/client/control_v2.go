package client

// Protocol v2 control plane (api RFC-029,
// docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md): heartbeat,
// commands, suppressions, fingerprint queries. The public methods of Client
// pick v2 per feature (controlV2) and fall back to protocol v1 against a
// platform that does not list the feature on hello, so a sensor gets v2 by
// upgrading the SDK, with no code change. Identity is the key alone: v2
// requests carry no X-Agent-ID.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// controlError is a non-2xx answer of a v2 control-plane route. It unwraps to
// both a *V2Error (the problem) and an *HTTPError, so callers that classify
// errors with IsHTTPError, IsAuthenticationError, IsRateLimitError or
// core.AuthFailureStatus see the same thing they saw on protocol v1.
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

// heartbeatV2 sends POST /heartbeat with the v1 heartbeat body. The answer's
// hint members have their v1 names, so core.ParseHeartbeatHints reads it.
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
	if ok, _ := c.controlV2(ctx, protov2.FeatureManifest); !ok {
		return nil, core.ErrManifestUnsupported
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

// GetManifestState re-reads the platform's view of the registered manifest
// (GET /manifest, api RFC-033 §6.12): its digest, the policy as it stands
// now and the heartbeat form. core.ErrManifestNotRegistered when the
// platform has none, core.ErrManifestUnsupported when it does not serve
// manifests. It implements core.ManifestStateReader.
func (c *Client) GetManifestState(ctx context.Context) (*core.ManifestAck, error) {
	if ok, _ := c.controlV2(ctx, protov2.FeatureManifest); !ok {
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
// doorbell) returns for a disabled sensor on v2: v2 answers a disabled
// sensor's heartbeat with 200 and the pause action, v1 answered 401. A
// caller that ignores hints, such as a one-shot run's connection test, must
// still learn that the key is not accepted.
func errPausedHeartbeat() error {
	return &controlError{
		v2:   &V2Error{Status: http.StatusUnauthorized, Body: "the platform disabled this sensor (heartbeat answered pause)"},
		http: &HTTPError{StatusCode: http.StatusUnauthorized, Body: "the platform disabled this sensor (heartbeat answered pause)"},
	}
}

// =============================================================================
// Commands
// =============================================================================

func (c *Client) pollCommandsV2(ctx context.Context, limit int) ([]Command, error) {
	var list protov2.CommandList
	path := protov2.PathPrefix + protov2.CommandsPath + "?limit=" + strconv.Itoa(limit)
	if _, err := c.v2JSON(ctx, http.MethodGet, path, nil, &list, nil, c.maxRetries); err != nil {
		return nil, err
	}
	out := make([]Command, 0, len(list.Commands))
	for _, v := range list.Commands {
		cmd := Command{
			ID: v.ID, Type: v.Type, Priority: v.Priority, Status: v.Status, Payload: v.Payload,
			ErrorMessage: v.ErrorMessage, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt,
			AcknowledgedAt: v.AcknowledgedAt, StartedAt: v.StartedAt, CompletedAt: v.CompletedAt, Result: v.Result,
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
func (c *Client) transitionV2(ctx context.Context, cmdID, action string, body any, retries int) error {
	_, err := c.v2JSON(ctx, http.MethodPost, protov2.CommandActionPath(url.PathEscape(cmdID), action), body, nil, nil, retries)
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

// =============================================================================
// Protocol v1 deprecation notice
// =============================================================================

var deprecationOnce sync.Once

// noteV1Deprecation prints, once per process, that the platform answered a
// protocol v1 request with a Deprecation header (api RFC-029 §5.2). The SDK
// only uses v1 when the platform does not offer the feature on v2, or when
// SENSOR_PROTOCOL=v1 forces it.
func (c *Client) noteV1Deprecation(hdr http.Header) {
	if hdr == nil || hdr.Get("Deprecation") == "" {
		return
	}
	deprecationOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "[openctem] WARNING: the platform deprecated sensor protocol v1 (Sunset: %s); "+
			"this sensor still uses it (SENSOR_PROTOCOL=%s). Use protocol auto or v2.\n", hdr.Get("Sunset"), c.protocol)
	})
}
