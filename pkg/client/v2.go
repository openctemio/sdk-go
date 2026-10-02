package client

// Protocol v2 results client (RFC-026, api docs/rfcs/RFC-026-sensor-results-ingest.md
// §3). A report is a resource the sensor names: PUT .../results/{report_id}
// with Content-Type application/vnd.openctem.ctis.v1+json, a required
// Content-Digest (RFC 9530, over the bytes as sent) and optional zstd. Large
// reports go as self-describing segments plus a commit. A replay of the same
// bytes is a no-op (200), so every retry reuses the report id.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/openctemio/sdk-go/pkg/chunk"
	"github.com/openctemio/sdk-go/pkg/ctis"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// Results protocol selection (Config.Protocol, SENSOR_PROTOCOL).
const (
	// ProtocolAuto uses v2 when the platform offers it and v1 otherwise
	// (the default).
	ProtocolAuto = "auto"
	// ProtocolV1 always uses the frozen v1 ingest routes.
	ProtocolV1 = "v1"
	// ProtocolV2 always uses v2 and fails against a platform without it.
	ProtocolV2 = "v2"
)

// ParseProtocol validates a protocol setting ("" is auto).
func ParseProtocol(s string) (string, error) {
	switch p := strings.ToLower(strings.TrimSpace(s)); p {
	case "", ProtocolAuto:
		return ProtocolAuto, nil
	case ProtocolV1, ProtocolV2:
		return p, nil
	default:
		return "", fmt.Errorf("unknown results protocol %q (want auto, v1 or v2)", s)
	}
}

// How long a protocol decision is trusted before hello is asked again. A v1
// decision is re-checked sooner, so an upgraded platform is noticed.
const (
	v2DecisionTTL = time.Hour
	v1DecisionTTL = 10 * time.Minute
)

// ErrV2Unsupported: protocol v2 was required but the platform does not offer
// it.
var ErrV2Unsupported = errors.New("the platform does not offer protocol v2 results (set the protocol to auto or v1)")

// ErrV2NoTool: v2 requires the report's tool (RFC-026 §3.3 step 8).
var ErrV2NoTool = errors.New("protocol v2 requires report.tool.name")

// errTooManySegments marks the 413 the SDK makes up for a report that needs
// more segments than the platform accepts: splitting further cannot help.
var errTooManySegments = errors.New("too many segments")

// V2Error is a non-2xx answer of a v2 resource.
type V2Error struct {
	Status     int
	Problem    *protov2.Problem
	RetryAfter time.Duration
	// Body is the raw answer when it was not a problem document (truncated).
	Body      string
	RequestID string
}

func (e *V2Error) Error() string {
	if e.Problem != nil {
		return fmt.Sprintf("v2 http %d %s: %s", e.Status, e.Problem.Name(), e.Problem.Detail)
	}
	return fmt.Sprintf("v2 http %d: %s", e.Status, truncateForError(e.Body, maxErrorMessageBytes))
}

// HTTPStatusCode lets core.AuthFailureStatus classify the error.
func (e *V2Error) HTTPStatusCode() int { return e.Status }

// ProblemName is the problem type's short name, or "".
func (e *V2Error) ProblemName() protov2.ProblemType { return e.Problem.Name() }

// Transient reports whether retrying later can succeed (RFC-026 §3.8: 429,
// 500, 502, 503, 504).
func (e *V2Error) Transient() bool {
	switch e.Status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// routeMissing: a 404/405 that is not a v2 problem document, i.e. the
// platform does not serve the v2 route at all (older platform, or v2 off).
func (e *V2Error) routeMissing() bool {
	return (e.Status == http.StatusNotFound || e.Status == http.StatusMethodNotAllowed) && e.Problem == nil
}

// V2Progress is the resumable state of one v2 report delivery. The outbox
// persists it, so a restart neither resends acknowledged segments nor loses
// the report id.
type V2Progress struct {
	// ReportID in use (it changes only when the report had to be restarted:
	// expired, or re-split after a 413).
	ReportID string `json:"report_id"`
	// Unbound: the command is gone; the report is sent unsolicited.
	Unbound bool `json:"unbound,omitempty"`
	// SegFindings and SegBytes cap the segments after a 413 (0: the
	// server's limits). Each 413 halves the segment that was refused.
	SegFindings int `json:"seg_findings,omitempty"`
	SegBytes    int `json:"seg_bytes,omitempty"`
	// Split is true once the report was split after a 413: it is then sent
	// as segments plus a commit even when one segment remains.
	Split bool `json:"split,omitempty"`
	// Segments is the planned segment count (0: not planned yet).
	Segments int `json:"segments,omitempty"`
	// Acked maps a segment number to the Content-Digest the server
	// acknowledged for it.
	Acked map[int]string `json:"acked,omitempty"`
	// Restarts counts report-id restarts (bounded).
	Restarts int `json:"restarts,omitempty"`

	// lastFindings/lastBytes describe the request being sent when an
	// error happened (the segment a 413 refused).
	lastFindings, lastBytes int
}

// V2PushOptions configures PushResultsV2.
type V2PushOptions struct {
	// ReportID is the stable report id (lower-case UUID). Empty: a new
	// UUIDv7. Retries MUST reuse it.
	ReportID string
	// CommandID binds the report to a command this sensor claimed ("" for
	// unsolicited results).
	CommandID string
	// Progress resumes an earlier attempt (nil: start).
	Progress *V2Progress
	// OnProgress persists progress after every acknowledged segment and
	// every restart. An error stops the push.
	OnProgress func(V2Progress) error
	// Logf receives restarts and fall-backs. Nil: silent.
	Logf func(format string, args ...any)
	// MaxFindingsPerSegment lowers the server's per-segment finding limit
	// (0: the server's). For constrained links and conformance tests.
	MaxFindingsPerSegment int
}

// defaultCTISVersion is set on a report without a CTIS version: v2 requires
// the body to state a major matching the media type.
const defaultCTISVersion = "1.0"

// maxV2Restarts bounds report-id restarts in one push.
const maxV2Restarts = 4

// v2State is the client's protocol decision: the hello the platform answered
// (nil when it offers no protocol v2) and when it was asked.
type v2State struct {
	mu        sync.Mutex
	decidedAt time.Time
	hello     *protov2.Hello
	// sticky v1: the platform refused this sensor on v2 (403 scope-denied).
	refused bool
}

var (
	v2EncOnce sync.Once
	v2Enc     *zstd.Encoder
)

func v2Encoder() *zstd.Encoder {
	v2EncOnce.Do(func() {
		// Deterministic (single-threaded) so a retry sends the same bytes
		// and the server sees an identical replay; a 4 MiB window stays
		// under the server's 8 MiB decoder cap.
		v2Enc, _ = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1),
			zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithWindowSize(4<<20))
	})
	return v2Enc
}

// Hello fetches GET /api/v2/sensor/hello.
func (c *Client) Hello(ctx context.Context) (*protov2.Hello, error) {
	data, _, err := c.v2Do(ctx, http.MethodGet, protov2.PathPrefix+protov2.HelloPath, nil, "", "")
	if err != nil {
		return nil, err
	}
	var h protov2.Hello
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("decode hello: %w", err)
	}
	return &h, nil
}

// ResultsProtocol returns the protocol the client uses for results now ("v1"
// or "v2"), asking the platform when the decision is stale (auto).
func (c *Client) ResultsProtocol(ctx context.Context) (string, error) {
	useV2, _, err := c.resultsProtocol(ctx)
	if err != nil {
		return "", err
	}
	if useV2 {
		return ProtocolV2, nil
	}
	return ProtocolV1, nil
}

// negotiate returns the platform's hello, or nil when it offers no protocol
// v2 (an older platform answers 404), asking again once the cached answer is
// stale. An error means the platform could not be asked (network, 401, 5xx):
// nothing is decided, the next call asks again.
func (c *Client) negotiate(ctx context.Context) (*protov2.Hello, error) {
	if c.protocol == ProtocolV1 {
		return nil, nil
	}
	s := &c.v2
	s.mu.Lock()
	if c.protocol == ProtocolAuto && s.refused {
		s.mu.Unlock()
		return nil, nil
	}
	if !s.decidedAt.IsZero() {
		ttl := v1DecisionTTL
		if s.hello != nil {
			ttl = v2DecisionTTL
		}
		if time.Since(s.decidedAt) < ttl {
			h := s.hello
			s.mu.Unlock()
			return h, nil
		}
	}
	s.mu.Unlock()

	h, err := c.Hello(ctx)
	if err != nil {
		var ve *V2Error
		if !errors.As(err, &ve) || ve.Status == http.StatusUnauthorized || ve.Transient() {
			return nil, err // network, auth or server trouble: decide later
		}
		h = nil // any other answer (404 on an older platform, 403, ...) means no v2
	} else if h.Protocol < protov2.ProtocolVersion {
		h = nil
	}
	s.mu.Lock()
	changed := s.decidedAt.IsZero() || featureSet(s.hello) != featureSet(h)
	s.hello, s.decidedAt = h, time.Now()
	s.mu.Unlock()
	if changed && c.verbose {
		if h == nil {
			fmt.Println("[openctem] sensor protocol: v1 (the platform offers no protocol v2)")
		} else {
			fmt.Printf("[openctem] sensor protocol: v2 for %s, v1 for the rest\n", featureSet(h))
		}
	}
	return h, nil
}

// featureSet is a hello's feature list as one comparable string.
func featureSet(h *protov2.Hello) string {
	if h == nil {
		return ""
	}
	return strings.Join(h.Features, ",")
}

// resultsProtocol decides v1 or v2 for results and returns the hello for v2.
func (c *Client) resultsProtocol(ctx context.Context) (bool, *protov2.Hello, error) {
	h, err := c.negotiate(ctx)
	if err != nil {
		return false, nil, err
	}
	useV2 := h.SupportsResults()
	if c.protocol == ProtocolV2 && !useV2 {
		return false, nil, ErrV2Unsupported
	}
	if !useV2 {
		h = nil
	}
	return useV2, h, nil
}

// controlV2 decides whether one control-plane call uses protocol v2 (api
// RFC-029 §6.1): v2 when hello lists feature, v1 otherwise. A platform that
// cannot be asked right now (network, 401, 5xx) gets this call on v1, which
// every platform still serves, and is asked again on the next call. The
// protocol setting v2 requires v2 for results only (as since sdk-go 0.8.0):
// a platform that lists results but not, say, heartbeat keeps working.
func (c *Client) controlV2(ctx context.Context, feature string) (bool, *protov2.Hello) {
	h, err := c.negotiate(ctx)
	if err != nil || !h.Supports(feature) {
		return false, nil
	}
	return true, h
}

// ProtocolFeatures returns the features this client uses protocol v2 for,
// as last negotiated (nil: protocol v1 for everything, or not asked yet).
func (c *Client) ProtocolFeatures() []string {
	s := &c.v2
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hello == nil {
		return nil
	}
	return append([]string(nil), s.hello.Features...)
}

// PlatformSupports reports whether the platform lists feature on its hello
// (GET /api/v2/sensor/hello): one of the protov2.Feature* names, or a name
// a newer platform announces that this SDK has no constant for. The answer
// is the cached negotiation, asked again when stale. A platform without
// protocol v2, one that cannot be asked right now, or a client set to
// protocol v1 supports nothing. This is how a sensor lights up an optional
// behavior for a newer platform without an SDK release, and keeps the old
// behavior against an older one (docs/STABILITY.md).
func (c *Client) PlatformSupports(ctx context.Context, feature string) bool {
	h, err := c.negotiate(ctx)
	if err != nil {
		return false
	}
	return h.Supports(feature)
}

// noteProtocolAdvert records what a v1 heartbeat answer said about v2: a
// change makes the next call ask hello again.
func (c *Client) noteProtocolAdvert(advertised bool) {
	s := &c.v2
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.decidedAt.IsZero() && s.hello.SupportsResults() != advertised {
		s.decidedAt = time.Time{}
	}
}

// forceV1 makes auto mode use v1 (v2 refused for this sensor, or a results
// route missing).
func (c *Client) forceV1(sticky bool) {
	s := &c.v2
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hello, s.decidedAt = nil, time.Now()
	if sticky {
		s.refused = true
	}
}

// renegotiate drops the cached decision: a v2 route the platform listed was
// missing (the platform was downgraded), so the next call asks hello again.
func (c *Client) renegotiate() {
	s := &c.v2
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decidedAt = time.Time{}
}

// segmentLimits derives the segment bounds from hello's limits and the caps a
// 413 put in p.
func segmentLimits(l protov2.Limits, p *V2Progress) chunk.SegmentLimits {
	// Uncompressed segments of at most 3/4 of the request limit always fit
	// the request limit even when sent uncompressed.
	maxBytes := int(min(l.MaxContentBytes*3/4, l.MaxDecompressedBytes*3/4))
	lim := chunk.SegmentLimits{
		MaxFindings: max(1, l.MaxFindingsPerSegment),
		MaxAssets:   max(1, l.MaxAssetsPerSegment),
		MaxBytes:    max(1024, maxBytes),
	}
	if p.SegFindings > 0 && p.SegFindings < lim.MaxFindings {
		lim.MaxFindings = p.SegFindings
		lim.MaxAssets = max(1, min(lim.MaxAssets, p.SegFindings))
	}
	if p.SegBytes > 0 && p.SegBytes < lim.MaxBytes {
		lim.MaxBytes = max(1024, p.SegBytes)
	}
	return lim
}

// PushResultsV2 sends a report over protocol v2 and returns its status
// resource. It makes one pass: transient failures (network, 429, 5xx) are
// returned as errors for the caller to retry with the same report id and
// progress (the outbox does). It handles the protocol's own recoveries: a
// 413 re-splits into smaller segments, an expired report or a gone command
// restarts under a new report id (unbound), and a conflicting replay of a
// report the server already has is resolved by reading its status.
func (c *Client) PushResultsV2(ctx context.Context, report *ctis.Report, opts *V2PushOptions) (*protov2.Status, error) {
	if report == nil {
		return nil, errors.New("nil report")
	}
	if report.Tool == nil || strings.TrimSpace(report.Tool.Name) == "" {
		return nil, ErrV2NoTool
	}
	if opts == nil {
		opts = &V2PushOptions{}
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var p V2Progress
	if opts.Progress != nil {
		p = *opts.Progress
		p.Acked = copyAcked(opts.Progress.Acked)
	}
	if p.ReportID == "" {
		p.ReportID = opts.ReportID
	}
	if p.ReportID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}
		p.ReportID = id.String()
	}
	save := func() error {
		if opts.OnProgress != nil {
			return opts.OnProgress(p)
		}
		return nil
	}
	restart := func(why string) error {
		p.Restarts++
		if p.Restarts > maxV2Restarts {
			return fmt.Errorf("report %s: too many restarts (last: %s)", p.ReportID, why)
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		logf("report %s: %s; sending it again as report %s", p.ReportID, why, id)
		p.ReportID, p.Segments, p.Acked = id.String(), 0, nil
		return save()
	}

	_, hello, err := c.resultsProtocol(ctx)
	if err != nil {
		return nil, err
	}
	limits := protov2.DefaultLimits()
	if hello != nil {
		limits = hello.Limits.WithDefaults()
	}
	if n := opts.MaxFindingsPerSegment; n > 0 && n < limits.MaxFindingsPerSegment {
		limits.MaxFindingsPerSegment = n
	}

	for {
		commandID := opts.CommandID
		if p.Unbound {
			commandID = ""
		}
		st, err := c.pushV2Once(ctx, report, limits, commandID, &p, save)
		if err == nil {
			return st, nil
		}
		var ve *V2Error
		if !errors.As(err, &ve) {
			return nil, err
		}
		switch {
		case ve.Status == http.StatusRequestEntityTooLarge && !errors.Is(err, errTooManySegments):
			// Halve the segment that was refused and send smaller ones.
			// Nothing of a refused request is stored, so the report id is
			// kept unless acknowledged segments would no longer line up.
			// A 413 without a problem document is a reverse proxy's body
			// limit (an ingress below the platform's own limit): smaller
			// segments pass it just the same.
			if p.lastFindings <= 1 && p.lastBytes <= 1024 {
				return nil, err // one finding is already too large
			}
			p.SegFindings = max(1, p.lastFindings/2)
			p.SegBytes = max(1024, p.lastBytes/2)
			p.Split = true
			why := "a proxy's body limit"
			if ve.Problem != nil {
				why = string(ve.Problem.Name())
			}
			logf("report %s: a %d-finding, %d-byte request was too large (%s); splitting into segments of at most %d findings",
				p.ReportID, p.lastFindings, p.lastBytes, why, p.SegFindings)
			if len(p.Acked) > 0 {
				if rerr := restart("re-split after 413"); rerr != nil {
					return nil, errors.Join(err, rerr)
				}
			} else {
				p.Segments = 0
				if serr := save(); serr != nil {
					return nil, errors.Join(err, serr)
				}
			}
		case ve.ProblemName() == protov2.ProblemCommandNotFound && commandID != "":
			p.Unbound = true
			if rerr := restart("its command is no longer open on the platform"); rerr != nil {
				return nil, errors.Join(err, rerr)
			}
		case ve.ProblemName() == protov2.ProblemReportExpired,
			ve.ProblemName() == protov2.ProblemSegmentSetMismatch,
			ve.ProblemName() == protov2.ProblemSegmentHeaderMismatch,
			ve.ProblemName() == protov2.ProblemBindingMismatch:
			if rerr := restart(string(ve.ProblemName())); rerr != nil {
				return nil, errors.Join(err, rerr)
			}
		case ve.ProblemName() == protov2.ProblemReportConflict || ve.ProblemName() == protov2.ProblemReportCommitted:
			// The server already holds this report id: with other bytes
			// (re-encoded by another SDK build) or already committed (the
			// answer to an earlier commit was lost). The item is immutable,
			// so it is the same report: delivered if the server has it
			// committed.
			if st, serr := c.GetReportStatus(ctx, p.ReportID); serr == nil && st.State != protov2.StateReceiving && st.State != protov2.StateExpired {
				return st, nil
			}
			if ve.ProblemName() == protov2.ProblemReportCommitted {
				return nil, err
			}
			if rerr := restart(string(ve.ProblemName())); rerr != nil {
				return nil, errors.Join(err, rerr)
			}
		default:
			return nil, err
		}
	}
}

func copyAcked(m map[int]string) map[int]string {
	if m == nil {
		return nil
	}
	out := make(map[int]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// pushV2Once plans and sends the report under p.ReportID.
func (c *Client) pushV2Once(ctx context.Context, report *ctis.Report, limits protov2.Limits, commandID string,
	p *V2Progress, save func() error) (*protov2.Status, error) {
	r := *report
	r.Metadata.ID = p.ReportID // RFC-026: metadata.id empty or equal to the report id
	if strings.TrimSpace(r.Version) == "" || !strings.HasPrefix(strings.TrimSpace(r.Version), "1") {
		r.Version = defaultCTISVersion
	}
	// Copy the slices BindFindingAssets writes to, never the caller's.
	r.Assets = append([]ctis.Asset(nil), report.Assets...)
	r.Findings = append([]ctis.Finding(nil), report.Findings...)
	chunk.BindFindingAssets(&r)

	segs, err := chunk.SplitSegments(&r, segmentLimits(limits, p))
	if err != nil {
		return nil, err
	}
	if limits.MaxSegmentsPerReport > 0 && len(segs) > limits.MaxSegmentsPerReport {
		return nil, errors.Join(&V2Error{Status: http.StatusRequestEntityTooLarge, Body: fmt.Sprintf(
			"the report needs %d segments; the platform accepts %d", len(segs), limits.MaxSegmentsPerReport)}, errTooManySegments)
	}
	if p.Segments != 0 && p.Segments != len(segs) {
		// The plan changed (other limits after an upgrade): acknowledged
		// segments no longer line up.
		p.Acked = nil
	}
	if p.Segments != len(segs) {
		p.Segments = len(segs)
		if err := save(); err != nil {
			return nil, err
		}
	}

	if len(segs) == 1 && !p.Split {
		body, enc, digest, err := encodeV2(segs[0], limits)
		if err != nil {
			return nil, err
		}
		p.lastFindings, p.lastBytes = len(segs[0].Findings), rawSize(segs[0])
		data, _, err := c.v2Do(ctx, http.MethodPut, protov2.ReportPath(commandID, p.ReportID), body, enc, digest)
		if err != nil {
			return nil, err
		}
		return decodeStatus(data)
	}

	digests := make([]string, len(segs))
	for seq, seg := range segs {
		body, enc, digest, err := encodeV2(seg, limits)
		if err != nil {
			return nil, err
		}
		digests[seq] = digest
		if got, ok := p.Acked[seq]; ok && got == digest {
			continue
		}
		p.lastFindings, p.lastBytes = len(seg.Findings), rawSize(seg)
		if _, _, err := c.v2Do(ctx, http.MethodPut, protov2.SegmentPath(commandID, p.ReportID, seq), body, enc, digest); err != nil {
			return nil, err
		}
		if p.Acked == nil {
			p.Acked = map[int]string{}
		}
		p.Acked[seq] = digest
		if err := save(); err != nil {
			return nil, err
		}
	}
	commit, err := json.Marshal(protov2.CommitRequest{SegmentCount: len(segs), SegmentDigests: digests})
	if err != nil {
		return nil, err
	}
	data, _, err := c.v2Do(ctx, http.MethodPost, protov2.CommitPath(commandID, p.ReportID), commit, "", "")
	if err != nil {
		return nil, err
	}
	return decodeStatus(data)
}

// encodeV2 marshals a segment and compresses it with zstd when that helps and
// stays within the server's compression-ratio cap. It returns the body, the
// Content-Encoding ("" for none) and the Content-Digest of the body.
func encodeV2(seg *ctis.Report, l protov2.Limits) ([]byte, string, string, error) {
	raw, err := json.Marshal(seg)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal segment: %w", err)
	}
	body, enc := raw, ""
	if len(raw) > 1024 {
		comp := v2Encoder().EncodeAll(raw, nil)
		ratio := float64(len(raw)) / float64(max(1, len(comp)))
		if len(comp) < len(raw) && ratio < 0.8*l.MaxCompressionRatio {
			body, enc = comp, protov2.EncodingZstd
		}
	}
	return body, enc, protov2.ContentDigest(body), nil
}

// rawSize is the JSON size of a segment before compression.
func rawSize(seg *ctis.Report) int {
	b, err := json.Marshal(seg)
	if err != nil {
		return 0
	}
	return len(b)
}

func decodeStatus(data []byte) (*protov2.Status, error) {
	var st protov2.Status
	if len(bytes.TrimSpace(data)) == 0 {
		return &st, nil
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	return &st, nil
}

// GetReportStatus reads a report's status resource.
func (c *Client) GetReportStatus(ctx context.Context, reportID string) (*protov2.Status, error) {
	data, _, err := c.v2Do(ctx, http.MethodGet, protov2.StatusPath(reportID), nil, "", "")
	if err != nil {
		return nil, err
	}
	return decodeStatus(data)
}

// AbandonReport deletes an uncommitted segmented report.
func (c *Client) AbandonReport(ctx context.Context, reportID string) error {
	_, _, err := c.v2Do(ctx, http.MethodDelete, protov2.StatusPath(reportID), nil, "", "")
	return err
}

// v2Do sends one v2 request (no retries). body with a digest is CTIS content;
// body without one is JSON (commit, control plane).
func (c *Client) v2Do(ctx context.Context, method, path string, body []byte, encoding, digest string) ([]byte, http.Header, error) {
	return c.v2DoWith(ctx, method, path, body, encoding, digest, nil)
}

// v2DoWith is v2Do with extra request headers.
func (c *Client) v2DoWith(ctx context.Context, method, path string, body []byte, encoding, digest string, extra http.Header) ([]byte, http.Header, error) {
	if err := c.checkBaseURL(); err != nil {
		return nil, nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
		if digest != "" {
			req.Header.Set("Content-Type", protov2.MediaTypeCTIS)
			req.Header.Set(protov2.HeaderContentDigest, digest)
		} else {
			req.Header.Set("Content-Type", protov2.MediaTypeJSON)
		}
		if encoding != "" {
			req.Header.Set("Content-Encoding", encoding)
		}
	}
	req.Header.Set("Accept", protov2.MediaTypeJSON+", "+protov2.MediaTypeProblem)
	req.Header.Set("Authorization", "Bearer "+c.getAPIKey())
	req.Header.Set("User-Agent", c.userAgentHeader())
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := c.httpFor(ctx).Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	if c.verbose {
		fmt.Printf("[openctem] v2 %s %s (%d bytes) -> %d\n", method, path, len(body), resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		ve := &V2Error{
			Status:     resp.StatusCode,
			RetryAfter: parseRetryAfter(resp.Header.Get(protov2.HeaderRetryAfter), time.Now()),
			RequestID:  resp.Header.Get("X-Request-ID"),
		}
		if protov2.IsProblemContentType(resp.Header.Get("Content-Type")) {
			ve.Problem = protov2.ParseProblem(raw)
		}
		if ve.Problem == nil {
			ve.Body = string(raw)
		}
		return nil, resp.Header, ve
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	if len(data) > maxResponseBodyBytes {
		return nil, nil, fmt.Errorf("response body exceeds %d bytes", maxResponseBodyBytes)
	}
	return data, resp.Header, nil
}

// parseRetryAfter reads a Retry-After header (delay-seconds or HTTP-date).
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0
		}
		return time.Duration(min(n, 86400)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return min(d, 24*time.Hour)
		}
	}
	return 0
}
