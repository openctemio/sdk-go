// Package v2 is the client side of sensor protocol v2 results ingest
// (RFC-026, api docs/rfcs/RFC-026-sensor-results-ingest.md): the paths, media
// type, headers, problem types, status resource, hello document and the
// Content-Digest the SDK sends.
//
// It mirrors the api's pkg/sensorproto/v2. The strings here are the wire
// contract; changing one is a protocol change. The conformance suite
// (pkg/conformance) checks them against a real server.
//
// Import it with an alias, as the api does:
//
//	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
//
// Stability: Stable (docs/STABILITY.md); Frozen once protocol v3 ships.
package v2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"strings"
	"time"
)

// ProtocolVersion is the protocol level a v2 response announces.
const ProtocolVersion = 2

// Paths.
const (
	PathPrefix   = "/api/v2/sensor"
	ResultsPath  = "/results"
	CommandsPath = "/commands"
	HelloPath    = "/hello"
)

// ReportPath is the whole-report (and status) resource of a report:
// PUT/GET/DELETE. commandID binds it to a claimed command; "" is the
// unsolicited form.
func ReportPath(commandID, reportID string) string {
	if commandID != "" {
		return PathPrefix + CommandsPath + "/" + commandID + ResultsPath + "/" + reportID
	}
	return PathPrefix + ResultsPath + "/" + reportID
}

// StatusPath is the status resource. Status is read on the unsolicited form
// whatever form the report was sent on.
func StatusPath(reportID string) string { return PathPrefix + ResultsPath + "/" + reportID }

// SegmentPath is one segment of a segmented report.
func SegmentPath(commandID, reportID string, seq int) string {
	return fmt.Sprintf("%s/segments/%d", ReportPath(commandID, reportID), seq)
}

// CommitPath closes a segmented report.
func CommitPath(commandID, reportID string) string {
	return ReportPath(commandID, reportID) + "/commit"
}

// Media types and encodings.
const (
	MediaTypeCTIS    = "application/vnd.openctem.ctis.v1+json"
	MediaTypeProblem = "application/problem+json"
	MediaTypeJSON    = "application/json"

	EncodingGzip = "gzip"
	EncodingZstd = "zstd"
)

// Header names.
const (
	// HeaderProtocol is on every v2 response.
	HeaderProtocol      = "OpenCTEM-Protocol"
	HeaderContentDigest = "Content-Digest"
	HeaderRetryAfter    = "Retry-After"
	// HeaderSensorFeatures lists optional request features a sensor asks
	// for (comma-separated, case-insensitive), e.g. FeatureCapacity on a
	// poll (claim-N).
	HeaderSensorFeatures = "X-OpenCTEM-Sensor-Features"
	// HeaderLeaseEpoch is the lease epoch (Command.LeaseEpoch) a sensor
	// holds a command under, sent on complete and fail: the platform
	// refuses the change when the command was claimed again since (api
	// RFC-035 D6). Optional; without it the platform fences by sensor and
	// state.
	HeaderLeaseEpoch = "X-OpenCTEM-Lease-Epoch"
)

// FeatureResults is the hello feature of the results resource.
const FeatureResults = "results"

// DigestSHA256 is the Content-Digest algorithm the SDK sends.
const DigestSHA256 = "sha-256"

// ContentDigest returns the RFC 9530 Content-Digest value (sha-256) of the
// content as sent, i.e. of the compressed bytes when a Content-Encoding is
// set.
func ContentDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return DigestSHA256 + "=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// IsProblemContentType reports whether a response Content-Type is RFC 9457
// problem details.
func IsProblemContentType(v string) bool {
	mt, _, err := mime.ParseMediaType(v)
	return err == nil && strings.EqualFold(mt, MediaTypeProblem)
}

// ProblemTypeBase prefixes every problem type URI.
const ProblemTypeBase = "https://openctem.io/problems/ingest/"

// ProblemType is the short name of a problem type ("digest-mismatch").
type ProblemType string

// Problem types the SDK acts on. The server's table is closed; a name the SDK
// does not know is handled by its HTTP status.
const (
	ProblemDigestRequired        ProblemType = "digest-required"
	ProblemDigestMismatch        ProblemType = "digest-mismatch"
	ProblemInvalidID             ProblemType = "invalid-id"
	ProblemUnauthenticated       ProblemType = "unauthenticated"
	ProblemScopeDenied           ProblemType = "scope-denied"
	ProblemCommandNotFound       ProblemType = "command-not-found"
	ProblemReportNotFound        ProblemType = "report-not-found"
	ProblemReportConflict        ProblemType = "report-conflict"
	ProblemReportCommitted       ProblemType = "report-committed"
	ProblemReportExpired         ProblemType = "report-expired"
	ProblemSegmentHeaderMismatch ProblemType = "segment-header-mismatch"
	ProblemSegmentSetMismatch    ProblemType = "segment-set-mismatch"
	ProblemBindingMismatch       ProblemType = "binding-mismatch"
	ProblemContentTooLarge       ProblemType = "content-too-large"
	ProblemDecompressedTooLarge  ProblemType = "decompressed-too-large"
	ProblemReportTooLarge        ProblemType = "report-too-large"
	ProblemUnsupportedMediaType  ProblemType = "unsupported-media-type"
	ProblemSchemaInvalid         ProblemType = "schema-invalid"
	ProblemToolNotPermitted      ProblemType = "tool-not-permitted"
	ProblemRateLimited           ProblemType = "rate-limited"
	ProblemQueueFull             ProblemType = "queue-full"
	ProblemTooManyOpenReports    ProblemType = "too-many-open-reports"
	ProblemInternal              ProblemType = "internal"
	ProblemUnavailable           ProblemType = "unavailable"
)

// ItemError is one per-item error on a 422 problem or on the status resource.
type ItemError struct {
	Segment *int   `json:"segment,omitempty"`
	Pointer string `json:"pointer"`
	Code    string `json:"code"`
	Detail  string `json:"detail"`
}

// Problem is an RFC 9457 problem details document with the RFC-026 extension
// members.
type Problem struct {
	Type   string      `json:"type"`
	Title  string      `json:"title"`
	Status int         `json:"status"`
	Detail string      `json:"detail"`
	Errors []ItemError `json:"errors,omitempty"`
	Limit  *int64      `json:"limit,omitempty"`
	// State is the command's current state on an invalid-transition problem
	// (api RFC-029 §4.4).
	State     string `json:"state,omitempty"`
	Retryable bool   `json:"retryable"`
}

// Name returns the problem type's short name, or "" when the type URI is
// neither an ingest (RFC-026) nor a sensor (RFC-029) problem type.
func (p *Problem) Name() ProblemType {
	if p == nil {
		return ""
	}
	for _, base := range []string{ProblemTypeBase, ProblemTypeBaseSensor} {
		if name, ok := strings.CutPrefix(p.Type, base); ok {
			return ProblemType(name)
		}
	}
	return ""
}

// ParseProblem decodes a problem document. It returns nil for a body that is
// not one.
func ParseProblem(body []byte) *Problem {
	var p Problem
	if json.Unmarshal(body, &p) != nil || p.Type == "" {
		return nil
	}
	return &p
}

// ReportState is the lifecycle state of a report on the status resource.
type ReportState string

const (
	StateReceiving  ReportState = "receiving"
	StateQueued     ReportState = "queued"
	StateProcessing ReportState = "processing"
	StateCompleted  ReportState = "completed"
	StateFailed     ReportState = "failed"
	StateExpired    ReportState = "expired"
)

// IsFinal reports whether the state can no longer change.
func (s ReportState) IsFinal() bool {
	return s == StateCompleted || s == StateFailed || s == StateExpired
}

// Counts are asset and finding counts on the status resource.
type Counts struct {
	Assets   int `json:"assets"`
	Findings int `json:"findings"`
}

// SegmentCounts are the segments received and, once committed, expected.
type SegmentCounts struct {
	Received int  `json:"received"`
	Expected *int `json:"expected,omitempty"`
}

// Status is the report status resource (RFC-026 §3.7).
type Status struct {
	ReportID        string        `json:"report_id"`
	CommandID       string        `json:"command_id,omitempty"`
	State           ReportState   `json:"state"`
	Segments        SegmentCounts `json:"segments"`
	Accepted        Counts        `json:"accepted"`
	Rejected        Counts        `json:"rejected"`
	Quarantined     Counts        `json:"quarantined"`
	AutoResolved    int           `json:"auto_resolved"`
	AutoResolve     string        `json:"auto_resolve,omitempty"`
	Errors          []ItemError   `json:"errors"`
	ErrorsTruncated bool          `json:"errors_truncated"`
	ReceivedAt      time.Time     `json:"received_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// CommitRequest is the body of POST .../commit: the canonical sha-256
// Content-Digest of each segment, in segment order.
type CommitRequest struct {
	SegmentCount   int      `json:"segment_count"`
	SegmentDigests []string `json:"segment_digests"`
}

// Limits are the server's ingest limits, published on hello.
type Limits struct {
	MaxContentBytes         int64   `json:"max_content_bytes"`
	MaxDecompressedBytes    int64   `json:"max_decompressed_bytes"`
	MaxCompressionRatio     float64 `json:"max_compression_ratio"`
	MaxZstdWindowBytes      int64   `json:"max_zstd_window_bytes"`
	MaxJSONDepth            int     `json:"max_json_depth"`
	MaxFindingsPerSegment   int     `json:"max_findings_per_segment"`
	MaxAssetsPerSegment     int     `json:"max_assets_per_segment"`
	MaxSegmentsPerReport    int     `json:"max_segments_per_report"`
	MaxFindingsPerReport    int     `json:"max_findings_per_report"`
	MaxAssetsPerReport      int     `json:"max_assets_per_report"`
	MaxOpenReportsPerSensor int     `json:"max_open_reports_per_sensor"`
	MaxSegmentsInFlight     int     `json:"max_segments_in_flight"`
	MaxItemErrors           int     `json:"max_item_errors"`
	UncommittedTTLSeconds   int     `json:"uncommitted_ttl_seconds"`
	// MaxControlBodyBytes and MaxFingerprintsPerRequest are the control-plane
	// limits (api RFC-029 §4); zero on a server from before it.
	MaxControlBodyBytes       int64 `json:"max_control_body_bytes,omitempty"`
	MaxFingerprintsPerRequest int   `json:"max_fingerprints_per_request,omitempty"`
}

// DefaultLimits are the RFC-026 §3.6 defaults, used when hello is not
// available or leaves a limit unset.
func DefaultLimits() Limits {
	return Limits{
		MaxContentBytes:         16 << 20,
		MaxDecompressedBytes:    64 << 20,
		MaxCompressionRatio:     100,
		MaxZstdWindowBytes:      8 << 20,
		MaxJSONDepth:            64,
		MaxFindingsPerSegment:   10000,
		MaxAssetsPerSegment:     10000,
		MaxSegmentsPerReport:    256,
		MaxFindingsPerReport:    100000,
		MaxAssetsPerReport:      100000,
		MaxOpenReportsPerSensor: 8,
		MaxSegmentsInFlight:     4,
		MaxItemErrors:           100,
		UncommittedTTLSeconds:   3600,

		MaxControlBodyBytes:       DefaultMaxControlBodyBytes,
		MaxFingerprintsPerRequest: DefaultMaxFingerprintsPerRequest,
	}
}

// WithDefaults returns l with every unset (zero or negative) limit replaced by
// its default, so a partial hello never sizes segments at zero.
func (l Limits) WithDefaults() Limits {
	d := DefaultLimits()
	pick64 := func(v, def int64) int64 {
		if v <= 0 {
			return def
		}
		return v
	}
	pick := func(v, def int) int {
		if v <= 0 {
			return def
		}
		return v
	}
	l.MaxContentBytes = pick64(l.MaxContentBytes, d.MaxContentBytes)
	l.MaxDecompressedBytes = pick64(l.MaxDecompressedBytes, d.MaxDecompressedBytes)
	if l.MaxCompressionRatio <= 0 {
		l.MaxCompressionRatio = d.MaxCompressionRatio
	}
	l.MaxZstdWindowBytes = pick64(l.MaxZstdWindowBytes, d.MaxZstdWindowBytes)
	l.MaxJSONDepth = pick(l.MaxJSONDepth, d.MaxJSONDepth)
	l.MaxFindingsPerSegment = pick(l.MaxFindingsPerSegment, d.MaxFindingsPerSegment)
	l.MaxAssetsPerSegment = pick(l.MaxAssetsPerSegment, d.MaxAssetsPerSegment)
	l.MaxSegmentsPerReport = pick(l.MaxSegmentsPerReport, d.MaxSegmentsPerReport)
	l.MaxFindingsPerReport = pick(l.MaxFindingsPerReport, d.MaxFindingsPerReport)
	l.MaxAssetsPerReport = pick(l.MaxAssetsPerReport, d.MaxAssetsPerReport)
	l.MaxOpenReportsPerSensor = pick(l.MaxOpenReportsPerSensor, d.MaxOpenReportsPerSensor)
	l.MaxSegmentsInFlight = pick(l.MaxSegmentsInFlight, d.MaxSegmentsInFlight)
	l.MaxItemErrors = pick(l.MaxItemErrors, d.MaxItemErrors)
	l.UncommittedTTLSeconds = pick(l.UncommittedTTLSeconds, d.UncommittedTTLSeconds)
	l.MaxControlBodyBytes = pick64(l.MaxControlBodyBytes, d.MaxControlBodyBytes)
	l.MaxFingerprintsPerRequest = pick(l.MaxFingerprintsPerRequest, d.MaxFingerprintsPerRequest)
	return l
}

// Hello is GET /api/v2/sensor/hello.
type Hello struct {
	Protocol   int      `json:"protocol"`
	Features   []string `json:"features"`
	MediaTypes []string `json:"media_types"`
	Encodings  []string `json:"encodings"`
	Digests    []string `json:"digests"`
	Limits     Limits   `json:"limits"`
	// Deprecations announces deprecated protocols ("protocol_v1"), api
	// RFC-029 §4.2. Empty on a server from before it.
	Deprecations map[string]Deprecation `json:"deprecations,omitempty"`
	// TransportV3 says where the platform serves sensor protocol v3 (api
	// RFC-059); nil when it does not.
	TransportV3 *TransportV3 `json:"transport_v3,omitempty"`
	// SignedJobs lists the job signer's keys when the platform signs jobs
	// (FeatureSignedJobs); nil when it does not. Keys is empty while the
	// signer has not answered the platform yet.
	SignedJobs *SignedJobs `json:"signed_jobs,omitempty"`
}

// SignedJobs is the hello's description of job signing.
type SignedJobs struct {
	PayloadType string         `json:"payload_type"`
	Keys        []SignedJobKey `json:"keys"`
	// KeySet is the current key set: a DSSE envelope signed by the
	// installation's offline root key (payload type
	// application/vnd.openctem.keyset.v1+json) listing the online signer
	// keys, with a version and an expiry. Absent when the platform serves
	// none. A sensor verifies it against its pinned root (pkg/jobsig).
	KeySet json.RawMessage `json:"keyset,omitempty"`
}

// SignedJobKey is one signer key: KeyID is "SHA256:" + lower-case hex of
// the SHA-256 of the raw key, PublicKey the raw 32-byte Ed25519 key in
// standard base64. A sensor recomputes the id; it never trusts it.
type SignedJobKey struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// TransportV3 locates protocol v3 on a v2 hello.
type TransportV3 struct {
	// HTTPSPath is the HTTPS binding's path on the platform host.
	HTTPSPath string `json:"https_path"`
	// GRPCEndpoint is host:port of the gRPC (mTLS) binding; "" when only
	// the HTTPS binding is served.
	GRPCEndpoint string `json:"grpc_endpoint,omitempty"`
}

// Supports reports whether the hello document lists feature (one of the
// Feature* names). Results are better checked with SupportsResults, which
// also checks the media type.
func (h *Hello) Supports(feature string) bool {
	if h == nil || h.Protocol < ProtocolVersion {
		return false
	}
	for _, f := range h.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// SupportsResults reports whether the hello document offers the CTIS results
// resource this SDK speaks.
func (h *Hello) SupportsResults() bool {
	if h == nil || h.Protocol < ProtocolVersion {
		return false
	}
	hasFeature, hasType := false, false
	for _, f := range h.Features {
		if f == FeatureResults {
			hasFeature = true
		}
	}
	for _, m := range h.MediaTypes {
		if strings.EqualFold(m, MediaTypeCTIS) {
			hasType = true
		}
	}
	return hasFeature && hasType
}

// SupportsEncoding reports whether the server accepts a content coding.
func (h *Hello) SupportsEncoding(enc string) bool {
	if h == nil {
		return false
	}
	for _, e := range h.Encodings {
		if strings.EqualFold(e, enc) {
			return true
		}
	}
	return false
}
