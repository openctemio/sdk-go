package v2

// The control plane of protocol v2 (api RFC-029,
// docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md): heartbeat,
// commands, suppressions, fingerprint queries and key renewal under
// PathPrefix. Bodies are JSON; servers ignore unknown request members and
// clients must ignore unknown response members, so both sides grow
// additively. A server lists what it serves on hello (Hello.Supports).

import (
	"encoding/json"
	"time"
)

// Control-plane paths under PathPrefix.
const (
	HeartbeatPath         = "/heartbeat"
	SuppressionsPath      = "/suppressions"
	FingerprintsCheckPath = "/fingerprints/check"
	BaselineDiffPath      = "/fingerprints/baseline-diff"
	KeysPath              = "/keys"
	// ManifestPath registers the sensor manifest (api RFC-033).
	ManifestPath = "/manifest"
)

// Command transitions (POST CommandsPath/{command_id}/<action>).
const (
	ClaimAction    = "claim"
	StartAction    = "start"
	CompleteAction = "complete"
	FailAction     = "fail"
	// ReleaseAction hands a claimed (acknowledged or running) command back:
	// the platform returns it to pending, unpinned (api RFC-030).
	ReleaseAction = "release"
)

// ReleaseRequest is the body of a release: why the sensor hands the
// command back ("draining", "shutdown", "canceled", "politeness", or free
// text of at most MaxReleaseReasonLen characters).
type ReleaseRequest struct {
	Reason string `json:"reason"`
}

// MaxReleaseReasonLen bounds ReleaseRequest.Reason.
const MaxReleaseReasonLen = 200

// CommandActionPath is the full path of a transition on one command; id must
// already be path-escaped.
func CommandActionPath(commandID, action string) string {
	return PathPrefix + CommandsPath + "/" + commandID + "/" + action
}

// Hello features of the control plane (FeatureResults is the results
// resource). A sensor uses v2 for a listed feature and protocol v1 for the
// rest.
const (
	FeatureHeartbeat    = "heartbeat"
	FeatureCommands     = "commands"
	FeatureSuppressions = "suppressions"
	FeatureFingerprints = "fingerprints"
	FeatureKeys         = "keys"
	// FeatureManifest: PUT /manifest and the heartbeat's manifest_digest
	// (api RFC-033).
	FeatureManifest = "manifest"
)

// ManifestResponse answers PUT /manifest: the digest the platform stored
// (echo it as the heartbeat's manifest_digest), whether it was new, and
// what was accepted and ignored.
type ManifestResponse struct {
	ManifestDigest string            `json:"manifest_digest"`
	Changed        bool              `json:"changed"`
	Accepted       ManifestAccepted  `json:"accepted"`
	Ignored        []ManifestIgnored `json:"ignored"`
}

// ManifestAccepted is what the platform kept of a manifest.
type ManifestAccepted struct {
	Tools        []string `json:"tools"`
	Capabilities []string `json:"capabilities"`
}

// ManifestIgnored is one manifest item the platform dropped.
type ManifestIgnored struct {
	Path   string `json:"path"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason"`
}

// Control-plane limit defaults (api RFC-029 §4.1, §4.6).
const (
	DefaultMaxControlBodyBytes       = 1 << 20
	DefaultMaxFingerprintsPerRequest = 50000
)

// ProblemTypeBaseSensor prefixes the problem types api RFC-029 added; the
// RFC-026 types keep ProblemTypeBase.
const ProblemTypeBaseSensor = "https://openctem.io/problems/sensor/"

// RFC-029 problem types (ProblemTypeBaseSensor).
const (
	// ProblemInvalidTransition: the command's state does not allow the
	// transition; Problem.State is the current state.
	ProblemInvalidTransition ProblemType = "invalid-transition"
	// ProblemCommandClaimed: another sensor claimed the command first.
	ProblemCommandClaimed ProblemType = "command-claimed"
	// ProblemTransitionConflict: the command already reached this state with
	// a different result or message.
	ProblemTransitionConflict ProblemType = "transition-conflict"
	// ProblemRenewalRefused: the sensor may not renew its key.
	ProblemRenewalRefused ProblemType = "renewal-refused"
	// ProblemTooManyItems: more items than the limit (Problem.Limit).
	ProblemTooManyItems ProblemType = "too-many-items"
	// ProblemManifestInvalid: the manifest is not a JSON object with a
	// schema member of the documented shape (api RFC-033).
	ProblemManifestInvalid ProblemType = "manifest-invalid"
	// ProblemManifestSchemaUnsupported: the platform does not read the
	// manifest's schema version.
	ProblemManifestSchemaUnsupported ProblemType = "manifest-schema-unsupported"
)

// ProblemInvalidRequest (ProblemTypeBase): a malformed request body, on the
// control plane and the commit request.
const ProblemInvalidRequest ProblemType = "invalid-request"

// Deprecation announces a deprecated protocol on hello.
type Deprecation struct {
	DeprecatedAt time.Time `json:"deprecated_at"`
	SunsetAt     time.Time `json:"sunset_at"`
}

// DeprecationProtocolV1 is the hello key of protocol v1's deprecation.
const DeprecationProtocolV1 = "protocol_v1"

// Heartbeat status values.
const (
	HeartbeatStatusOK     = "ok"
	HeartbeatStatusPaused = "paused"
)

// HeartbeatResponse is the answer of POST /heartbeat. The doorbell hints use
// the v1 member names, so core.ParseHeartbeatHints reads both.
type HeartbeatResponse struct {
	SensorID             string   `json:"sensor_id"`
	TenantID             string   `json:"tenant_id"`
	Status               string   `json:"status"`
	PendingJobs          int      `json:"pending_jobs"`
	NextHeartbeatSeconds int      `json:"next_heartbeat_seconds"`
	Actions              []string `json:"actions"`
	ConfigVersion        string   `json:"config_version"`
}

// Command is a command as the v2 command resources return it.
type Command struct {
	ID             string          `json:"id"`
	Type           string          `json:"type"`
	Priority       string          `json:"priority"`
	Status         string          `json:"status"`
	SensorID       *string         `json:"sensor_id"`
	Payload        json.RawMessage `json:"payload"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      *time.Time      `json:"expires_at"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at"`
	StartedAt      *time.Time      `json:"started_at"`
	CompletedAt    *time.Time      `json:"completed_at"`
	ErrorMessage   string          `json:"error_message"`
	Result         json.RawMessage `json:"result"`
}

// CommandList is the answer of GET /commands.
type CommandList struct {
	Commands []Command `json:"commands"`
}

// CompleteRequest is the body of POST /commands/{id}/complete.
type CompleteRequest struct {
	Result json.RawMessage `json:"result,omitempty"`
}

// FailRequest is the body of POST /commands/{id}/fail.
type FailRequest struct {
	ErrorMessage string `json:"error_message"`
}

// FingerprintsCheckRequest is the body of POST /fingerprints/check.
type FingerprintsCheckRequest struct {
	Fingerprints []string `json:"fingerprints"`
}

// FingerprintsCheckResponse answers POST /fingerprints/check.
type FingerprintsCheckResponse struct {
	Existing []string `json:"existing"`
	Missing  []string `json:"missing"`
}

// BaselineDiffRequest is the body of POST /fingerprints/baseline-diff.
type BaselineDiffRequest struct {
	Repository   string   `json:"repository"`
	BaseBranch   string   `json:"base_branch"`
	Fingerprints []string `json:"fingerprints"`
}

// BaselineDiffResponse answers POST /fingerprints/baseline-diff.
type BaselineDiffResponse struct {
	NewFingerprints         []string `json:"new_fingerprints"`
	PreExistingFingerprints []string `json:"pre_existing_fingerprints"`
	BaseBranchScanned       bool     `json:"base_branch_scanned"`
}

// KeyResponse answers POST /keys: the new key, shown once.
type KeyResponse struct {
	APIKey    string     `json:"api_key"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// SuppressionRule is one active suppression rule.
type SuppressionRule struct {
	RuleID      string  `json:"rule_id,omitempty"`
	ToolName    string  `json:"tool_name,omitempty"`
	PathPattern string  `json:"path_pattern,omitempty"`
	AssetID     *string `json:"asset_id,omitempty"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// SuppressionList answers GET /suppressions.
type SuppressionList struct {
	Count int               `json:"count"`
	Rules []SuppressionRule `json:"rules"`
}
