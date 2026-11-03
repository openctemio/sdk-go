package tool

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Context is what a running tool gets from the runtime. It is canceled on
// cancel, on the task's deadline and on the sensor's kill switch.
type Context interface {
	context.Context

	// Log is a structured logger. Values are redacted (Secret prints
	// [REDACTED]) and the runtime bounds the rate and size of what it
	// keeps.
	Log() *slog.Logger
	// Progress reports done of total units (throttled by the runtime).
	Progress(done, total int, msg string)
	// Emit is the record channel. Each record is checked when it is
	// emitted.
	Emit() Emitter
	// TargetDone reports that the tool finished a target.
	TargetDone(t Target)
	// TargetError reports that a target failed (its scan coverage); err
	// is categorized like a Run error.
	TargetError(t Target, err error)
	// TargetSkipped reports that the tool did not work on a target.
	TargetSkipped(t Target, reason string)
	// Artifact creates a size-capped artifact (a raw log, a screenshot),
	// delivered separately from the records.
	Artifact(name, mediaType string) (io.WriteCloser, error)
	// Workdir is the task's private directory, removed after the task.
	Workdir() string
	// Secret returns a credential the manifest declares and the operator
	// stored; anything else is ErrUndeclaredCredential.
	Secret(name string) (Secret, error)
	// HTTP is a client that reaches only what the manifest's network
	// permission allows: the task's targets (NetTargets), the vendor
	// hosts (NetVendor) or nothing (NetNone); it never reaches cloud
	// metadata endpoints. It is defense in depth: the sandbox backend's
	// network class is the boundary. On a sensor that confines the
	// task's network it goes through the task's forwarder (EgressProxy).
	// Requests carry the User-Agent "openctem-<tool>/<version>" unless the
	// tool sets its own. A tool that speaks TCP itself uses Dial.
	HTTP() *http.Client
}

// Emitter is the record channel. Every call checks the record at once, so
// a tool learns about a bad record at the line that produced it:
//   - it must be valid CTIS (required fields, enums, ranges);
//   - its kind must be in Manifest.Produces, else ErrUndeclaredOutput (the
//     record is quarantined, the task ends partial);
//   - the task's record count and bytes must stay within the resources,
//     else ErrOutputLimit (the tool should stop);
//   - control and bidirectional-override characters are removed and long
//     strings cut;
//   - provenance (which tool, version, sandbox, sensor, task) is stamped by
//     the runtime, never taken from the tool.
//
// The runtime repeats every check on its side of the process boundary.
type Emitter interface {
	// Asset emits an asset.
	Asset(a ctis.Asset) error
	// Finding emits a finding of target t. A finding without an asset
	// reference is filed on t's asset.
	Finding(t Target, f ctis.Finding) error
	// Dependency emits a dependency (SBOM component) found on t.
	Dependency(t Target, d ctis.Dependency) error
	// Endpoint emits a method and path a web origin serves.
	// A URL in it never carries a query value or credentials.
	Endpoint(e ctis.Endpoint) error
	// Relationship emits a typed edge between two assets emitted before it
	// (by their document-local ids): a host or address exposes a service, a
	// name resolves to an address, a service serves a certificate.
	Relationship(r ctis.Relationship) error
	// Rule emits an entry of the report's rule catalog: a tool that reports
	// many findings of one rule writes the rule's text once and sets
	// rule_ref (with the same rule_id) on each finding. Optional; a rule is
	// emitted before the findings that name it.
	Rule(r ctis.Rule) error
	// Report emits every record of a report (the output of a converter),
	// plus its tool, metadata and properties (ReportInfo).
	Report(r *ctis.Report) error
}

// ReportInfo is what a report carries besides its records: the tool's
// vendor and techniques, metadata such as the coverage type and branch,
// and properties. The runtime keeps the tool's name as the manifest's.
type ReportInfo struct {
	Tool       *ctis.Tool          `json:"tool,omitempty"`
	Metadata   *ReportInfoMetadata `json:"metadata,omitempty"`
	Properties ctis.Properties     `json:"properties,omitempty"`
}

// ReportInfoMetadata is the part of a report's metadata a tool may set
// (CTIS 2.0 member names). metadata.id, generated_at and the per-target
// outcomes are the runtime's: a tool never names the document or the
// receiver's job.
type ReportInfoMetadata struct {
	DurationMs   int               `json:"duration_ms,omitempty"`
	Channel      ctis.Channel      `json:"channel,omitempty"`
	SourceRefs   []ctis.SourceRef  `json:"source_refs,omitempty"`
	CoverageType ctis.CoverageType `json:"coverage_type,omitempty"`
	Branch       *ctis.BranchInfo  `json:"branch,omitempty"`
	Profiles     []ctis.Profile    `json:"profiles,omitempty"`
	StartedAt    *time.Time        `json:"started_at,omitempty"`
	EndedAt      *time.Time        `json:"ended_at,omitempty"`
	Properties   ctis.Properties   `json:"properties,omitempty"`
	Extensions   ctis.Extensions   `json:"extensions,omitempty"`
}

// InfoOf returns the ReportInfo of r (nil when r carries none).
func InfoOf(r *ctis.Report) *ReportInfo {
	if r == nil {
		return nil
	}
	info := &ReportInfo{Tool: r.Tool, Properties: r.Properties}
	md := r.Metadata
	if md.DurationMs != 0 || md.Channel != "" || len(md.SourceRefs) > 0 || md.CoverageType != "" ||
		md.Branch != nil || len(md.Profiles) > 0 || md.StartedAt != nil || md.EndedAt != nil ||
		len(md.Properties) > 0 || len(md.Extensions) > 0 {
		info.Metadata = &ReportInfoMetadata{DurationMs: md.DurationMs, Channel: md.Channel,
			SourceRefs: md.SourceRefs, CoverageType: md.CoverageType, Branch: md.Branch,
			Profiles: md.Profiles, StartedAt: md.StartedAt, EndedAt: md.EndedAt,
			Properties: md.Properties, Extensions: md.Extensions}
	}
	if info.Tool == nil && info.Metadata == nil && len(info.Properties) == 0 {
		return nil
	}
	return info
}

// Redacted is what a Secret prints.
const Redacted = "[REDACTED]"

// Secret is a credential. It prints, formats, logs and marshals as
// [REDACTED]; Reveal returns the value, and the SDK never logs it.
type Secret struct{ v string }

// NewSecret wraps a value (runtimes and tests).
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the value. Call it where the value is used, never to log.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.v == "" }

func (s Secret) String() string   { return Redacted }
func (s Secret) GoString() string { return Redacted }

// Format prints [REDACTED] for every verb.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) }

// MarshalJSON writes "[REDACTED]".
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText writes [REDACTED].
func (s Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue logs [REDACTED].
func (s Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }
