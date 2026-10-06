// Package sarif provides an adapter to convert SARIF format to CTIS.
//
// Deprecated: the converters duplicate core.SARIFParser and the parsers the
// sensor ships; no sensor, platform or collector imports them. Emit CTIS
// from a tool (pkg/tool) or convert SARIF with the ctis module. Removal is
// planned for a later minor release (docs/STABILITY.md).
package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/assetctx"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/sdk-go/pkg/internal/importbridge"
)

// Adapter converts SARIF (Static Analysis Results Interchange Format) to CTIS.
type Adapter struct{}

// NewAdapter creates a new SARIF adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "sarif"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"sarif", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var sarif SARIFReport
	if err := json.Unmarshal(input, &sarif); err != nil {
		return false
	}
	// Check for SARIF schema or version
	return sarif.Schema != "" || sarif.Version != ""
}

// Convert transforms sarif output to a CTIS report with the one conversion
// entry point, github.com/openctemio/ctis/importer.
//
// Every finding is filed on one repository asset: opts.Repository, else the
// repository the log's versionControlProvenance names, else the repository
// of the CI job. A log with results and none of these is an error matching
// ctis.ErrNoAssetForFindings.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	asset, _ := assetctx.AdapterExplicit(opts)
	fallback, _ := assetctx.CI(assetctx.DefaultID)
	req := importbridge.Request{Format: importer.FormatSARIF, Tool: a.Name(), Input: input, Asset: asset, Fallback: fallback, NeedsAsset: true}
	if opts != nil {
		req.Scope, req.MinSeverity = opts.Repository, opts.MinSeverity
	}
	return importbridge.Convert(ctx, req)
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// SARIFReport is the root SARIF document.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a tool.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Results     []SARIFResult     `json:"results"`

	// VersionControlProvenance names the repository and revision the run
	// analyzed.
	VersionControlProvenance []SARIFVersionControlDetails `json:"versionControlProvenance,omitempty"`
}

// SARIFVersionControlDetails is a SARIF versionControlDetails object.
type SARIFVersionControlDetails struct {
	RepositoryURI string `json:"repositoryUri"`
	RevisionID    string `json:"revisionId,omitempty"`
	Branch        string `json:"branch,omitempty"`
}

// Repository returns the first repository named in the run's
// versionControlProvenance, with its revision and branch, or empty strings.
func (r *SARIFRun) Repository() (uri, revision, branch string) {
	for _, vc := range r.VersionControlProvenance {
		if u := strings.TrimSpace(vc.RepositoryURI); u != "" {
			return u, vc.RevisionID, vc.Branch
		}
	}
	return "", "", ""
}

// SARIFInvocation describes a tool invocation.
type SARIFInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

// SARIFTool describes the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver.
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Organization    string      `json:"organization,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a detection rule.
type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     SARIFMessage           `json:"shortDescription,omitempty"`
	FullDescription      SARIFMessage           `json:"fullDescription,omitempty"`
	Help                 SARIFHelp              `json:"help,omitempty"`
	HelpURI              string                 `json:"helpUri,omitempty"`
	DefaultConfiguration SARIFRuleConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           SARIFRuleProps         `json:"properties,omitempty"`
}

// SARIFRuleConfiguration describes default rule configuration.
type SARIFRuleConfiguration struct {
	Level string `json:"level,omitempty"` // error, warning, note, none
}

// SARIFHelp contains help information.
type SARIFHelp struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFRuleProps contains rule properties.
type SARIFRuleProps struct {
	Tags      []string `json:"tags,omitempty"`
	Precision string   `json:"precision,omitempty"`
}

// SARIFMessage is a SARIF message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult is a single finding.
type SARIFResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level,omitempty"`
	Message      SARIFMessage      `json:"message"`
	Locations    []SARIFLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	CodeFlows    []SARIFCodeFlow   `json:"codeFlows,omitempty"`
	Properties   map[string]any    `json:"properties,omitempty"`

	// SARIF 2.1.0 extended fields
	Kind                string            `json:"kind,omitempty"`
	BaselineState       string            `json:"baselineState,omitempty"`
	Rank                float64           `json:"rank,omitempty"`
	OccurrenceCount     int               `json:"occurrenceCount,omitempty"`
	CorrelationGuid     string            `json:"correlationGuid,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	RelatedLocations    []SARIFLocation   `json:"relatedLocations,omitempty"`
	Stacks              []SARIFStack      `json:"stacks,omitempty"`
	Attachments         []SARIFAttachment `json:"attachments,omitempty"`
	WorkItemUris        []string          `json:"workItemUris,omitempty"`
	HostedViewerUri     string            `json:"hostedViewerUri,omitempty"`
}

// SARIFLocation is a location in a result.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation is a physical file location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation is an artifact location.
type SARIFArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseId string `json:"uriBaseId,omitempty"`
}

// SARIFRegion is a region within a file.
type SARIFRegion struct {
	StartLine   int          `json:"startLine,omitempty"`
	EndLine     int          `json:"endLine,omitempty"`
	StartColumn int          `json:"startColumn,omitempty"`
	EndColumn   int          `json:"endColumn,omitempty"`
	Snippet     SARIFSnippet `json:"snippet,omitempty"`
}

// SARIFSnippet is a code snippet.
type SARIFSnippet struct {
	Text string `json:"text,omitempty"`
}

// SARIFCodeFlow represents a code flow (taint tracking).
type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows,omitempty"`
}

// SARIFThreadFlow is a thread flow in a code flow.
type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations,omitempty"`
}

// SARIFThreadFlowLocation is a location in a thread flow.
type SARIFThreadFlowLocation struct {
	Location     SARIFLocation `json:"location,omitempty"`
	NestingLevel int           `json:"nestingLevel,omitempty"`
	Importance   string        `json:"importance,omitempty"`
}

// SARIFStack represents a call stack.
type SARIFStack struct {
	Message SARIFMessage      `json:"message,omitempty"`
	Frames  []SARIFStackFrame `json:"frames,omitempty"`
}

// SARIFStackFrame is a single frame in a call stack.
type SARIFStackFrame struct {
	Location   SARIFLocation `json:"location,omitempty"`
	Module     string        `json:"module,omitempty"`
	ThreadId   int           `json:"threadId,omitempty"`
	Parameters []string      `json:"parameters,omitempty"`
}

// SARIFAttachment represents an artifact or evidence attachment.
type SARIFAttachment struct {
	Description      SARIFMessage          `json:"description,omitempty"`
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation,omitempty"`
}

// =============================================================================
// Convenience Functions
// =============================================================================

// ParseJSONBytes parses SARIF JSON from bytes.
func ParseJSONBytes(data []byte) (*SARIFReport, error) {
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}
	return &report, nil
}

// pickResultFingerprint chooses one of a result's fingerprints the same way
// every time: matchBasedId/v1 when usable, else the usable value under the
// lowest key. Ranging over the map picked a random entry, so a re-scan could
// carry a different fingerprint for the same result. "requires login" is
// what Semgrep reports instead of a value when a pro feature is missing.
func pickResultFingerprint(fps map[string]string) string {
	usable := func(v string) bool { return v != "" && v != "requires login" }
	if fp, ok := fps["matchBasedId/v1"]; ok && usable(fp) {
		return fp
	}
	keys := make([]string, 0, len(fps))
	for k, v := range fps {
		if usable(v) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return fps[keys[0]]
}

// ParseToCTIS is a convenience function to convert sarif output to CTIS.
// The findings are filed on the asset opts names (AssetValue/AssetType, else
// BranchInfo.RepositoryURL), else as Adapter.Convert does.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	asset, _ := assetctx.Explicit(opts)
	id := ""
	if opts != nil {
		id = opts.AssetID
	}
	fallback, _ := assetctx.CI(id)
	req := importbridge.Request{Format: importer.FormatSARIF, Tool: NewAdapter().Name(), Input: data, Asset: asset, Fallback: fallback, NeedsAsset: true}
	if so := assetctx.ScopeOptions(opts); so != nil {
		req.Scope = so.Repository
	}
	return importbridge.Convert(context.Background(), req)
}
