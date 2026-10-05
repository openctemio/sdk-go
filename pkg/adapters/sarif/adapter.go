// Package sarif provides an adapter to convert SARIF format to CTIS.
//
// Deprecated: the converters duplicate ctis.FromSARIF and the parsers the
// sensor ships; no sensor, platform or collector imports them. Emit CTIS
// from a tool (pkg/tool) or convert SARIF with the ctis module. Removal is
// planned for a later minor release (docs/STABILITY.md).
package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/assetctx"
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

// Convert transforms SARIF input to CTIS Report.
//
// Every finding is filed on one repository asset: opts.Repository, else the
// repository the log's versionControlProvenance names, else the repository
// of the CI job (GitHub Actions, GitLab CI). A log with results and none of
// these is an error matching ctis.ErrNoAssetForFindings.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	asset, ok := assetctx.AdapterExplicit(opts)
	return a.convert(input, opts, asset, ok)
}

// convert converts input, filing its findings on asset when hasAsset.
func (a *Adapter) convert(input []byte, opts *core.AdapterOptions, asset ctis.Asset, hasAsset bool) (*ctis.Report, error) {
	var sarif SARIFReport
	if err := json.Unmarshal(input, &sarif); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}

	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"

	if opts != nil {
		report.Metadata.Scope = &ctis.Scope{
			Name: opts.Repository,
		}
	}

	// Process each run
	for runIdx, run := range sarif.Runs {
		// Set tool info from first run
		if report.Tool == nil && run.Tool.Driver.Name != "" {
			version := run.Tool.Driver.Version
			if version == "" {
				version = run.Tool.Driver.SemanticVersion
			}
			report.Tool = &ctis.Tool{
				Name:    run.Tool.Driver.Name,
				Version: version,
				Vendor:  run.Tool.Driver.Organization,
			}
		}

		// Build rule index for quick lookup
		ruleIndex := make(map[string]*SARIFRule)
		for i := range run.Tool.Driver.Rules {
			rule := &run.Tool.Driver.Rules[i]
			ruleIndex[rule.ID] = rule
		}

		// Convert results to findings
		for i, result := range run.Results {
			finding := a.convertResult(result, ruleIndex, opts, runIdx, i)
			if finding != nil {
				report.Findings = append(report.Findings, *finding)
			}
		}
	}

	if !hasAsset {
		for i := range sarif.Runs {
			if asset, hasAsset = assetctx.SARIFProvenance(sarif.Runs[i].Repository()); hasAsset {
				break
			}
		}
	}
	if !hasAsset {
		asset, hasAsset = assetctx.CI(assetctx.DefaultID)
	}
	tool := "SARIF"
	if report.Tool != nil {
		tool = report.Tool.Name
	}
	if err := assetctx.BindOrFail(report, asset, hasAsset, tool); err != nil {
		return nil, err
	}
	return report, nil
}

// convertResult converts a SARIF result to a CTIS finding.
func (a *Adapter) convertResult(result SARIFResult, ruleIndex map[string]*SARIFRule, opts *core.AdapterOptions, runIdx, resultIdx int) *ctis.Finding {
	rule := ruleIndex[result.RuleID]

	finding := &ctis.Finding{
		ID:     fmt.Sprintf("run%d-finding%d", runIdx, resultIdx+1),
		Type:   ctis.FindingTypeVulnerability,
		RuleID: result.RuleID,
	}

	// Get info from rule if available
	if rule != nil {
		// Title: prefer human-readable title over generic "Semgrep Finding: rule.id"
		finding.Title = a.extractTitle(rule)
		finding.Description = rule.FullDescription.Text
		finding.RuleName = rule.Name

		// Severity from rule's default configuration
		if rule.DefaultConfiguration.Level != "" {
			finding.Severity = mapSARIFSeverity(rule.DefaultConfiguration.Level)
		}

		// Extract CWE, OWASP, Confidence from tags
		cwes, owasps, confidence := a.extractFromTags(rule.Properties.Tags)
		if len(cwes) > 0 || len(owasps) > 0 {
			finding.Vulnerability = &ctis.VulnerabilityDetails{
				CWEIDs:   cwes,
				OWASPIDs: owasps,
			}
			if len(cwes) > 0 {
				finding.Vulnerability.CWEID = cwes[0]
			}
		}
		finding.Confidence = confidence

		// Add help URL as reference
		if rule.HelpURI != "" {
			finding.References = append(finding.References, rule.HelpURI)
		}

		// Extract additional references from help markdown
		if rule.Help.Markdown != "" {
			refs := extractURLsFromMarkdown(rule.Help.Markdown)
			finding.References = append(finding.References, refs...)
		}

		// Tags from rule properties
		for _, tag := range rule.Properties.Tags {
			// Skip CWE/OWASP/CONFIDENCE tags (already processed)
			tagLower := strings.ToLower(tag)
			if !strings.HasPrefix(tagLower, "cwe-") &&
				!strings.HasPrefix(tagLower, "owasp") &&
				!strings.Contains(tagLower, "confidence") {
				finding.Tags = append(finding.Tags, tag)
			}
		}
	}

	// Override severity from result level if present
	if result.Level != "" {
		finding.Severity = mapSARIFSeverity(result.Level)
	}

	// Use message as title/description fallback
	if finding.Title == "" {
		finding.Title = result.Message.Text
	}

	// Set message from SARIF result message (primary display text)
	finding.Message = result.Message.Text

	// Fingerprint from result fingerprints
	finding.Fingerprint = pickResultFingerprint(result.Fingerprints)

	// Generate fingerprint if not available
	if finding.Fingerprint == "" {
		path := ""
		line := 0
		if len(result.Locations) > 0 {
			path = result.Locations[0].PhysicalLocation.ArtifactLocation.URI
			line = result.Locations[0].PhysicalLocation.Region.StartLine
		}
		finding.Fingerprint = core.GenerateSastFingerprint(path, result.RuleID, line)
	}

	// Set location from first location
	if len(result.Locations) > 0 {
		loc := result.Locations[0]
		finding.Location = &ctis.FindingLocation{
			Path:        loc.PhysicalLocation.ArtifactLocation.URI,
			StartLine:   loc.PhysicalLocation.Region.StartLine,
			EndLine:     loc.PhysicalLocation.Region.EndLine,
			StartColumn: loc.PhysicalLocation.Region.StartColumn,
			EndColumn:   loc.PhysicalLocation.Region.EndColumn,
			Snippet:     loc.PhysicalLocation.Region.Snippet.Text,
		}
	}

	// Convert code flows (taint tracking)
	if len(result.CodeFlows) > 0 {
		finding.DataFlow = a.convertCodeFlow(result.CodeFlows[0])
	}

	// Map SARIF 2.1.0 extended fields
	// Send the CTIS vocabulary ("not_applicable"), not the SARIF spelling
	// ("notApplicable"), which the CTIS schema rejects; unknown values unset.
	finding.Kind = ctis.NormalizeSARIFKind(result.Kind)
	finding.BaselineState = ctis.NormalizeSARIFBaselineState(result.BaselineState)
	finding.Rank = result.Rank
	finding.OccurrenceCount = result.OccurrenceCount
	finding.CorrelationID = result.CorrelationGuid
	finding.PartialFingerprints = result.PartialFingerprints
	finding.WorkItemURIs = result.WorkItemUris
	finding.HostedViewerURI = result.HostedViewerUri

	// Convert related locations
	for _, loc := range result.RelatedLocations {
		finding.RelatedLocations = append(finding.RelatedLocations, &ctis.FindingLocation{
			Path:        loc.PhysicalLocation.ArtifactLocation.URI,
			StartLine:   loc.PhysicalLocation.Region.StartLine,
			EndLine:     loc.PhysicalLocation.Region.EndLine,
			StartColumn: loc.PhysicalLocation.Region.StartColumn,
			EndColumn:   loc.PhysicalLocation.Region.EndColumn,
			Snippet:     loc.PhysicalLocation.Region.Snippet.Text,
		})
	}

	// Convert stacks
	for _, stack := range result.Stacks {
		st := &ctis.StackTrace{
			Message: stack.Message.Text,
		}
		for _, frame := range stack.Frames {
			st.Frames = append(st.Frames, &ctis.StackFrame{
				Location: &ctis.FindingLocation{
					Path:        frame.Location.PhysicalLocation.ArtifactLocation.URI,
					StartLine:   frame.Location.PhysicalLocation.Region.StartLine,
					EndLine:     frame.Location.PhysicalLocation.Region.EndLine,
					StartColumn: frame.Location.PhysicalLocation.Region.StartColumn,
					EndColumn:   frame.Location.PhysicalLocation.Region.EndColumn,
					Snippet:     frame.Location.PhysicalLocation.Region.Snippet.Text,
				},
				Module:     frame.Module,
				ThreadID:   frame.ThreadId,
				Parameters: frame.Parameters,
			})
		}
		finding.Stacks = append(finding.Stacks, st)
	}

	// Convert attachments
	for _, att := range result.Attachments {
		finding.Attachments = append(finding.Attachments, &ctis.Attachment{
			Description: att.Description.Text,
			ArtifactLocation: &ctis.ArtifactLocation{
				URI: att.ArtifactLocation.URI,
			},
		})
	}

	// Filter by severity if option is set
	if opts != nil && opts.MinSeverity != "" {
		if !meetsMinSeverity(finding.Severity, ctis.Severity(opts.MinSeverity)) {
			return nil
		}
	}

	return finding
}

// extractTitle extracts a human-readable title from rule.
func (a *Adapter) extractTitle(rule *SARIFRule) string {
	// Check shortDescription first
	if rule.ShortDescription.Text != "" {
		// Skip generic "Semgrep Finding: rule.id" format
		if !strings.HasPrefix(rule.ShortDescription.Text, "Semgrep Finding:") {
			return rule.ShortDescription.Text
		}
	}

	// Try to create title from rule ID
	// e.g., "dockerfile.security.missing-user.missing-user" -> "Missing User"
	if rule.ID != "" {
		return slugToTitle(rule.ID)
	}

	// Fallback to rule name
	return rule.Name
}

// extractFromTags extracts CWE IDs, OWASP IDs, and confidence from SARIF tags.
func (a *Adapter) extractFromTags(tags []string) (cwes []string, owasps []string, confidence int) {
	confidence = 70 // Default medium confidence

	for _, tag := range tags {
		tagLower := strings.ToLower(tag)

		// Extract CWE (e.g., "CWE-95: Improper Neutralization...")
		if strings.HasPrefix(tagLower, "cwe-") {
			// Extract just the CWE ID
			if idx := strings.Index(tag, ":"); idx > 0 {
				cwes = append(cwes, strings.TrimSpace(tag[:idx]))
			} else if idx := strings.Index(tag, " "); idx > 0 {
				cwes = append(cwes, strings.TrimSpace(tag[:idx]))
			} else {
				cwes = append(cwes, tag)
			}
		}

		// Extract OWASP (e.g., "OWASP-A03:2021 - Injection")
		if strings.HasPrefix(tagLower, "owasp") {
			// Extract just the OWASP ID (e.g., "A03:2021")
			owasp := tag
			if strings.HasPrefix(tagLower, "owasp-") {
				owasp = tag[6:] // Remove "OWASP-" prefix
			}
			if idx := strings.Index(owasp, " - "); idx > 0 {
				owasps = append(owasps, strings.TrimSpace(owasp[:idx]))
			} else {
				owasps = append(owasps, owasp)
			}
		}

		// Extract confidence (e.g., "MEDIUM CONFIDENCE", "HIGH CONFIDENCE")
		if strings.Contains(tagLower, "confidence") {
			if strings.Contains(tagLower, "high") {
				confidence = 90
			} else if strings.Contains(tagLower, "medium") {
				confidence = 70
			} else if strings.Contains(tagLower, "low") {
				confidence = 50
			}
		}
	}

	return cwes, owasps, confidence
}

// slugToTitle converts a rule ID slug to human-readable title.
// e.g., "dockerfile.security.missing-user.missing-user" -> "Missing User"
func slugToTitle(slug string) string {
	parts := strings.Split(slug, ".")
	if len(parts) == 0 {
		return slug
	}

	// Use last part (or second-to-last if they're the same)
	lastPart := parts[len(parts)-1]
	if len(parts) > 1 && parts[len(parts)-1] == parts[len(parts)-2] {
		lastPart = parts[len(parts)-2]
	}

	// Convert hyphens to spaces and capitalize
	words := strings.Split(lastPart, "-")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}

	return strings.Join(words, " ")
}

// extractURLsFromMarkdown extracts URLs from markdown text.
func extractURLsFromMarkdown(markdown string) []string {
	var urls []string

	// Match markdown links [text](url)
	linkRegex := regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	matches := linkRegex.FindAllStringSubmatch(markdown, -1)
	for _, match := range matches {
		if len(match) > 2 && strings.HasPrefix(match[2], "http") {
			urls = append(urls, match[2])
		}
	}

	// Match raw URLs
	urlRegex := regexp.MustCompile(`https?://[^\s<>\[\]()]+`)
	rawURLs := urlRegex.FindAllString(markdown, -1)
	for _, url := range rawURLs {
		// Avoid duplicates
		found := false
		for _, existing := range urls {
			if existing == url {
				found = true
				break
			}
		}
		if !found {
			urls = append(urls, url)
		}
	}

	return urls
}

// convertCodeFlow converts SARIF code flow to CTIS data flow.
func (a *Adapter) convertCodeFlow(cf SARIFCodeFlow) *ctis.DataFlow {
	if len(cf.ThreadFlows) == 0 {
		return nil
	}

	dataFlow := &ctis.DataFlow{}

	for _, tf := range cf.ThreadFlows {
		for i, loc := range tf.Locations {
			dfLoc := ctis.DataFlowLocation{
				Path:    loc.Location.PhysicalLocation.ArtifactLocation.URI,
				Line:    loc.Location.PhysicalLocation.Region.StartLine,
				Column:  loc.Location.PhysicalLocation.Region.StartColumn,
				Content: loc.Location.PhysicalLocation.Region.Snippet.Text,
				Index:   i,
			}

			// First location is source, last is sink, rest are intermediates
			if i == 0 {
				dataFlow.Sources = append(dataFlow.Sources, dfLoc)
			} else if i == len(tf.Locations)-1 {
				dataFlow.Sinks = append(dataFlow.Sinks, dfLoc)
			} else {
				dataFlow.Intermediates = append(dataFlow.Intermediates, dfLoc)
			}
		}
	}

	return dataFlow
}

// mapSARIFSeverity maps SARIF level to CTIS severity.
func mapSARIFSeverity(level string) ctis.Severity {
	switch strings.ToLower(level) {
	case "error":
		return ctis.SeverityHigh
	case "warning":
		return ctis.SeverityMedium
	case "note":
		return ctis.SeverityLow
	case "none":
		return ctis.SeverityInfo
	default:
		return ctis.SeverityMedium
	}
}

// meetsMinSeverity checks if severity meets minimum threshold.
func meetsMinSeverity(s, min ctis.Severity) bool {
	order := map[ctis.Severity]int{
		ctis.SeverityCritical: 5,
		ctis.SeverityHigh:     4,
		ctis.SeverityMedium:   3,
		ctis.SeverityLow:      2,
		ctis.SeverityInfo:     1,
	}
	return order[s] >= order[min]
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// =============================================================================
// SARIF Types (SARIF 2.1.0 Specification)
// =============================================================================

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

// ParseToCTIS is a convenience function to parse SARIF JSON to CTIS format.
// This provides a consistent API with other scanner parsers (e.g., semgrep.ParseToCTIS).
//
// The findings are filed on the asset opts names (AssetValue/AssetType, else
// BranchInfo.RepositoryURL), else as Adapter.Convert does.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	asset, ok := assetctx.Explicit(opts)
	return NewAdapter().convert(data, assetctx.ScopeOptions(opts), asset, ok)
}

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
