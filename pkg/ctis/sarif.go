package ctis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// =============================================================================
// SARIF Types (for parsing tool output)
// =============================================================================

// SARIFLog is the root SARIF document.
type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a tool.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Artifacts   []SARIFArtifact   `json:"artifacts,omitempty"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool describes the tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool metadata.
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a rule/check.
type SARIFRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name,omitempty"`
	ShortDescription     *SARIFMessage    `json:"shortDescription,omitempty"`
	FullDescription      *SARIFMessage    `json:"fullDescription,omitempty"`
	HelpURI              string           `json:"helpUri,omitempty"`
	Help                 *SARIFMessage    `json:"help,omitempty"`
	DefaultConfiguration *SARIFRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any   `json:"properties,omitempty"`
}

// SARIFRuleConfig holds rule configuration.
type SARIFRuleConfig struct {
	Level string `json:"level,omitempty"`
}

// SARIFResult represents a finding.
type SARIFResult struct {
	RuleID       string            `json:"ruleId"`
	RuleIndex    int               `json:"ruleIndex,omitempty"`
	Level        string            `json:"level,omitempty"`
	Message      SARIFMessage      `json:"message"`
	Locations    []SARIFLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Properties   map[string]any    `json:"properties,omitempty"`
}

// SARIFMessage holds text.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a code location.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation contains file/region info.
type SARIFPhysicalLocation struct {
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation contains file path.
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseId string `json:"uriBaseId,omitempty"`
}

// SARIFRegion contains line/column info.
type SARIFRegion struct {
	StartLine   int           `json:"startLine,omitempty"`
	EndLine     int           `json:"endLine,omitempty"`
	StartColumn int           `json:"startColumn,omitempty"`
	EndColumn   int           `json:"endColumn,omitempty"`
	Snippet     *SARIFSnippet `json:"snippet,omitempty"`
}

// SARIFSnippet contains code snippet.
type SARIFSnippet struct {
	Text string `json:"text"`
}

// SARIFArtifact represents a scanned file.
type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
}

// SARIFInvocation contains execution details.
type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	CommandLine         string `json:"commandLine,omitempty"`
}

// =============================================================================
// SARIF to CTIS Conversion
// =============================================================================

// ConvertOptions configures SARIF to CTIS conversion.
type ConvertOptions struct {
	// Asset to associate findings with
	AssetType  AssetType
	AssetValue string
	AssetID    string

	// Branch/commit info (legacy - use BranchInfo for full context)
	Branch    string
	CommitSHA string

	// Branch information for branch-aware finding lifecycle
	// Provides full CI/CD context for auto-resolve and expiry features
	BranchInfo *BranchInfo

	// Default confidence
	DefaultConfidence int

	// Tool type hints (for finding type detection)
	ToolType string // "sast", "sca", "secret", "iac", "web3"
}

// DefaultConvertOptions returns default conversion options.
func DefaultConvertOptions() *ConvertOptions {
	return &ConvertOptions{
		AssetType:         AssetTypeRepository,
		DefaultConfidence: 90,
	}
}

// FromSARIF converts SARIF log to CTIS report.
func FromSARIF(data []byte, opts *ConvertOptions) (*Report, error) {
	if opts == nil {
		opts = DefaultConvertOptions()
	}

	var sarif SARIFLog
	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}

	report := NewReport()

	if len(sarif.Runs) == 0 {
		return report, nil
	}

	run := sarif.Runs[0]

	// Set tool info
	report.Tool = &Tool{
		Name:         run.Tool.Driver.Name,
		Version:      run.Tool.Driver.Version,
		Capabilities: detectCapabilities(run.Tool.Driver.Name, opts.ToolType),
	}
	if run.Tool.Driver.InformationURI != "" {
		report.Tool.InfoURL = run.Tool.Driver.InformationURI
	}

	// Add asset if configured
	if opts.AssetValue != "" {
		assetID := opts.AssetID
		if assetID == "" {
			assetID = "asset-1"
		}
		report.Assets = append(report.Assets, Asset{
			ID:          assetID,
			Type:        opts.AssetType,
			Value:       opts.AssetValue,
			Criticality: CriticalityHigh,
		})
	}

	// Set branch info for branch-aware finding lifecycle
	if opts.BranchInfo != nil {
		report.Metadata.Branch = opts.BranchInfo
	} else if opts.Branch != "" {
		// Fallback: create minimal BranchInfo from legacy fields
		report.Metadata.Branch = &BranchInfo{
			Name:      opts.Branch,
			CommitSHA: opts.CommitSHA,
		}
	}

	// Build rule lookup
	ruleMap := make(map[string]*SARIFRule)
	for i := range run.Tool.Driver.Rules {
		rule := &run.Tool.Driver.Rules[i]
		ruleMap[rule.ID] = rule
	}

	// Convert results to findings
	findingType := detectFindingType(run.Tool.Driver.Name, opts.ToolType)

	for i, result := range run.Results {
		finding := Finding{
			ID:         fmt.Sprintf("finding-%d", i+1),
			Type:       findingType,
			Title:      result.Message.Text,
			Severity:   mapSARIFLevel(result.Level),
			Confidence: opts.DefaultConfidence,
			RuleID:     result.RuleID,
		}

		// Link to asset
		if opts.AssetValue != "" {
			assetID := opts.AssetID
			if assetID == "" {
				assetID = "asset-1"
			}
			finding.AssetRef = assetID
		}

		// Add rule details
		if rule, ok := ruleMap[result.RuleID]; ok {
			if rule.ShortDescription != nil {
				finding.Description = rule.ShortDescription.Text
			}
			if rule.Name != "" {
				finding.RuleName = rule.Name
			}
			if rule.HelpURI != "" {
				finding.References = append(finding.References, rule.HelpURI)
			}
			// Extract CWE
			if rule.Properties != nil {
				if cwe, ok := rule.Properties["cwe"].(string); ok {
					finding.Vulnerability = &VulnerabilityDetails{CWEID: cwe}
				}
				// Extract precision as confidence
				if precision, ok := rule.Properties["precision"].(string); ok {
					switch precision {
					case "very-high":
						finding.Confidence = 95
					case "high":
						finding.Confidence = 85
					case "medium":
						finding.Confidence = 70
					case "low":
						finding.Confidence = 50
					}
				}
			}
		}

		// Add location
		if len(result.Locations) > 0 && result.Locations[0].PhysicalLocation != nil {
			loc := result.Locations[0].PhysicalLocation
			finding.Location = &FindingLocation{
				Branch:    opts.Branch,
				CommitSHA: opts.CommitSHA,
			}
			if loc.ArtifactLocation != nil {
				finding.Location.Path = loc.ArtifactLocation.URI
			}
			if loc.Region != nil {
				finding.Location.StartLine = loc.Region.StartLine
				finding.Location.EndLine = loc.Region.EndLine
				finding.Location.StartColumn = loc.Region.StartColumn
				finding.Location.EndColumn = loc.Region.EndColumn
				if loc.Region.Snippet != nil {
					finding.Location.Snippet = loc.Region.Snippet.Text
				}
			}
		}

		// Add fingerprint (hash if too long to fit VARCHAR(64))
		for _, fp := range result.Fingerprints {
			if len(fp) > 64 {
				// Hash long fingerprints to fit database constraint
				hash := sha256.Sum256([]byte(fp))
				finding.Fingerprint = hex.EncodeToString(hash[:])
			} else {
				finding.Fingerprint = fp
			}
			break
		}

		report.Findings = append(report.Findings, finding)
	}

	return report, nil
}

// mapSARIFLevel converts SARIF level to CTIS severity.
func mapSARIFLevel(level string) Severity {
	switch strings.ToLower(level) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note":
		return SeverityLow
	case "none":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

// detectFindingType determines finding type based on tool name.
func detectFindingType(toolName string, toolType string) FindingType {
	name := strings.ToLower(toolName)

	// Explicit tool type
	switch toolType {
	case "secret":
		return FindingTypeSecret
	case "iac":
		return FindingTypeMisconfiguration
	case "web3":
		return FindingTypeWeb3
	}

	// Secret scanners
	secretTools := []string{"gitleaks", "trufflehog", "detect-secrets", "secret"}
	for _, t := range secretTools {
		if strings.Contains(name, t) {
			return FindingTypeSecret
		}
	}

	// Web3 scanners
	web3Tools := []string{"slither", "mythril", "securify", "manticore", "echidna", "aderyn"}
	for _, t := range web3Tools {
		if strings.Contains(name, t) {
			return FindingTypeWeb3
		}
	}

	// IaC scanners
	iacTools := []string{"trivy", "checkov", "tfsec", "terrascan", "kics"}
	for _, t := range iacTools {
		if strings.Contains(name, t) {
			return FindingTypeMisconfiguration
		}
	}

	// Default to vulnerability
	return FindingTypeVulnerability
}

// detectCapabilities determines tool capabilities.
func detectCapabilities(toolName string, toolType string) []string {
	name := strings.ToLower(toolName)

	switch toolType {
	case "secret":
		return []string{"secret"}
	case "iac":
		return []string{"misconfiguration"}
	case "web3":
		return []string{"web3"}
	case "sca":
		return []string{"vulnerability"}
	}

	// Auto-detect
	if strings.Contains(name, "secret") || strings.Contains(name, "gitleaks") || strings.Contains(name, "trufflehog") {
		return []string{"secret"}
	}
	if strings.Contains(name, "slither") || strings.Contains(name, "mythril") {
		return []string{"web3"}
	}
	if strings.Contains(name, "trivy") || strings.Contains(name, "checkov") {
		return []string{"vulnerability", "misconfiguration"}
	}

	return []string{"vulnerability", "secret"}
}
