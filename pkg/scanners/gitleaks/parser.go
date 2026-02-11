package gitleaks

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Parser converts gitleaks output to CTIS format.
type Parser struct{}

// Name returns the parser name.
func (p *Parser) Name() string {
	return "gitleaks"
}

// SupportedFormats returns the output formats this parser can handle.
func (p *Parser) SupportedFormats() []string {
	return []string{"json"}
}

// CanParse checks if the parser can handle the given data.
func (p *Parser) CanParse(data []byte) bool {
	// Try to parse as gitleaks JSON
	_, err := ParseJSONBytes(data)
	return err == nil
}

// Parse converts gitleaks JSON output to CTIS report.
func (p *Parser) Parse(ctx context.Context, data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	// Parse gitleaks findings
	findings, err := ParseJSONBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	// Create CTIS report
	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Metadata.Timestamp = time.Now()

	// Set tool info
	report.Tool = &ctis.Tool{
		Name:   "gitleaks",
		Vendor: "Gitleaks",
		Capabilities: []string{
			"secret_detection",
			"api_key_detection",
			"password_detection",
			"private_key_detection",
			"git_history_scan",
		},
	}

	// Set branch info from options (critical for asset auto-creation in ingest)
	if opts != nil && opts.BranchInfo != nil {
		report.Metadata.Branch = opts.BranchInfo
	} else if opts != nil && (opts.Branch != "" || opts.CommitSHA != "") {
		// Legacy: create BranchInfo from individual fields
		report.Metadata.Branch = &ctis.BranchInfo{
			Name:      opts.Branch,
			CommitSHA: opts.CommitSHA,
		}
	}

	// Add asset from options or branch info
	if asset := p.createAssetFromOptions(opts); asset != nil {
		report.Assets = append(report.Assets, *asset)
	}

	// Convert findings
	for i, f := range findings {
		risFinding := p.convertFinding(f, i, opts)
		report.Findings = append(report.Findings, risFinding)
	}

	return report, nil
}

// convertFinding converts a gitleaks finding to CTIS finding.
func (p *Parser) convertFinding(f Finding, index int, opts *core.ParseOptions) ctis.Finding {
	title := fmt.Sprintf("%s detected in %s:%d", f.Description, f.File, f.StartLine)
	finding := ctis.Finding{
		ID:         fmt.Sprintf("finding-%d", index+1),
		Type:       ctis.FindingTypeSecret,
		Title:      title,
		Message:    title,             // Primary display text
		Severity:   ctis.SeverityHigh, // Secrets are always high severity
		Confidence: 90,
		Category:   "Hardcoded Secret",
		RuleID:     f.RuleID,
		RuleName:   f.Description,
		// Description: detailed explanation of the secret type and its risks
		Description: fmt.Sprintf("A %s was detected in the source code. Hardcoded secrets pose a significant security risk as they can be easily extracted from the codebase and used maliciously.", f.Description),
	}

	// Generate or use fingerprint
	if f.Fingerprint != "" {
		finding.Fingerprint = f.Fingerprint
	} else {
		finding.Fingerprint = core.GenerateSecretFingerprint(f.File, f.RuleID, f.StartLine, f.Secret)
	}

	// Set location
	finding.Location = &ctis.FindingLocation{
		Path:        f.File,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
		Snippet:     f.Match,
	}

	// Add branch/commit if available
	if opts != nil {
		if opts.Branch != "" {
			finding.Location.Branch = opts.Branch
		}
		if opts.CommitSHA != "" {
			finding.Location.CommitSHA = opts.CommitSHA
		}
	}

	// If commit from gitleaks is available, use it
	if f.Commit != "" {
		finding.Location.CommitSHA = f.Commit
	}

	// Set git metadata from gitleaks
	if f.Author != "" {
		finding.Author = f.Author
	}
	if f.Email != "" {
		finding.AuthorEmail = f.Email
	}
	if f.Date != "" {
		// Try to parse date in various formats
		for _, layout := range []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05 -0700",
			"Mon Jan 2 15:04:05 2006 -0700",
		} {
			if t, err := time.Parse(layout, f.Date); err == nil {
				finding.CommitDate = &t
				break
			}
		}
	}

	// Store commit message in properties for reference
	if f.Message != "" {
		if finding.Properties == nil {
			finding.Properties = make(map[string]any)
		}
		finding.Properties["commit_message"] = f.Message
	}

	// Set secret details
	finding.Secret = &ctis.SecretDetails{
		SecretType:  GetSecretType(f.RuleID),
		Service:     GetServiceName(f.RuleID),
		MaskedValue: core.MaskSecret(f.Secret),
		Length:      len(f.Secret),
		Entropy:     f.Entropy,
	}

	// Link to asset (from AssetValue or BranchInfo)
	if opts != nil {
		assetID := opts.AssetID
		if assetID == "" {
			assetID = "asset-1"
		}
		// Link if we have asset info (either explicit or from branch info)
		if opts.AssetValue != "" || (opts.BranchInfo != nil && opts.BranchInfo.RepositoryURL != "") {
			finding.AssetRef = assetID
		}
	}

	// Add default confidence
	if opts != nil && opts.DefaultConfidence > 0 {
		finding.Confidence = opts.DefaultConfidence
	}

	// Add remediation guidance
	finding.Remediation = &ctis.Remediation{
		Recommendation: fmt.Sprintf("Remove the %s from the codebase and rotate/revoke it immediately.", GetSecretType(f.RuleID)),
		Steps: []string{
			"1. Revoke the exposed secret immediately",
			"2. Generate a new secret/credential",
			"3. Update the secret in a secure vault (e.g., HashiCorp Vault, AWS Secrets Manager)",
			"4. Remove the secret from the codebase and git history if necessary",
			"5. Add the file pattern to .gitignore to prevent future commits",
		},
		Effort:       "low",
		FixAvailable: true,
	}

	// Add references
	finding.References = []string{
		"https://github.com/gitleaks/gitleaks",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
	}

	// Add tags
	finding.Tags = []string{
		"secret",
		GetSecretType(f.RuleID),
		GetServiceName(f.RuleID),
	}

	return finding
}

// createAssetFromOptions creates an asset from parse options or branch info.
// Priority: opts.AssetValue > opts.BranchInfo.RepositoryURL
func (p *Parser) createAssetFromOptions(opts *core.ParseOptions) *ctis.Asset {
	if opts == nil {
		return nil
	}

	assetID := opts.AssetID
	if assetID == "" {
		assetID = "asset-1"
	}

	// Priority 1: Explicit AssetValue
	if opts.AssetValue != "" {
		assetType := opts.AssetType
		if assetType == "" {
			assetType = ctis.AssetTypeRepository
		}
		return &ctis.Asset{
			ID:          assetID,
			Type:        assetType,
			Value:       opts.AssetValue,
			Name:        opts.AssetValue,
			Criticality: ctis.CriticalityHigh,
			Properties: ctis.Properties{
				"source": "parse_options",
			},
		}
	}

	// Priority 2: BranchInfo.RepositoryURL
	if opts.BranchInfo != nil && opts.BranchInfo.RepositoryURL != "" {
		props := ctis.Properties{
			"source":       "branch_info",
			"auto_created": true,
		}
		if opts.BranchInfo.CommitSHA != "" {
			props["commit_sha"] = opts.BranchInfo.CommitSHA
		}
		if opts.BranchInfo.Name != "" {
			props["branch"] = opts.BranchInfo.Name
		}
		props["is_default_branch"] = opts.BranchInfo.IsDefaultBranch

		return &ctis.Asset{
			ID:          assetID,
			Type:        ctis.AssetTypeRepository,
			Value:       opts.BranchInfo.RepositoryURL,
			Name:        opts.BranchInfo.RepositoryURL,
			Criticality: ctis.CriticalityHigh,
			Properties:  props,
		}
	}

	return nil
}

// ParseToCTIS is a convenience function to parse gitleaks JSON to CTIS.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	parser := &Parser{}
	return parser.Parse(context.Background(), data, opts)
}
