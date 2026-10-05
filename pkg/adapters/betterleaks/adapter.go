package betterleaks

import (
	"context"
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/assetctx"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/sdk-go/pkg/internal/importbridge"
)

// Adapter converts Betterleaks JSON reports to CTIS.
type Adapter struct{}

// NewAdapter creates a new Betterleaks adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return core.ScannerBetterleaks
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	// "gitleaks" is the report format betterleaks v1 kept, so reports
	// named with the old format still convert.
	return []string{"betterleaks", "gitleaks", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var findings []Finding
	if err := json.Unmarshal(input, &findings); err != nil {
		return false
	}
	// The report is a JSON array with RuleID and File fields
	if len(findings) == 0 {
		return false
	}
	return findings[0].RuleID != "" && findings[0].File != ""
}

// Convert transforms betterleaks output to a CTIS report with the one conversion
// entry point, github.com/openctemio/ctis/importer.
//
// Every finding is filed on one repository asset: opts.Repository, else the
// repository of the CI job (GitHub Actions, GitLab CI). Output with findings
// and neither is an error matching ctis.ErrNoAssetForFindings.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	asset, _ := assetctx.AdapterExplicit(opts)
	fallback, _ := assetctx.CI(assetctx.DefaultID)
	req := importbridge.Request{Format: importer.FormatBetterleaks, Tool: a.Name(), Input: input, Asset: asset, Fallback: fallback, NeedsAsset: true}
	if opts != nil {
		req.Scope, req.MinSeverity = opts.Repository, opts.MinSeverity
	}
	return importbridge.Convert(ctx, req)
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// ParseToCTIS is a convenience function to convert betterleaks output to CTIS.
// The findings are filed on the asset opts names (AssetValue/AssetType, else
// BranchInfo.RepositoryURL), else as Adapter.Convert does.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	asset, _ := assetctx.Explicit(opts)
	id := ""
	if opts != nil {
		id = opts.AssetID
	}
	fallback, _ := assetctx.CI(id)
	req := importbridge.Request{Format: importer.FormatBetterleaks, Tool: NewAdapter().Name(), Input: data, Asset: asset, Fallback: fallback, NeedsAsset: true}
	if so := assetctx.ScopeOptions(opts); so != nil {
		req.Scope = so.Repository
	}
	return importbridge.Convert(context.Background(), req)
}
