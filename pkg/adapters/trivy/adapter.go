// Package trivy provides an adapter to convert Trivy JSON output to CTIS.
//
// Deprecated: the converters duplicate ctis.FromSARIF and the parsers the
// sensor ships; no sensor, platform or collector imports them. Emit CTIS
// from a tool (pkg/tool) or convert SARIF with the ctis module. Removal is
// planned for a later minor release (docs/STABILITY.md).
package trivy

import (
	"context"
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/assetctx"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/sdk-go/pkg/internal/importbridge"
)

// Adapter converts Trivy JSON output to CTIS.
type Adapter struct{}

// NewAdapter creates a new Trivy adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "trivy"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"trivy", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var report TrivyReport
	if err := json.Unmarshal(input, &report); err != nil {
		return false
	}
	return report.SchemaVersion > 0 && len(report.Results) > 0
}

// Convert transforms trivy output to a CTIS report with the one conversion
// entry point, github.com/openctemio/ctis/importer.
//
// Every finding is filed on one asset: opts.Repository, else the artifact
// Trivy scanned when it is an asset by itself (the image of an image scan,
// the remote repository of a repo scan), else the repository of the CI job
// (GitHub Actions, GitLab CI). A filesystem scan with findings and none of
// them is an error matching ctis.ErrNoAssetForFindings.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	asset, _ := assetctx.AdapterExplicit(opts)
	fallback, _ := assetctx.CI(assetctx.DefaultID)
	req := importbridge.Request{Format: importer.FormatTrivy, Tool: a.Name(), Input: input, Asset: asset, Fallback: fallback, NeedsAsset: true}
	if opts != nil {
		req.Scope, req.MinSeverity = opts.Repository, opts.MinSeverity
	}
	return importbridge.Convert(ctx, req)
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// ParseToCTIS is a convenience function to convert trivy output to CTIS.
// The findings are filed on the asset opts names (AssetValue/AssetType, else
// BranchInfo.RepositoryURL), else as Adapter.Convert does.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	asset, _ := assetctx.Explicit(opts)
	id := ""
	if opts != nil {
		id = opts.AssetID
	}
	fallback, _ := assetctx.CI(id)
	req := importbridge.Request{Format: importer.FormatTrivy, Tool: NewAdapter().Name(), Input: data, Asset: asset, Fallback: fallback, NeedsAsset: true}
	if so := assetctx.ScopeOptions(opts); so != nil {
		req.Scope = so.Repository
	}
	return importbridge.Convert(context.Background(), req)
}
