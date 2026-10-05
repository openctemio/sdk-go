// Package semgrep provides an adapter to convert Semgrep JSON output to CTIS.
//
// Deprecated: the converters duplicate ctis.FromSARIF and the parsers the
// sensor ships; no sensor, platform or collector imports them. Emit CTIS
// from a tool (pkg/tool) or convert SARIF with the ctis module. Removal is
// planned for a later minor release (docs/STABILITY.md).
package semgrep

import (
	"context"
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/assetctx"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/sdk-go/pkg/internal/importbridge"
)

// Adapter converts Semgrep JSON output to CTIS.
type Adapter struct{}

// NewAdapter creates a new Semgrep adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "semgrep"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"semgrep", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var output SemgrepOutput
	if err := json.Unmarshal(input, &output); err != nil {
		return false
	}
	// Semgrep always has a "results" key (even if empty array)
	return output.Results != nil
}

// Convert transforms semgrep output to a CTIS report with the one conversion
// entry point, github.com/openctemio/ctis/importer.
//
// Every finding is filed on one repository asset: opts.Repository, else the
// repository of the CI job (GitHub Actions, GitLab CI). Output with results
// and neither is an error matching ctis.ErrNoAssetForFindings.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	asset, _ := assetctx.AdapterExplicit(opts)
	fallback, _ := assetctx.CI(assetctx.DefaultID)
	req := importbridge.Request{Format: importer.FormatSemgrep, Tool: a.Name(), Input: input, Asset: asset, Fallback: fallback, NeedsAsset: true}
	if opts != nil {
		req.Scope, req.MinSeverity = opts.Repository, opts.MinSeverity
	}
	return importbridge.Convert(ctx, req)
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// ParseToCTIS is a convenience function to convert semgrep output to CTIS.
// The findings are filed on the asset opts names (AssetValue/AssetType, else
// BranchInfo.RepositoryURL), else as Adapter.Convert does.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	asset, _ := assetctx.Explicit(opts)
	id := ""
	if opts != nil {
		id = opts.AssetID
	}
	fallback, _ := assetctx.CI(id)
	req := importbridge.Request{Format: importer.FormatSemgrep, Tool: NewAdapter().Name(), Input: data, Asset: asset, Fallback: fallback, NeedsAsset: true}
	if so := assetctx.ScopeOptions(opts); so != nil {
		req.Scope = so.Repository
	}
	return importbridge.Convert(context.Background(), req)
}
