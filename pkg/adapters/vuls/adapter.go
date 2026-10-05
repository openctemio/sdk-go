package vuls

import (
	"context"
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/assetctx"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/sdk-go/pkg/internal/importbridge"
)

// Adapter converts Vuls JSON output to CTIS.
type Adapter struct{}

// NewAdapter creates a new Vuls adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "vuls"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"vuls", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var report VulsReport
	if err := json.Unmarshal(input, &report); err != nil {
		return false
	}
	return report.ServerName != "" && report.ScannedCves != nil
}

// Convert transforms vuls output to a CTIS report with the one conversion
// entry point, github.com/openctemio/ctis/importer.
//
// The scanned server is the asset every finding belongs to.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	req := importbridge.Request{Format: importer.FormatVuls, Tool: a.Name(), Input: input}
	if opts != nil {
		req.Scope, req.MinSeverity = opts.Repository, opts.MinSeverity
	}
	return importbridge.Convert(ctx, req)
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// ParseToCTIS is a convenience function to convert vuls output to CTIS.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	var ao *core.AdapterOptions
	if so := assetctx.ScopeOptions(opts); so != nil {
		ao = so
	}
	return NewAdapter().Convert(context.Background(), data, ao)
}
