// Package nuclei provides an adapter to convert Nuclei JSONL output to CTIS.
//
// Deprecated: the converters duplicate core.SARIFParser and the parsers the
// sensor ships; no sensor, platform or collector imports them. Emit CTIS
// from a tool (pkg/tool) or convert SARIF with the ctis module. Removal is
// planned for a later minor release (docs/STABILITY.md).
package nuclei

import (
	"context"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/assetctx"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/sdk-go/pkg/internal/importbridge"
)

// Adapter converts Nuclei JSONL output to CTIS.
type Adapter struct{}

// NewAdapter creates a new Nuclei adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "nuclei"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"nuclei", "jsonl", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	return importbridge.Detect(input, importer.FormatNuclei)
}

// Convert transforms nuclei output to a CTIS report with the one conversion
// entry point, github.com/openctemio/ctis/importer.
//
// Each finding is filed on the host it matched: one asset per distinct host.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	req := importbridge.Request{Format: importer.FormatNuclei, Tool: a.Name(), Input: input, Unreadable: true}
	if opts != nil {
		req.Scope, req.MinSeverity = opts.Repository, opts.MinSeverity
	}
	return importbridge.Convert(ctx, req)
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// ParseToCTIS is a convenience function to convert nuclei output to CTIS.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	var ao *core.AdapterOptions
	if so := assetctx.ScopeOptions(opts); so != nil {
		ao = so
	}
	return NewAdapter().Convert(context.Background(), data, ao)
}
