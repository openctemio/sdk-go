// Package importbridge runs the deprecated tool adapters (pkg/adapters) on
// the one conversion entry point, github.com/openctemio/ctis/importer, so
// the SDK, the platform and the sensor convert a tool's output the same way
// and under the same hostile-input limits.
//
// The adapters keep their asset rules: a code report is filed on the
// repository the caller names (or the CI job's repository), else on the one
// the file names, and with neither a report with findings is an error
// matching ctis.ErrNoAssetForFindings, never a made-up asset.
package importbridge

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/assetctx"
)

// noAsset is the default asset the importer falls back to when neither the
// caller nor the file names one; seeing it in the result means "no asset".
const noAsset = "\x00no-asset"

// Request is one conversion.
type Request struct {
	Format importer.Format
	Tool   string // the adapter's name, for error messages
	Input  []byte
	// The asset the caller named (Asset.Value empty: none). A repository is
	// passed to the importer, which then never takes another one from the
	// file; any other type replaces the asset of every finding.
	Asset ctis.Asset
	// The asset used when neither the caller nor the file names one (the
	// CI job's repository).
	Fallback ctis.Asset
	// Code reports need an asset; host-per-finding reports (nuclei, vuls)
	// name their own.
	NeedsAsset bool
	// Scope names the report scope (metadata.scope.name), when set.
	Scope       string
	MinSeverity string
	// Unreadable: input whose every record was unreadable is an error, as
	// the adapter always returned (a line-per-record format skips bad
	// records with an issue instead).
	Unreadable bool
}

// Convert runs the request through the importer.
func Convert(ctx context.Context, req Request) (*ctis.Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts := importer.Options{
		Format:      req.Format,
		SourceType:  "scanner",
		MinSeverity: ctis.Severity(strings.ToLower(strings.TrimSpace(req.MinSeverity))),
	}
	explicit := strings.TrimSpace(req.Asset.Value) != ""
	if req.NeedsAsset {
		if explicit && req.Asset.Type == ctis.AssetTypeRepository {
			opts.Repository = req.Asset.Value
			opts.Branch, _ = req.Asset.Properties["branch"].(string)
			opts.CommitSHA, _ = req.Asset.Properties["commit_sha"].(string)
		}
		opts.DefaultAsset = &ctis.Asset{ID: noAsset, Type: ctis.AssetTypeUnclassified, Value: noAsset}
	}
	res, err := importer.Parse(ctx, bytes.NewReader(req.Input), opts)
	if err != nil {
		return nil, err
	}
	r := res.Report
	if req.Unreadable && len(r.Findings) == 0 && len(res.Issues) > 0 && res.Stats.Skipped >= res.Stats.Records {
		return nil, fmt.Errorf("parse %s: %s", req.Tool, res.Issues[0].String())
	}
	if req.NeedsAsset {
		usedDefault := false
		for _, a := range r.Assets {
			if a.ID == noAsset {
				usedDefault = true
			}
		}
		switch {
		case explicit && req.Asset.Type != ctis.AssetTypeRepository:
			a := req.Asset
			if a.ID == "" {
				a.ID = assetctx.DefaultID
			}
			r.Assets = r.Assets[:0]
			assetctx.Bind(r, a)
		case usedDefault && strings.TrimSpace(req.Fallback.Value) != "":
			a := req.Fallback
			if a.ID == "" {
				a.ID = assetctx.DefaultID
			}
			r.Assets = r.Assets[:0]
			assetctx.Bind(r, a)
		case usedDefault:
			if len(r.Findings) > 0 {
				return nil, assetctx.NoRepository(req.Tool, len(r.Findings))
			}
			r.Assets = nil
		}
	}
	if req.Scope != "" && r.Metadata.Scope == nil {
		r.Metadata.Scope = &ctis.Scope{Name: req.Scope}
	}
	return r, nil
}

// Detect reports whether input is the format (the importer's detection).
func Detect(input []byte, f importer.Format) bool {
	got, ok := importer.Detect(input)
	return ok && got == f
}
