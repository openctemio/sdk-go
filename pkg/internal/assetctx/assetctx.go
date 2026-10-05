// Package assetctx gives the SDK's converters the asset their findings belong
// to. Protocol v2 ingest accepts a finding only when it resolves to an asset
// of its own report (ctis.CheckFindingAssets), and there is no fallback asset
// on the server, so every converter names one or fails with
// ctis.ErrNoAssetForFindings.
package assetctx

import (
	"fmt"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/cirepo"
)

// DefaultID is the asset ID a single-asset report uses when the caller does
// not choose one.
const DefaultID = "asset-1"

// Explicit returns the asset the caller named in opts: AssetValue (typed
// AssetType, a repository when unset), else BranchInfo.RepositoryURL. It
// returns false when opts names none.
func Explicit(opts *core.ParseOptions) (ctis.Asset, bool) {
	if opts == nil {
		return ctis.Asset{}, false
	}
	id := opts.AssetID
	if id == "" {
		id = DefaultID
	}

	if v := strings.TrimSpace(opts.AssetValue); v != "" {
		t := opts.AssetType
		if t == "" {
			t = ctis.AssetTypeRepository
		}
		return ctis.Asset{
			ID:          id,
			Type:        t,
			Value:       opts.AssetValue,
			Name:        opts.AssetValue,
			Criticality: ctis.CriticalityHigh,
			Properties:  ctis.Properties{"source": "parse_options"},
		}, true
	}

	if bi := opts.BranchInfo; bi != nil && strings.TrimSpace(bi.RepositoryURL) != "" {
		props := ctis.Properties{
			"source":            "branch_info",
			"auto_created":      true,
			"is_default_branch": bi.IsDefaultBranch,
		}
		if bi.CommitSHA != "" {
			props["commit_sha"] = bi.CommitSHA
		}
		if bi.Name != "" {
			props["branch"] = bi.Name
		}
		return ctis.Asset{
			ID:          id,
			Type:        ctis.AssetTypeRepository,
			Value:       bi.RepositoryURL,
			Name:        bi.RepositoryURL,
			Criticality: ctis.CriticalityHigh,
			Properties:  props,
		}, true
	}
	return ctis.Asset{}, false
}

// CI returns the repository the CI job (GitHub Actions, GitLab CI) is
// building as an asset with the given ID (DefaultID when empty), and false
// outside CI.
func CI(id string) (ctis.Asset, bool) {
	repo, ok := cirepo.Detect()
	if !ok {
		return ctis.Asset{}, false
	}
	return repoAsset(id, repo.URL, repo.Branch, repo.Commit, "ci_environment"), true
}

// ScopeOptions maps ParseOptions to the AdapterOptions an adapter reads
// besides the asset (the report scope name), for the adapters' ParseToCTIS.
func ScopeOptions(opts *core.ParseOptions) *core.AdapterOptions {
	if opts == nil {
		return nil
	}
	ao := &core.AdapterOptions{Repository: opts.AssetValue}
	if opts.BranchInfo != nil && opts.BranchInfo.RepositoryURL != "" {
		ao.Repository = opts.BranchInfo.RepositoryURL
	}
	return ao
}

// AdapterExplicit returns the repository the Repository option names (with
// Branch and CommitSHA), and false when it is empty.
func AdapterExplicit(opts *core.AdapterOptions) (ctis.Asset, bool) {
	if opts != nil && strings.TrimSpace(opts.Repository) != "" {
		return repoAsset(DefaultID, opts.Repository, opts.Branch, opts.CommitSHA, "adapter_options"), true
	}
	return ctis.Asset{}, false
}

func repoAsset(id, value, branch, commit, source string) ctis.Asset {
	if id == "" {
		id = DefaultID
	}
	props := ctis.Properties{"source": source}
	if branch != "" {
		props["branch"] = branch
	}
	if commit != "" {
		props["commit_sha"] = commit
	}
	return ctis.Asset{
		ID:          id,
		Type:        ctis.AssetTypeRepository,
		Value:       value,
		Name:        value,
		Criticality: ctis.CriticalityHigh,
		Properties:  props,
	}
}

// Bind adds a to r and points every finding of r at it. Use it for
// converters whose findings all belong to one asset (a repository, an
// image, a host).
func Bind(r *ctis.Report, a ctis.Asset) {
	if a.ID == "" {
		a.ID = DefaultID
	}
	r.Assets = append(r.Assets, a)
	for i := range r.Findings {
		r.Findings[i].AssetRef = a.ID
	}
}

// NoRepository is the error a code converter returns when it has findings
// but no repository to file them on.
func NoRepository(tool string, findings int) error {
	return fmt.Errorf("%w: %s reported %d finding(s) but no repository is known: "+
		"pass the scanned repository (ParseOptions.AssetValue or BranchInfo.RepositoryURL) "+
		"or run inside GitHub Actions / GitLab CI", ctis.ErrNoAssetForFindings, tool, findings)
}
