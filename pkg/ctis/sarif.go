package ctis

import (
	"encoding/json"
	"fmt"
	"strings"

	upstream "github.com/openctemio/ctis"
)

// SARIFLog is the root SARIF document. It is the module's SARIFLog with the
// SDK's SARIFRun, which also reads versionControlProvenance.
type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun is a single run of a tool: the module's SARIFRun plus
// VersionControlProvenance. The nested SARIF types are the module's.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Artifacts   []SARIFArtifact   `json:"artifacts,omitempty"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`

	// VersionControlProvenance names the repository and revision the run
	// analyzed (SARIF 2.1.0 §3.14.17). GitHub code scanning and CodeQL
	// emit it.
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

// repository returns the first repository named in any run.
func (l *SARIFLog) repository() (uri, revision, branch string) {
	for i := range l.Runs {
		if uri, revision, branch = l.Runs[i].Repository(); uri != "" {
			return uri, revision, branch
		}
	}
	return "", "", ""
}

func (l *SARIFLog) results() int {
	n := 0
	for i := range l.Runs {
		n += len(l.Runs[i].Results)
	}
	return n
}

// FromSARIF converts a SARIF 2.1.0 log to a CTIS report with
// github.com/openctemio/ctis FromSARIF, after choosing the asset every
// finding belongs to:
//
//  1. opts.AssetValue (opts.AssetType, default repository);
//  2. else opts.BranchInfo.RepositoryURL (a repository);
//  3. else the first repository the log names in versionControlProvenance
//     (properties: source, commit_sha, branch).
//
// There is no fallback asset: a log with results and none of these is an
// error matching ErrNoAssetForFindings. The asset gets no criticality: that
// is the receiver's call (CTIS spec 4.1).
func FromSARIF(data []byte, opts *ConvertOptions) (*Report, error) {
	if opts == nil {
		opts = DefaultConvertOptions()
	}
	var view SARIFLog
	if err := json.Unmarshal(data, &view); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}

	o := *opts
	var props Properties
	switch {
	case strings.TrimSpace(o.AssetValue) != "":
		if o.AssetType == "" {
			o.AssetType = AssetTypeRepository
		}
	case o.BranchInfo != nil && strings.TrimSpace(o.BranchInfo.RepositoryURL) != "":
		o.AssetValue = o.BranchInfo.RepositoryURL
		o.AssetType = AssetTypeRepository
	default:
		if uri, revision, branch := view.repository(); uri != "" {
			o.AssetValue = uri
			o.AssetType = AssetTypeRepository
			props = Properties{"source": "sarif_version_control_provenance"}
			if revision != "" {
				props["commit_sha"] = revision
			}
			if branch != "" {
				props["branch"] = branch
			}
		}
	}
	if strings.TrimSpace(o.AssetValue) == "" {
		if n := view.results(); n > 0 {
			return nil, fmt.Errorf("%w: SARIF log from %q has %d result(s) but names no repository: "+
				"set the asset (AssetValue or BranchInfo.RepositoryURL) or add versionControlProvenance",
				ErrNoAssetForFindings, view.Runs[0].Tool.Driver.Name, n)
		}
	}

	report, err := upstream.FromSARIF(data, &o)
	if err != nil {
		return nil, err
	}
	if props != nil && len(report.Assets) > 0 {
		report.Assets[0].Properties = props
	}
	return report, nil
}

// NormalizeSARIFKind maps a SARIF result.kind onto CTIS finding.kind: SARIF
// spells "notApplicable" in camelCase where CTIS uses "not_applicable";
// matching ignores case and underscores. Unknown values return "" (leave
// unset), so an absent kind is not defaulted to SARIF's implicit "fail".
func NormalizeSARIFKind(kind string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(kind), "_", "")) {
	case "notapplicable":
		return "not_applicable"
	case "pass":
		return "pass"
	case "fail":
		return "fail"
	case "review":
		return "review"
	case "open":
		return "open"
	case "informational":
		return "informational"
	default:
		return ""
	}
}

// NormalizeSARIFBaselineState maps a SARIF result.baselineState onto CTIS
// finding.baseline_state (the same four values, matched case-insensitively).
// Unknown values return "" (leave unset).
func NormalizeSARIFBaselineState(state string) string {
	switch s := strings.ToLower(strings.TrimSpace(state)); s {
	case "new", "unchanged", "updated", "absent":
		return s
	default:
		return ""
	}
}
