package ctis

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNoAssetForFindings reports findings that do not belong to an asset of
// their own report. Protocol v2 ingest rejects such a finding
// (asset_unresolved): there is no fallback asset on the server, so a
// converter that cannot name the asset its findings belong to must fail
// instead of sending them. Test with errors.Is; CheckFindingAssets returns a
// *FindingAssetError that matches it.
var ErrNoAssetForFindings = errors.New("ctis: findings have no asset in the report")

// maxReportedIndices bounds the finding indices a FindingAssetError keeps.
const maxReportedIndices = 5

// FindingAssetError lists the findings of a report that do not resolve to an
// asset of that report. It carries indices only, never finding content, so
// it is safe to log.
type FindingAssetError struct {
	// Unresolved is the number of findings that do not resolve.
	Unresolved int
	// Total is the number of findings in the report.
	Total int
	// Indices holds the indices (into Report.Findings) of the first few
	// unresolved findings, in order.
	Indices []int
}

// Error implements error.
func (e *FindingAssetError) Error() string {
	idx := make([]string, len(e.Indices))
	for i, n := range e.Indices {
		idx[i] = strconv.Itoa(n)
	}
	more := ""
	if e.Unresolved > len(e.Indices) {
		more = ", ..."
	}
	return fmt.Sprintf("%v: %d of %d finding(s) do not resolve to an asset in the report (finding indices %s%s)",
		ErrNoAssetForFindings, e.Unresolved, e.Total, strings.Join(idx, ", "), more)
}

// Is makes errors.Is(err, ErrNoAssetForFindings) true.
func (e *FindingAssetError) Is(target error) bool {
	return target == ErrNoAssetForFindings
}

// CheckFindingAssets checks that every finding of r resolves to an asset of
// r under the protocol v2 ingest rule:
//
//   - a finding whose AssetRef is set must name the ID of an asset in
//     r.Assets;
//   - a finding with an empty AssetRef resolves only when r has exactly one
//     asset;
//   - the asset it resolves to must have a value, since the server does not
//     store an asset without one.
//
// AssetValue/AssetType on a finding are not a reference: v1 ingest created a
// shared asset from them, v2 does not. It returns nil when every finding
// resolves (or r is nil or has no findings), and a *FindingAssetError
// otherwise.
func CheckFindingAssets(r *Report) error {
	if r == nil || len(r.Findings) == 0 {
		return nil
	}

	byID := make(map[string]*Asset, len(r.Assets))
	for i := range r.Assets {
		if id := r.Assets[i].ID; id != "" {
			if _, dup := byID[id]; !dup {
				byID[id] = &r.Assets[i]
			}
		}
	}

	var e *FindingAssetError
	for i := range r.Findings {
		var asset *Asset
		switch ref := r.Findings[i].AssetRef; {
		case ref != "":
			asset = byID[ref]
		case len(r.Assets) == 1:
			asset = &r.Assets[0]
		}
		if asset != nil && strings.TrimSpace(asset.Value) != "" {
			continue
		}
		if e == nil {
			e = &FindingAssetError{Total: len(r.Findings)}
		}
		e.Unresolved++
		if len(e.Indices) < maxReportedIndices {
			e.Indices = append(e.Indices, i)
		}
	}
	if e != nil {
		return e
	}
	return nil
}
