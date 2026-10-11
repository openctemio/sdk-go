package core

import "github.com/openctemio/sdk-go/pkg/adapt"

// Result metadata keys of a scan's coverage gaps (RFC-074 in
// openctemio/openctem api/docs/rfcs): the platform shows them on the run
// and keeps the step partial.
const (
	// MetaCoverageGaps is the list of hosts not fully covered
	// ([]adapt.Gap: host, reason breaker_open | rate_floor | blocked,
	// detail), at most adapt.TargetRate.MaxGaps entries.
	MetaCoverageGaps = "coverage_gaps"
	// MetaCoverageGapsTotal is how many hosts were not fully covered.
	MetaCoverageGapsTotal = "coverage_gaps_total"
	// MetaTargetRate is the per-host rate summary (adapt.Summary without
	// its gap list).
	MetaTargetRate = "target_rate"
)

// HasCoverageGaps reports whether the scan left hosts not fully covered.
func (r *ScanResult) HasCoverageGaps() bool {
	return r != nil && (len(r.CoverageGaps) > 0 || r.CoverageGapsTotal > 0)
}

// CoverageGapsMetadata returns the result metadata for r's coverage gaps
// and rate summary (nil when there is neither).
func CoverageGapsMetadata(r *ScanResult) map[string]any {
	if r == nil {
		return nil
	}
	meta := map[string]any{}
	if r.HasCoverageGaps() {
		gaps := r.CoverageGaps
		if len(gaps) > adapt.TargetRate.MaxGaps {
			gaps = gaps[:adapt.TargetRate.MaxGaps]
		}
		meta[MetaCoverageGaps] = append([]adapt.Gap(nil), gaps...)
		meta[MetaCoverageGapsTotal] = max(r.CoverageGapsTotal, len(r.CoverageGaps))
	}
	if r.TargetRate != nil {
		s := *r.TargetRate
		s.Gaps, s.GapsTotal = nil, 0
		meta[MetaTargetRate] = s
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

// WithTargetRate sets r's rate summary and adds its gaps to r's coverage
// gaps (nil s: no change).
func (r *ScanResult) WithTargetRate(s *adapt.Summary) {
	if r == nil || s == nil {
		return
	}
	r.TargetRate = s
	r.AddCoverageGaps(s.Gaps, s.GapsTotal)
}

// AddCoverageGaps adds gaps (total counting also those not listed) to r,
// once per host.
func (r *ScanResult) AddCoverageGaps(gaps []adapt.Gap, total int) {
	if r == nil {
		return
	}
	prev := max(r.CoverageGapsTotal, len(r.CoverageGaps))
	seen := make(map[string]bool, len(r.CoverageGaps))
	for _, g := range r.CoverageGaps {
		seen[g.Host] = true
	}
	dups := 0
	for _, g := range gaps {
		if g.Host == "" || seen[g.Host] {
			dups++
			continue
		}
		seen[g.Host] = true
		if len(r.CoverageGaps) < adapt.TargetRate.MaxGaps {
			r.CoverageGaps = append(r.CoverageGaps, g)
		}
	}
	r.CoverageGapsTotal = prev + max(total, len(gaps)) - dups
}
