package chunk

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// SegmentLimits bound one protocol v2 segment (RFC-026 §3.5, §3.6). The v2
// client derives them from the server's hello limits.
type SegmentLimits struct {
	// MaxFindings and MaxAssets per segment.
	MaxFindings int
	MaxAssets   int
	// MaxBytes is the target size of a segment's JSON before compression.
	// A single finding larger than this still gets a segment of its own.
	MaxBytes int
}

// BindFindingAssets makes every finding's asset explicit, so a report can be
// split without changing which asset a finding belongs to:
//
//   - an asset without an id gets one ("asset-<index>"), so it can be
//     referenced;
//   - a finding without asset_ref is bound to the report's only asset when
//     there is exactly one (the server applies the same rule to a whole
//     document, RFC-026 §10.1, but a segment may carry several assets).
//
// It returns how many findings still resolve to no asset in the report
// (empty asset_ref with several or no assets, or a reference to an unknown
// id). The server rejects those findings; they are never bound to a guess.
// It modifies r.
func BindFindingAssets(r *ctis.Report) (unresolved int) {
	ids := make(map[string]bool, len(r.Assets))
	for i := range r.Assets {
		if r.Assets[i].ID == "" {
			r.Assets[i].ID = uniqueAssetID(ids, i)
		}
		ids[r.Assets[i].ID] = true
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		switch {
		case f.AssetRef != "" && ids[f.AssetRef]:
		case f.AssetRef == "" && len(r.Assets) == 1:
			f.AssetRef = r.Assets[0].ID
		default:
			unresolved++
		}
	}
	return unresolved
}

func uniqueAssetID(ids map[string]bool, i int) string {
	for n := i; ; n++ {
		id := "asset-" + strconv.Itoa(n)
		if !ids[id] {
			return id
		}
	}
}

// SplitSegments splits a report into protocol v2 segments. Every segment is a
// complete CTIS document: the same version, schema, metadata and tool as the
// report (the server checks they are identical), the findings of that
// segment and every asset those findings reference. An asset referenced by
// findings in several segments is repeated in each (the ingest merge is
// idempotent). Assets no finding references are packed into segments of
// their own. Dependencies and report properties go into the first segment.
//
// Findings that resolve to no asset (see BindFindingAssets) are put in
// segments that carry no asset, so they are rejected by the server rather
// than bound to whichever single asset a segment happens to hold.
//
// Call BindFindingAssets first. One segment is returned when the report fits
// the limits; it is r itself.
func SplitSegments(r *ctis.Report, lim SegmentLimits) ([]*ctis.Report, error) {
	if r == nil {
		return nil, fmt.Errorf("chunk: nil report")
	}
	if lim.MaxFindings <= 0 || lim.MaxAssets <= 0 || lim.MaxBytes <= 0 {
		return nil, fmt.Errorf("chunk: segment limits must be positive: %+v", lim)
	}
	whole, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("chunk: marshal report: %w", err)
	}
	if len(r.Findings) <= lim.MaxFindings && len(r.Assets) <= lim.MaxAssets && len(whole) <= lim.MaxBytes {
		return []*ctis.Report{r}, nil
	}
	pk, err := newPacker(r, lim)
	if err != nil {
		return nil, err
	}
	if err := pk.pack(); err != nil {
		return nil, err
	}
	return pk.documents(), nil
}

// findingGroup is the findings of one asset (asset -1: unresolved).
type findingGroup struct {
	asset    int
	findings []int
}

// seg is one segment being packed: indices into the report.
type seg struct {
	assets   []int
	hasAsset map[int]bool
	findings []int
	bytes    int
}

// packer distributes a report's findings and assets over segments.
type packer struct {
	r         *ctis.Report
	lim       SegmentLimits
	header    ctis.Report
	base      int
	assetSize []int
	groups    []*findingGroup
	byAsset   map[int]*findingGroup
	segs      []*seg
	cur       *seg
}

func newPacker(r *ctis.Report, lim SegmentLimits) (*packer, error) {
	pk := &packer{r: r, lim: lim, header: *r, byAsset: map[int]*findingGroup{}}
	pk.header.Assets, pk.header.Findings, pk.header.Dependencies, pk.header.Properties = nil, nil, nil, nil
	headerBytes, err := json.Marshal(&pk.header)
	if err != nil {
		return nil, fmt.Errorf("chunk: marshal header: %w", err)
	}
	pk.base = len(headerBytes) + 64 // array brackets and keys

	assetIdx := make(map[string]int, len(r.Assets))
	pk.assetSize = make([]int, len(r.Assets))
	for i := range r.Assets {
		if id := r.Assets[i].ID; id != "" {
			if _, dup := assetIdx[id]; !dup {
				assetIdx[id] = i
			}
		}
		b, err := json.Marshal(&r.Assets[i])
		if err != nil {
			return nil, fmt.Errorf("chunk: marshal asset %d: %w", i, err)
		}
		pk.assetSize[i] = len(b) + 1
	}
	// Group findings by asset, in order of first appearance.
	for i := range r.Findings {
		a := -1
		if idx, ok := assetIdx[r.Findings[i].AssetRef]; ok {
			a = idx
		}
		g := pk.byAsset[a]
		if g == nil {
			g = &findingGroup{asset: a}
			pk.byAsset[a] = g
			pk.groups = append(pk.groups, g)
		}
		g.findings = append(g.findings, i)
	}
	pk.cur = pk.newSeg()
	return pk, nil
}

func (pk *packer) newSeg() *seg { return &seg{hasAsset: map[int]bool{}, bytes: pk.base} }

func (pk *packer) flush() {
	if len(pk.cur.assets) > 0 || len(pk.cur.findings) > 0 {
		pk.segs = append(pk.segs, pk.cur)
	}
	pk.cur = pk.newSeg()
}

func (pk *packer) addAsset(a int) {
	if a >= 0 && !pk.cur.hasAsset[a] {
		pk.cur.hasAsset[a] = true
		pk.cur.assets = append(pk.cur.assets, a)
		pk.cur.bytes += pk.assetSize[a]
	}
}

// addFinding adds finding fi of asset a (-1: none), starting a new segment
// (carrying the asset again) when the current one is full.
func (pk *packer) addFinding(fi, a int) error {
	b, err := json.Marshal(&pk.r.Findings[fi])
	if err != nil {
		return fmt.Errorf("chunk: marshal finding %d: %w", fi, err)
	}
	sz := len(b) + 1
	if len(pk.cur.findings) > 0 && (len(pk.cur.findings) >= pk.lim.MaxFindings || pk.cur.bytes+sz > pk.lim.MaxBytes) {
		pk.flush()
		pk.addAsset(a)
	}
	pk.cur.findings = append(pk.cur.findings, fi)
	pk.cur.bytes += sz
	return nil
}

func (pk *packer) pack() error {
	// Unresolved findings first, in asset-less segments.
	if g := pk.byAsset[-1]; g != nil {
		for _, fi := range g.findings {
			if err := pk.addFinding(fi, -1); err != nil {
				return err
			}
		}
		pk.flush()
	}
	for _, g := range pk.groups {
		if g.asset < 0 {
			continue
		}
		// Start a new segment when this asset cannot join the current one.
		if !pk.cur.hasAsset[g.asset] && (len(pk.cur.assets) >= pk.lim.MaxAssets || pk.cur.bytes+pk.assetSize[g.asset] > pk.lim.MaxBytes) {
			pk.flush()
		}
		pk.addAsset(g.asset)
		for _, fi := range g.findings {
			if err := pk.addFinding(fi, g.asset); err != nil {
				return err
			}
		}
	}
	// Assets no finding references.
	for i := range pk.r.Assets {
		if _, referenced := pk.byAsset[i]; referenced {
			continue
		}
		if len(pk.cur.assets) > 0 && (len(pk.cur.assets) >= pk.lim.MaxAssets || pk.cur.bytes+pk.assetSize[i] > pk.lim.MaxBytes) {
			pk.flush()
		}
		pk.addAsset(i)
	}
	pk.flush()
	if len(pk.segs) == 0 {
		pk.segs = append(pk.segs, pk.newSeg())
	}
	return nil
}

// documents builds the CTIS documents of the packed segments.
func (pk *packer) documents() []*ctis.Report {
	out := make([]*ctis.Report, len(pk.segs))
	for si, s := range pk.segs {
		doc := pk.header
		if len(s.assets) > 0 {
			doc.Assets = make([]ctis.Asset, len(s.assets))
			for j, a := range s.assets {
				doc.Assets[j] = pk.r.Assets[a]
			}
		}
		if len(s.findings) > 0 {
			doc.Findings = make([]ctis.Finding, len(s.findings))
			for j, fi := range s.findings {
				doc.Findings[j] = pk.r.Findings[fi]
			}
		}
		if si == 0 {
			doc.Dependencies = pk.r.Dependencies
			doc.Properties = pk.r.Properties
		}
		out[si] = &doc
	}
	return out
}
