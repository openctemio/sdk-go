package chunk

import (
	"encoding/json"
	"sort"

	"github.com/google/uuid"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Splitter handles report chunking logic.
type Splitter struct {
	cfg *Config
}

// NewSplitter creates a new splitter with the given config.
func NewSplitter(cfg *Config) *Splitter {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Splitter{cfg: cfg}
}

// NeedsChunking determines if a report should be chunked.
func (s *Splitter) NeedsChunking(report *ctis.Report) bool {
	if len(report.Findings) >= s.cfg.MinFindingsForChunking {
		return true
	}
	if len(report.Assets) >= s.cfg.MinAssetsForChunking {
		return true
	}

	// Check raw size
	data, err := json.Marshal(report)
	if err == nil && len(data) >= s.cfg.MinSizeForChunking {
		return true
	}

	return false
}

// Split divides a report into chunks.
//
// Algorithm:
//  1. If report is small enough, return single chunk
//  2. Group findings by their asset_ref
//  3. Create chunks that respect both findings and assets limits
//  4. Every chunk is self-describing: it carries the report's tool and
//     metadata, and every asset its findings reference
//
// The platform ingests each chunk as a report of its own. A chunk without the
// tool was attributed to tool "unknown", and a finding whose asset was sent in
// an earlier chunk landed on a placeholder "scan:unknown:<report>" asset. So
// the tool and metadata are repeated in every chunk, and an asset whose
// findings span several chunks is repeated in each of them.
func (s *Splitter) Split(report *ctis.Report) ([]*ChunkData, error) {
	reportID := s.getReportID(report)

	if !s.NeedsChunking(report) {
		// Single chunk - just wrap the whole report
		return []*ChunkData{{
			ReportID:    reportID,
			ChunkIndex:  0,
			TotalChunks: 1,
			Tool:        report.Tool,
			Metadata:    &report.Metadata,
			Assets:      report.Assets,
			Findings:    report.Findings,
			IsFinal:     true,
		}}, nil
	}

	chunks := make([]*ChunkData, 0)

	// Build asset reference map: assetRef -> asset
	assetMap := make(map[string]*ctis.Asset)
	assetOrder := make([]string, 0, len(report.Assets))
	for i := range report.Assets {
		a := &report.Assets[i]
		if _, dup := assetMap[a.ID]; !dup {
			assetOrder = append(assetOrder, a.ID)
		}
		assetMap[a.ID] = a
	}

	// Group findings by asset reference
	findingsByAsset := make(map[string][]ctis.Finding)
	orphanFindings := make([]ctis.Finding, 0) // Findings without asset_ref

	for _, f := range report.Findings {
		if f.AssetRef != "" {
			findingsByAsset[f.AssetRef] = append(findingsByAsset[f.AssetRef], f)
		} else {
			orphanFindings = append(orphanFindings, f)
		}
	}

	// Sort asset refs for deterministic chunking
	assetRefs := make([]string, 0, len(findingsByAsset))
	for ref := range findingsByAsset {
		assetRefs = append(assetRefs, ref)
	}
	sort.Strings(assetRefs)

	// Create chunks
	chunkIndex := 0
	currentAssets := make([]ctis.Asset, 0, s.cfg.MaxAssetsPerChunk)
	currentFindings := make([]ctis.Finding, 0, s.cfg.MaxFindingsPerChunk)
	inChunk := make(map[string]bool)     // assets already in the current chunk
	addedAssets := make(map[string]bool) // assets sent in any chunk
	// partial marks a chunk holding only part of one asset's findings. The
	// platform auto-resolves an asset's findings that a full-coverage report
	// does not contain, so such a chunk must not claim full coverage: it
	// would resolve the findings still to come in the next chunk.
	partial := false

	flushChunk := func(isFinal bool) {
		if len(currentAssets) == 0 && len(currentFindings) == 0 {
			return
		}

		chunk := &ChunkData{
			ReportID:   reportID,
			ChunkIndex: chunkIndex,
			Tool:       report.Tool,
			Metadata:   chunkMetadata(&report.Metadata, partial),
			Assets:     currentAssets,
			Findings:   currentFindings,
			IsFinal:    isFinal,
		}

		chunks = append(chunks, chunk)
		chunkIndex++

		// Reset for next chunk
		currentAssets = make([]ctis.Asset, 0, s.cfg.MaxAssetsPerChunk)
		currentFindings = make([]ctis.Finding, 0, s.cfg.MaxFindingsPerChunk)
		inChunk = make(map[string]bool)
		partial = false
	}

	// addAsset puts the referenced asset into the current chunk once.
	addAsset := func(ref string) {
		asset, ok := assetMap[ref]
		if !ok || inChunk[ref] {
			return
		}
		currentAssets = append(currentAssets, *asset)
		inChunk[ref] = true
		addedAssets[ref] = true
	}

	// Process findings grouped by asset
	for _, assetRef := range assetRefs {
		findings := findingsByAsset[assetRef]
		_, hasAsset := assetMap[assetRef]

		// One asset with more findings than a chunk holds: give it chunks of
		// its own, the asset repeated in each.
		if len(findings) > s.cfg.MaxFindingsPerChunk {
			flushChunk(false)
			for i := 0; i < len(findings); i += s.cfg.MaxFindingsPerChunk {
				end := min(i+s.cfg.MaxFindingsPerChunk, len(findings))
				addAsset(assetRef)
				currentFindings = append(currentFindings, findings[i:end]...)
				if end < len(findings) {
					partial = true
					flushChunk(false)
				}
			}
			continue
		}

		needsNewChunk := len(currentFindings)+len(findings) > s.cfg.MaxFindingsPerChunk ||
			(hasAsset && !inChunk[assetRef] && len(currentAssets) >= s.cfg.MaxAssetsPerChunk)
		if needsNewChunk {
			flushChunk(false)
		}

		addAsset(assetRef)
		currentFindings = append(currentFindings, findings...)
	}

	// Handle orphan findings (findings without asset_ref)
	for _, f := range orphanFindings {
		if len(currentFindings) >= s.cfg.MaxFindingsPerChunk {
			flushChunk(false)
		}
		currentFindings = append(currentFindings, f)
	}

	// Add any assets that weren't referenced by findings
	for _, id := range assetOrder {
		if !addedAssets[id] {
			if len(currentAssets) >= s.cfg.MaxAssetsPerChunk {
				flushChunk(false)
			}
			addAsset(id)
		}
	}

	// Flush remaining
	flushChunk(true)

	// Update total chunks count in all chunks
	totalChunks := len(chunks)
	for _, c := range chunks {
		c.TotalChunks = totalChunks
	}

	// Mark last chunk as final
	if len(chunks) > 0 {
		chunks[len(chunks)-1].IsFinal = true
	}

	return chunks, nil
}

// coverageFull is the ctis coverage_type value that enables auto-resolve.
const coverageFull = "full"

// chunkMetadata returns the metadata a chunk carries: the report's own, or —
// for a chunk holding only part of one asset's findings — a copy that does
// not claim full coverage (see Split).
func chunkMetadata(md *ctis.ReportMetadata, partial bool) *ctis.ReportMetadata {
	if !partial || md.CoverageType != coverageFull {
		return md
	}
	cp := *md
	cp.CoverageType = "partial"
	return &cp
}

// getReportID extracts or generates a report ID.
func (s *Splitter) getReportID(report *ctis.Report) string {
	if report.Metadata.ID != "" {
		return report.Metadata.ID
	}
	return uuid.New().String()
}

// EstimateChunks estimates the number of chunks without actually splitting.
func (s *Splitter) EstimateChunks(findingsCount, assetsCount int) int {
	// If below all thresholds, no chunking needed
	if findingsCount < s.cfg.MinFindingsForChunking && assetsCount < s.cfg.MinAssetsForChunking {
		return 1
	}

	// Calculate chunks based on which threshold was exceeded
	findingChunks := 1
	if findingsCount >= s.cfg.MinFindingsForChunking {
		findingChunks = (findingsCount + s.cfg.MaxFindingsPerChunk - 1) / s.cfg.MaxFindingsPerChunk
	}

	assetChunks := 1
	if assetsCount >= s.cfg.MinAssetsForChunking {
		assetChunks = (assetsCount + s.cfg.MaxAssetsPerChunk - 1) / s.cfg.MaxAssetsPerChunk
	}

	// Return the larger of the two
	if findingChunks > assetChunks {
		return findingChunks
	}
	return assetChunks
}
