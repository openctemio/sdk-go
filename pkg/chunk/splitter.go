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
// 1. If report is small enough, return single chunk
// 2. Group findings by their asset_ref
// 3. Create chunks that respect both findings and assets limits
// 4. First chunk always includes tool and metadata
// 5. Each chunk is self-contained with its assets and findings
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
	for i := range report.Assets {
		a := &report.Assets[i]
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
	addedAssets := make(map[string]bool) // Track which assets we've added

	flushChunk := func(isFinal bool) {
		if len(currentAssets) == 0 && len(currentFindings) == 0 {
			return
		}

		chunk := &ChunkData{
			ReportID:   reportID,
			ChunkIndex: chunkIndex,
			Assets:     currentAssets,
			Findings:   currentFindings,
			IsFinal:    isFinal,
		}

		// First chunk includes tool and metadata
		if chunkIndex == 0 {
			chunk.Tool = report.Tool
			chunk.Metadata = &report.Metadata
		}

		chunks = append(chunks, chunk)
		chunkIndex++

		// Reset for next chunk
		currentAssets = make([]ctis.Asset, 0, s.cfg.MaxAssetsPerChunk)
		currentFindings = make([]ctis.Finding, 0, s.cfg.MaxFindingsPerChunk)
	}

	// Process findings grouped by asset
	for _, assetRef := range assetRefs {
		findings := findingsByAsset[assetRef]

		// Get the asset if exists and not already added
		asset, hasAsset := assetMap[assetRef]
		needsAsset := hasAsset && !addedAssets[assetRef]

		// Check if we need to start a new chunk
		needsNewChunk := false
		if needsAsset && len(currentAssets) >= s.cfg.MaxAssetsPerChunk {
			needsNewChunk = true
		}
		if len(currentFindings)+len(findings) > s.cfg.MaxFindingsPerChunk {
			// If findings for this asset exceed chunk limit, we need special handling
			if len(findings) > s.cfg.MaxFindingsPerChunk {
				// Split findings across multiple chunks
				for i := 0; i < len(findings); i += s.cfg.MaxFindingsPerChunk {
					if len(currentFindings) > 0 || len(currentAssets) > 0 {
						flushChunk(false)
					}

					end := i + s.cfg.MaxFindingsPerChunk
					if end > len(findings) {
						end = len(findings)
					}

					// Add asset to first chunk of this batch if needed
					if needsAsset && i == 0 {
						currentAssets = append(currentAssets, *asset)
						addedAssets[assetRef] = true
					}

					currentFindings = append(currentFindings, findings[i:end]...)
				}
				continue
			}
			needsNewChunk = true
		}

		if needsNewChunk && (len(currentAssets) > 0 || len(currentFindings) > 0) {
			flushChunk(false)
		}

		// Add asset if not already added
		if needsAsset {
			currentAssets = append(currentAssets, *asset)
			addedAssets[assetRef] = true
		}

		// Add findings
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
	for id, asset := range assetMap {
		if !addedAssets[id] {
			if len(currentAssets) >= s.cfg.MaxAssetsPerChunk {
				flushChunk(false)
			}
			currentAssets = append(currentAssets, *asset)
			addedAssets[id] = true
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
