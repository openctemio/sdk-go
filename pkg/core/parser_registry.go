package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/internal/cirepo"
)

// =============================================================================
// Parser Registry - Plugin system for parsers
// =============================================================================

// ParserRegistry manages registered parsers.
type ParserRegistry struct {
	parsers map[string]Parser
	// order is the registration order. FindParser probes in this order so
	// detection is deterministic: iterating the map directly picked a
	// different parser from run to run when two parsers accepted the data.
	order []string
	mu    sync.RWMutex
}

// NewParserRegistry creates a new parser registry with built-in parsers.
func NewParserRegistry() *ParserRegistry {
	registry := &ParserRegistry{
		parsers: make(map[string]Parser),
	}

	// Register built-in parsers
	registry.Register(&SARIFParser{})
	registry.Register(&JSONParser{})

	return registry
}

// Register adds a parser to the registry. Registering a name again replaces
// that parser and keeps its original position.
func (r *ParserRegistry) Register(parser Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := parser.Name()
	if _, exists := r.parsers[name]; !exists {
		r.order = append(r.order, name)
	}
	r.parsers[name] = parser
}

// Get returns a parser by name.
func (r *ParserRegistry) Get(name string) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.parsers[name]
}

// FindParser finds a parser that can handle the given data. Parsers are
// probed in registration order, after the generic SARIF and JSON parsers
// that NewParserRegistry registers, so a tool-specific parser registered
// later wins only when the generic formats do not match.
func (r *ParserRegistry) FindParser(data []byte) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, name := range r.order {
		if parser := r.parsers[name]; parser.CanParse(data) {
			return parser
		}
	}
	return nil
}

// ForScanner returns the parser for a scanner's raw output, or an error when
// no parser recognizes it.
//
// Selection order: the parser registered under the scanner's own name (when it
// accepts the data), then content detection, then nothing. Output that no
// parser recognizes is an error, never "0 findings": a scanner whose results
// cannot be read must fail its command, or real findings vanish while the scan
// reports success. Callers decide what empty output means before calling.
func (r *ParserRegistry) ForScanner(scannerName string, data []byte) (Parser, error) {
	if r != nil {
		if p := r.Get(scannerName); p != nil && p.CanParse(data) {
			return p, nil
		}
		if p := r.FindParser(data); p != nil {
			return p, nil
		}
	} else if sarif := (&SARIFParser{}); sarif.CanParse(data) {
		return sarif, nil
	}
	return nil, fmt.Errorf("no parser recognizes the output of scanner %q (%d bytes); register a parser for it",
		scannerName, len(data))
}

// List returns all registered parser names.
func (r *ParserRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.parsers))
	for name := range r.parsers {
		names = append(names, name)
	}
	return names
}

// =============================================================================
// SARIF Parser - Built-in parser for SARIF format
// =============================================================================

// SARIFParser parses SARIF format output.
type SARIFParser struct{}

// Name returns the parser name.
func (p *SARIFParser) Name() string {
	return "sarif"
}

// SupportedFormats returns supported formats.
func (p *SARIFParser) SupportedFormats() []string {
	return []string{"sarif", "sarif-2.1.0"}
}

// CanParse checks if this parser can handle the data: a single JSON object
// with a "runs" array, the one member every SARIF log must have. Substring
// checks are not enough: a JSON Lines stream (nuclei) whose response bodies
// mention "version" and "runs" passed them, and was then read as an empty
// SARIF log.
func (p *SARIFParser) CanParse(data []byte) bool {
	return isSARIFLog(data)
}

// isSARIFLog reports whether data is one JSON object with a "runs" array.
func isSARIFLog(data []byte) bool {
	var probe struct {
		Runs json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	runs := strings.TrimSpace(string(probe.Runs))
	return strings.HasPrefix(runs, "[")
}

// Parse converts SARIF to CTIS format. Data that is not a SARIF log is an
// error: decoding arbitrary JSON into the SARIF structure succeeds with no
// runs, which used to turn a scanner's real results into "0 findings".
func (p *SARIFParser) Parse(ctx context.Context, data []byte, opts *ParseOptions) (*ctis.Report, error) {
	if !isSARIFLog(data) {
		return nil, fmt.Errorf("not a SARIF log: expected a JSON object with a \"runs\" array")
	}
	if opts == nil {
		opts = &ParseOptions{
			DefaultConfidence: 90,
		}
	}

	// Use the CTIS package's SARIF converter
	convertOpts := &ctis.ConvertOptions{
		AssetType:         opts.AssetType,
		AssetValue:        opts.AssetValue,
		AssetID:           opts.AssetID,
		Branch:            opts.Branch,
		CommitSHA:         opts.CommitSHA,
		BranchInfo:        opts.BranchInfo,
		DefaultConfidence: opts.DefaultConfidence,
		ToolType:          opts.ToolType,
	}

	report, err := ctis.FromSARIF(data, convertOpts)
	if !errors.Is(err, ctis.ErrNoAssetForFindings) {
		return report, err
	}
	// Neither the options nor the log name the repository: use the one the
	// CI job is building, or fail. Never a shared placeholder asset.
	repo, ok := cirepo.Detect()
	if !ok {
		return nil, err
	}
	convertOpts.AssetType = ctis.AssetTypeRepository
	convertOpts.AssetValue = repo.URL
	if convertOpts.Branch == "" {
		convertOpts.Branch = repo.Branch
	}
	if convertOpts.CommitSHA == "" {
		convertOpts.CommitSHA = repo.Commit
	}
	return ctis.FromSARIF(data, convertOpts)
}

// =============================================================================
// JSON Parser - Generic JSON parser
// =============================================================================

// JSONParser parses generic JSON output that follows CTIS schema.
type JSONParser struct{}

// Name returns the parser name.
func (p *JSONParser) Name() string {
	return "json"
}

// SupportedFormats returns supported formats.
func (p *JSONParser) SupportedFormats() []string {
	return []string{"json", "ctis"}
}

// CanParse checks if this parser can handle the data.
func (p *JSONParser) CanParse(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check if it's valid JSON and has CTIS markers
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}

	// Check for CTIS format markers
	_, hasVersion := raw["version"]
	_, hasFindings := raw["findings"]
	_, hasMetadata := raw["metadata"]

	return hasVersion && (hasFindings || hasMetadata)
}

// Parse converts JSON to CTIS format.
func (p *JSONParser) Parse(ctx context.Context, data []byte, opts *ParseOptions) (*ctis.Report, error) {
	var report ctis.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	// Apply options
	if opts != nil {
		linkTo := opts.AssetID
		if opts.AssetValue != "" && len(report.Assets) == 0 {
			assetID := opts.AssetID
			if assetID == "" {
				assetID = "asset-1"
			}
			report.Assets = append(report.Assets, ctis.Asset{
				ID:    assetID,
				Type:  opts.AssetType,
				Value: opts.AssetValue,
			})
			linkTo = assetID
		}

		// Link findings without an asset reference to the asset. The
		// asset-1 created above used to be left unreferenced when AssetID
		// was empty.
		if linkTo != "" {
			for i := range report.Findings {
				if report.Findings[i].AssetRef == "" {
					report.Findings[i].AssetRef = linkTo
				}
			}
		}
	}

	return &report, nil
}

// =============================================================================
// Base Parser - For custom parser implementations
// =============================================================================

// BaseParser provides a base implementation for custom parsers.
// Embed this in your custom parser for common functionality.
type BaseParser struct {
	name             string
	supportedFormats []string
}

// NewBaseParser creates a new base parser.
func NewBaseParser(name string, formats []string) *BaseParser {
	return &BaseParser{
		name:             name,
		supportedFormats: formats,
	}
}

// Name returns the parser name.
func (p *BaseParser) Name() string {
	return p.name
}

// SupportedFormats returns supported formats.
func (p *BaseParser) SupportedFormats() []string {
	return p.supportedFormats
}

// CanParse default implementation - override in your parser.
func (p *BaseParser) CanParse(data []byte) bool {
	return false
}

// Parse default implementation - override in your parser.
func (p *BaseParser) Parse(ctx context.Context, data []byte, opts *ParseOptions) (*ctis.Report, error) {
	return nil, fmt.Errorf("Parse not implemented - override this method in your parser")
}

// CreateFinding is a helper to create a finding with common fields set.
func (p *BaseParser) CreateFinding(id, title string, severity ctis.Severity) ctis.Finding {
	return ctis.Finding{
		ID:       id,
		Type:     ctis.FindingTypeVulnerability,
		Title:    title,
		Severity: severity,
	}
}

// CreateReport is a helper to create a new report.
func (p *BaseParser) CreateReport(toolName, toolVersion string) *ctis.Report {
	report := ctis.NewReport()
	report.Tool = &ctis.Tool{
		Name:    toolName,
		Version: toolVersion,
	}
	return report
}
