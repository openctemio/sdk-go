package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// =============================================================================
// Parser Registry - Plugin system for parsers
// =============================================================================

// ParserRegistry manages registered parsers.
type ParserRegistry struct {
	parsers map[string]Parser
	mu      sync.RWMutex
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

// Register adds a parser to the registry.
func (r *ParserRegistry) Register(parser Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers[parser.Name()] = parser
}

// Get returns a parser by name.
func (r *ParserRegistry) Get(name string) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.parsers[name]
}

// FindParser finds a parser that can handle the given data.
func (r *ParserRegistry) FindParser(data []byte) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, parser := range r.parsers {
		if parser.CanParse(data) {
			return parser
		}
	}
	return nil
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

// CanParse checks if this parser can handle the data.
func (p *SARIFParser) CanParse(data []byte) bool {
	// Check for SARIF markers
	if len(data) == 0 {
		return false
	}

	// Quick check for SARIF schema or version
	s := string(data)
	return strings.Contains(s, `"$schema"`) && strings.Contains(s, "sarif") ||
		strings.Contains(s, `"version"`) && strings.Contains(s, `"runs"`)
}

// Parse converts SARIF to CTIS format.
func (p *SARIFParser) Parse(ctx context.Context, data []byte, opts *ParseOptions) (*ctis.Report, error) {
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
		}

		// Link findings to asset
		if opts.AssetID != "" {
			for i := range report.Findings {
				if report.Findings[i].AssetRef == "" {
					report.Findings[i].AssetRef = opts.AssetID
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
