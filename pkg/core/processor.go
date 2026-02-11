package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// BaseProcessor provides a default implementation of the Processor interface.
type BaseProcessor struct {
	pusher  Pusher
	parsers *ParserRegistry
	verbose bool
}

// NewBaseProcessor creates a new processor.
func NewBaseProcessor(pusher Pusher) *BaseProcessor {
	return &BaseProcessor{
		pusher:  pusher,
		parsers: NewParserRegistry(),
	}
}

// Process runs a complete scan workflow: scan -> parse -> push.
func (p *BaseProcessor) Process(ctx context.Context, scanner Scanner, opts *ProcessOptions) (*ProcessResult, error) {
	result := &ProcessResult{
		ScannerName: scanner.Name(),
	}

	if opts == nil {
		opts = &ProcessOptions{}
	}

	// Get target from options
	target := ""
	if opts.ScanOptions != nil {
		target = opts.ScanOptions.TargetDir
	}

	if p.verbose {
		fmt.Printf("[processor] Processing scanner %s on %s\n", scanner.Name(), target)
	}

	// Step 1: Scan
	scanResult, err := scanner.Scan(ctx, target, opts.ScanOptions)
	result.ScanResult = scanResult
	if err != nil {
		result.Error = fmt.Sprintf("scan failed: %v", err)
		return result, err
	}

	if p.verbose {
		fmt.Printf("[processor] Scan completed in %dms\n", scanResult.DurationMs)
	}

	// Step 2: Parse
	parser := p.parsers.FindParser(scanResult.RawOutput)
	if parser == nil {
		parser = p.parsers.Get("sarif") // Default to SARIF
	}

	if parser == nil {
		err := fmt.Errorf("no suitable parser found")
		result.Error = err.Error()
		return result, err
	}

	report, err := parser.Parse(ctx, scanResult.RawOutput, opts.ParseOptions)
	if err != nil {
		result.Error = fmt.Sprintf("parse failed: %v", err)
		return result, err
	}
	result.Report = report

	if p.verbose {
		fmt.Printf("[processor] Parsed %d findings\n", len(report.Findings))
	}

	// Step 3: Save locally if requested
	if opts.SaveLocal {
		localFile, err := p.saveLocal(report, scanner.Name(), opts.OutputDir)
		if err != nil {
			if p.verbose {
				fmt.Printf("[processor] Failed to save locally: %v\n", err)
			}
		} else {
			result.LocalFile = localFile
			if p.verbose {
				fmt.Printf("[processor] Saved to %s\n", localFile)
			}
		}
	}

	// Step 4: Push if requested
	if opts.Push && p.pusher != nil && len(report.Findings) > 0 {
		pushResult, err := p.pushWithRetry(ctx, report, opts.MaxRetries, opts.RetryDelay)
		if err != nil {
			result.Error = fmt.Sprintf("push failed: %v", err)
			return result, err
		}
		result.PushResult = pushResult

		if p.verbose {
			fmt.Printf("[processor] Pushed %d findings (%d created, %d updated)\n",
				len(report.Findings), pushResult.FindingsCreated, pushResult.FindingsUpdated)
		}
	}

	return result, nil
}

// ProcessBatch runs multiple scanners in parallel.
func (p *BaseProcessor) ProcessBatch(ctx context.Context, scanners []Scanner, opts *ProcessOptions) ([]*ProcessResult, error) {
	results := make([]*ProcessResult, len(scanners))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for i, scanner := range scanners {
		wg.Add(1)
		go func(idx int, s Scanner) {
			defer wg.Done()

			result, err := p.Process(ctx, s, opts)

			mu.Lock()
			results[idx] = result
			if err != nil && firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}(i, scanner)
	}

	wg.Wait()

	return results, firstErr
}

// saveLocal saves the report to a local file.
func (p *BaseProcessor) saveLocal(report *ctis.Report, scannerName, outputDir string) (string, error) {
	if outputDir == "" {
		outputDir = "."
	}

	// Create output directory if needed
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	// Generate filename
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s-%s.json", scannerName, timestamp)
	filepath := filepath.Join(outputDir, filename)

	// Write report
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}

	return filepath, nil
}

// pushWithRetry pushes findings with retry logic.
func (p *BaseProcessor) pushWithRetry(ctx context.Context, report *ctis.Report, maxRetries, retryDelaySec int) (*PushResult, error) {
	if maxRetries == 0 {
		maxRetries = 3
	}
	if retryDelaySec == 0 {
		retryDelaySec = 2
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(retryDelaySec) * time.Second * time.Duration(1<<(attempt-1))
			if p.verbose {
				fmt.Printf("[processor] Retrying push (attempt %d/%d) after %v\n", attempt, maxRetries, backoff)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, err := p.pusher.PushFindings(ctx, report)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("push failed after %d retries: %w", maxRetries, lastErr)
}

// SetVerbose sets verbose mode.
func (p *BaseProcessor) SetVerbose(v bool) {
	p.verbose = v
}

// AddParser adds a custom parser.
func (p *BaseProcessor) AddParser(parser Parser) {
	p.parsers.Register(parser)
}

// Ensure BaseProcessor implements Processor
var _ Processor = (*BaseProcessor)(nil)
