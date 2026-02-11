// Example: Testing semgrep scanner
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/scanners"
	"github.com/openctemio/sdk-go/pkg/scanners/semgrep"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create semgrep scanner with default config
	scanner := scanners.Semgrep()
	scanner.Verbose = true

	// Check if installed
	installed, version, err := scanner.IsInstalled(ctx)
	if err != nil {
		fmt.Printf("Error checking semgrep: %v\n", err)
		os.Exit(1)
	}
	if !installed {
		fmt.Println("Semgrep is not installed. Install with: pip install semgrep")
		os.Exit(1)
	}
	fmt.Printf("✓ Semgrep version: %s\n", version)

	// Get target directory (current directory or argument)
	target := "."
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	fmt.Printf("✓ Target: %s\n", target)

	// Run scan
	fmt.Println("\n--- Running Semgrep Scan ---")
	result, err := scanner.Scan(ctx, target, &core.ScanOptions{
		Verbose: true,
	})
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ Scan completed in %dms\n", result.DurationMs)
	fmt.Printf("✓ Exit code: %d\n", result.ExitCode)

	// Parse to SAST result
	sastResult, err := semgrep.ParseToSastResult(result.RawOutput)
	if err != nil {
		fmt.Printf("Failed to parse results: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Found %d findings\n", len(sastResult.Findings))

	// Print findings
	if len(sastResult.Findings) > 0 {
		fmt.Println("\n--- Findings ---")
		for i, f := range sastResult.Findings {
			fmt.Printf("\n[%d] %s\n", i+1, f.Title)
			fmt.Printf("    Severity: %s | Confidence: %d%%\n", f.Severity, f.Confidence)
			fmt.Printf("    File: %s:%d-%d\n", f.File, f.StartLine, f.EndLine)
			fmt.Printf("    Rule: %s\n", f.RuleID)
			if f.Description != "" {
				fmt.Printf("    Description: %s\n", truncate(f.Description, 100))
			}
			if len(f.CWEs) > 0 {
				fmt.Printf("    CWEs: %v\n", f.CWEs)
			}
			if len(f.DataFlow) > 0 {
				fmt.Printf("    Data Flow (%d steps):\n", len(f.DataFlow))
				for _, step := range f.DataFlow {
					fmt.Printf("      [%s] %s:%d - %s\n", step.StepType, step.File, step.Line, truncate(step.Content, 50))
				}
			}
		}
	}

	// Parse to CTIS format
	fmt.Println("\n--- Converting to CTIS ---")
	parser := &semgrep.Parser{}
	ctisReport, err := parser.Parse(ctx, result.RawOutput, &core.ParseOptions{
		AssetType:  "repository",
		AssetValue: target,
		Branch:     "main",
	})
	if err != nil {
		fmt.Printf("Failed to convert to CTIS: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ CTIS Report generated\n")
	fmt.Printf("  - Tool: %s v%s\n", ctisReport.Tool.Name, ctisReport.Tool.Version)
	fmt.Printf("  - Findings: %d\n", len(ctisReport.Findings))
	fmt.Printf("  - Assets: %d\n", len(ctisReport.Assets))

	// Print first finding as JSON sample
	if len(ctisReport.Findings) > 0 {
		fmt.Println("\n--- Sample CTIS Finding (JSON) ---")
		sample, _ := json.MarshalIndent(ctisReport.Findings[0], "", "  ")
		fmt.Println(string(sample))
	}

	fmt.Println("\n✓ Test completed successfully!")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
