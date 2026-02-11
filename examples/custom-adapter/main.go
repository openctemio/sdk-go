// Example: Using the SARIF Adapter
//
// This example demonstrates how to use the SARIF adapter to convert
// SARIF output from any security tool to CTIS format.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/openctemio/sdk-go/pkg/adapters/sarif"
	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
)

func main() {
	ctx := context.Background()

	// Read SARIF file
	sarifData, err := os.ReadFile("results.sarif")
	if err != nil {
		fmt.Printf("Failed to read SARIF file: %v\n", err)
		os.Exit(1)
	}

	// Create SARIF adapter
	adapter := sarif.NewAdapter()

	// Check if input is valid SARIF
	if !adapter.CanConvert(sarifData) {
		fmt.Println("Input is not valid SARIF format")
		os.Exit(1)
	}

	// Convert to CTIS
	report, err := adapter.Convert(ctx, sarifData, &core.AdapterOptions{
		SourceName:  "custom-scanner",
		Repository:  "owner/repo",
		MinSeverity: "medium", // Filter out low/info findings
	})
	if err != nil {
		fmt.Printf("Failed to convert SARIF: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	fmt.Printf("Tool: %s v%s\n", report.Tool.Name, report.Tool.Version)
	fmt.Printf("Findings: %d\n\n", len(report.Findings))

	// Print findings by severity
	severityCounts := map[string]int{}
	for _, finding := range report.Findings {
		severityCounts[string(finding.Severity)]++
	}

	fmt.Println("By Severity:")
	for severity, count := range severityCounts {
		fmt.Printf("  %s: %d\n", severity, count)
	}

	// Print findings with data flow (taint tracking)
	fmt.Println("\nFindings with data flow:")
	for _, finding := range report.Findings {
		if finding.DataFlow != nil && len(finding.DataFlow.Sources) > 0 {
			fmt.Printf("  - %s\n", finding.Title)
			fmt.Printf("    Source: %s:%d\n",
				finding.DataFlow.Sources[0].Path,
				finding.DataFlow.Sources[0].Line,
			)
			if len(finding.DataFlow.Sinks) > 0 {
				fmt.Printf("    Sink: %s:%d\n",
					finding.DataFlow.Sinks[0].Path,
					finding.DataFlow.Sinks[0].Line,
				)
			}
		}
	}

	// Push to OpenCTEM platform
	if os.Getenv("API_URL") != "" {
		apiClient := client.New(&client.Config{
			BaseURL: os.Getenv("API_URL"),
			APIKey:  os.Getenv("API_KEY"),
			AgentID: os.Getenv("AGENT_ID"),
		})

		result, err := apiClient.PushFindings(ctx, report)
		if err != nil {
			fmt.Printf("Failed to push findings: %v\n", err)
		} else {
			fmt.Printf("\n✓ Pushed: %d created, %d updated\n",
				result.FindingsCreated,
				result.FindingsUpdated,
			)
		}
	}
}
