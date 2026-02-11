// Example: Using the GitHub Provider
//
// This example demonstrates how to use the GitHubProvider to collect
// repository information, code scanning alerts, and Dependabot alerts.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/providers/github"
)

func main() {
	ctx := context.Background()

	// Create GitHub provider
	provider := github.NewProvider(&github.Config{
		Token:        os.Getenv("GITHUB_TOKEN"),
		Organization: os.Getenv("GITHUB_ORG"), // Optional: scope to organization
		RateLimit:    5000,                    // requests per hour
		Verbose:      true,
	})

	// Test connection
	if err := provider.TestConnection(ctx); err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Connected to GitHub")

	// List available collectors
	fmt.Println("\nAvailable collectors:")
	for _, collector := range provider.ListCollectors() {
		fmt.Printf("  - %s (%s)\n", collector.Name(), collector.Type())
	}

	// Collect repositories
	repoCollector, _ := provider.GetCollector("repos")
	result, err := repoCollector.Collect(ctx, &core.CollectOptions{
		PageSize: 10,
		MaxPages: 1,
	})
	if err != nil {
		fmt.Printf("Failed to collect repos: %v\n", err)
	} else {
		fmt.Printf("\n✓ Collected %d repositories\n", result.TotalItems)
		for _, report := range result.Reports {
			for _, asset := range report.Assets {
				fmt.Printf("  - %s\n", asset.Value)
			}
		}
	}

	// Collect code scanning alerts for a specific repo
	csCollector, _ := provider.GetCollector("code-scanning")
	csResult, err := csCollector.Collect(ctx, &core.CollectOptions{
		Repository: "owner/repo", // Replace with actual repo
	})
	if err != nil {
		fmt.Printf("Failed to collect code scanning alerts: %v\n", err)
	} else {
		fmt.Printf("\n✓ Collected %d code scanning alerts\n", csResult.TotalItems)
		for _, report := range csResult.Reports {
			for _, finding := range report.Findings {
				fmt.Printf("  - [%s] %s (%s:%d)\n",
					finding.Severity,
					finding.Title,
					finding.Location.Path,
					finding.Location.StartLine,
				)
			}
		}
	}

	// Push results to OpenCTEM platform
	if os.Getenv("API_URL") != "" {
		apiClient := client.New(&client.Config{
			BaseURL: os.Getenv("API_URL"),
			APIKey:  os.Getenv("API_KEY"),
			AgentID: os.Getenv("AGENT_ID"),
		})

		for _, report := range result.Reports {
			pushResult, err := apiClient.PushAssets(ctx, report)
			if err != nil {
				fmt.Printf("Failed to push assets: %v\n", err)
			} else {
				fmt.Printf("✓ Pushed %d assets\n", pushResult.AssetsCreated+pushResult.AssetsUpdated)
			}
		}
	}

	// Clean up
	provider.Close()
}
