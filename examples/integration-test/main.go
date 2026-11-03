// Package main provides an integration test example for the OpenCTEM SDK.
// This example demonstrates how to:
// 1. Connect to the OpenCTEM API
// 2. Send heartbeat
// 3. Push findings and assets
// 4. Poll for commands
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

func main() {
	// Parse command line flags
	baseURL := flag.String("url", "http://localhost:8080", "OpenCTEM API base URL")
	apiKey := flag.String("api-key", "", "API key for authentication")
	sensorID := flag.String("sensor-id", "", "Sensor ID (optional)")
	verbose := flag.Bool("verbose", true, "Enable verbose output")
	flag.Parse()

	// Check required flags
	if *apiKey == "" {
		// Try to get from environment
		*apiKey = os.Getenv("SENSOR_API_KEY")
		if *apiKey == "" {
			log.Fatal("API key is required. Use -api-key flag or API_KEY environment variable")
		}
	}

	// Create client
	cfg := &client.Config{
		BaseURL:    *baseURL,
		APIKey:     *apiKey,
		SensorID:   *sensorID,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 2 * time.Second,
		Verbose:    *verbose,
	}

	c := client.New(cfg)
	ctx := context.Background()

	fmt.Println("=== OpenCTEM SDK Integration Test ===")
	fmt.Printf("Base URL: %s\n", *baseURL)
	fmt.Println()

	// Test 1: Connection test (heartbeat)
	fmt.Println("1. Testing connection (heartbeat)...")
	if err := testHeartbeat(ctx, c); err != nil {
		log.Printf("   ✗ Heartbeat failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Heartbeat successful")
	}
	fmt.Println()

	// Test 2: Push findings
	fmt.Println("2. Testing push findings...")
	if err := testPushFindings(ctx, c); err != nil {
		log.Printf("   ✗ Push findings failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Push findings successful")
	}
	fmt.Println()

	// Test 3: Push assets
	fmt.Println("3. Testing push assets...")
	if err := testPushAssets(ctx, c); err != nil {
		log.Printf("   ✗ Push assets failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Push assets successful")
	}
	fmt.Println()

	// Test 4: Push combined (findings + assets)
	fmt.Println("4. Testing push combined report...")
	if err := testPushCombined(ctx, c); err != nil {
		log.Printf("   ✗ Push combined failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Push combined successful")
	}
	fmt.Println()

	// Test 5: Poll commands
	fmt.Println("5. Testing poll commands...")
	if err := testPollCommands(ctx, c); err != nil {
		log.Printf("   ✗ Poll commands failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Poll commands successful")
	}
	fmt.Println()

	fmt.Println("=== Integration Test Complete ===")
}

func testHeartbeat(ctx context.Context, c *client.Client) error {
	status := &core.SensorStatus{
		Name:     "integration-test",
		Status:   core.SensorStateRunning,
		Message:  "Integration test running",
		Scanners: []string{"semgrep", "trivy"},
		Uptime:   100,
	}

	return c.SendHeartbeat(ctx, status)
}

func testPushFindings(ctx context.Context, c *client.Client) error {
	report := createSampleFindingsReport()

	result, err := c.PushFindings(ctx, report)
	if err != nil {
		return err
	}

	fmt.Printf("   Findings created: %d, updated: %d\n", result.FindingsCreated, result.FindingsUpdated)
	return nil
}

func testPushAssets(ctx context.Context, c *client.Client) error {
	report := createSampleAssetsReport()

	result, err := c.PushAssets(ctx, report)
	if err != nil {
		return err
	}

	fmt.Printf("   Assets created: %d, updated: %d\n", result.AssetsCreated, result.AssetsUpdated)
	return nil
}

func testPushCombined(ctx context.Context, c *client.Client) error {
	report := createCombinedReport()

	result, err := c.PushFindings(ctx, report)
	if err != nil {
		return err
	}

	fmt.Printf("   Assets created: %d, Findings created: %d\n", result.AssetsCreated, result.FindingsCreated)
	return nil
}

func testPollCommands(ctx context.Context, c *client.Client) error {
	commands, err := c.PollCommands(ctx, 10)
	if err != nil {
		return err
	}

	fmt.Printf("   Pending commands: %d\n", len(commands))
	for _, cmd := range commands {
		fmt.Printf("   - Command: %s (type: %s, priority: %s)\n", cmd.ID, cmd.Type, cmd.Priority)
	}

	return nil
}

// createSampleFindingsReport creates a sample CTIS 2.0 report with code
// findings filed on one repository asset.
func createSampleFindingsReport() *ctis.Report {
	report := ctis.NewReport() // metadata.id is a new UUIDv7, generated_at now
	report.Metadata.DurationMs = 5000
	report.Metadata.SourceRefs = []ctis.SourceRef{{System: "integration-test", ID: "run-1"}}

	report.Tool = &ctis.Tool{
		Name:       "semgrep",
		Version:    "1.50.0",
		Vendor:     "Semgrep Inc.",
		Techniques: []ctis.Technique{ctis.TechniqueSAST, ctis.TechniqueSecret},
	}

	report.Assets = []ctis.Asset{{
		ID:    "repo-1",
		Type:  ctis.AssetTypeRepository,
		Value: "github.com/example/webapp",
	}}

	// Add sample findings
	report.Findings = []ctis.Finding{
		{
			ID:          "finding-1",
			Type:        ctis.FindingTypeWeakness,
			Title:       "SQL Injection vulnerability",
			Description: "User input is directly concatenated into SQL query without proper sanitization.",
			Severity:    ctis.SeverityHigh,
			Confidence:  90,
			Category:    "security",
			RuleID:      "sql-injection",
			RuleName:    "SQL Injection Detection",
			AssetRef:    "repo-1",
			Location: &ctis.FindingLocation{
				Path:        "src/api/users.go",
				StartLine:   45,
				EndLine:     48,
				StartColumn: 1,
				EndColumn:   50,
				Snippet:     `query := "SELECT * FROM users WHERE id = " + userID`,
			},
			Vulnerability: &ctis.VulnerabilityDetails{
				CWEIDs: []string{"CWE-89"},
			},
			Remediation: &ctis.Remediation{
				Recommendation: "Use parameterized queries instead of string concatenation",
				Steps: []string{
					"Replace string concatenation with prepared statements",
					"Use query parameters for user input",
					"Validate and sanitize all user inputs",
				},
				Effort: ctis.EffortLow,
			},
			References: []string{
				"https://owasp.org/www-community/attacks/SQL_Injection",
			},
			Tags: []string{"owasp-top-10", "injection"},
		},
		{
			ID:          "finding-2",
			Type:        ctis.FindingTypeSecret,
			Title:       "Hardcoded credentials detected",
			Description: "API key is hardcoded in the source code.",
			Severity:    ctis.SeverityCritical,
			Confidence:  95,
			Category:    "security",
			RuleID:      "hardcoded-secret",
			AssetRef:    "repo-1",
			Location: &ctis.FindingLocation{
				Path:      "src/config/config.go",
				StartLine: 12,
				EndLine:   12,
			},
			Secret: &ctis.SecretDetails{
				Type:        "api_key",
				Service:     "stripe",
				MaskedValue: "sk_l****xxxx",
				Length:      32,
			},
			Tags: []string{"secrets", "credentials"},
		},
		{
			ID:          "finding-3",
			Type:        ctis.FindingTypeWeakness,
			Title:       "Cross-Site Scripting (XSS)",
			Description: "User input is rendered without escaping in HTML template.",
			Severity:    ctis.SeverityMedium,
			Confidence:  80,
			RuleID:      "xss-reflected",
			AssetRef:    "repo-1",
			Location: &ctis.FindingLocation{
				Path:      "templates/user.html",
				StartLine: 25,
				Snippet:   `<div>{{ .UserInput }}</div>`,
			},
			Vulnerability: &ctis.VulnerabilityDetails{
				CWEIDs: []string{"CWE-79"},
			},
		},
	}

	return report
}

// createSampleAssetsReport creates a sample report with assets only: a
// repository, a domain name, a host address and the service it exposes.
func createSampleAssetsReport() *ctis.Report {
	report := ctis.NewReport()
	report.Metadata.Channel = ctis.ChannelCollector

	report.Tool = &ctis.Tool{
		Name:    "asset-collector",
		Version: "1.0.0",
	}

	report.Assets = []ctis.Asset{
		{
			ID:          "asset-1",
			Type:        ctis.AssetTypeRepository,
			Value:       "github.com/example/webapp",
			Name:        "Web Application",
			Description: "Main web application repository",
			Criticality: ctis.CriticalityHigh,
			Tags:        []string{"production", "frontend"},
			Technical: &ctis.AssetTechnical{
				Repository: &ctis.RepositoryTechnical{
					Platform:      "github",
					Owner:         "example",
					Name:          "webapp",
					DefaultBranch: "main",
					Visibility:    "private",
					URL:           "https://github.com/example/webapp",
				},
			},
		},
		{
			ID:          "asset-2",
			Type:        ctis.AssetTypeDomainName,
			Value:       "api.example.com",
			Name:        "API Domain",
			Criticality: ctis.CriticalityCritical,
			Tags:        []string{"production", "api"},
			Technical: &ctis.AssetTechnical{
				Domain: &ctis.DomainTechnical{
					Registrar:   "Cloudflare",
					Nameservers: []string{"ns1.cloudflare.com", "ns2.cloudflare.com"},
				},
			},
		},
		{
			ID:          "asset-3",
			Type:        ctis.AssetTypeIPAddress,
			Value:       "10.0.1.100",
			Name:        "Database Server",
			Criticality: ctis.CriticalityCritical,
			Tags:        []string{"internal", "database"},
			Technical: &ctis.AssetTechnical{
				IPAddress: &ctis.IPAddressTechnical{
					Version:  4,
					Hostname: "db-primary.internal",
				},
			},
		},
		{
			ID:    "asset-4",
			Type:  ctis.AssetTypeService,
			Value: "10.0.1.100:5432/tcp",
			Technical: &ctis.AssetTechnical{
				Service: &ctis.ServiceTechnical{
					Port:        5432,
					Transport:   ctis.TransportTCP,
					AppProtocol: "postgresql",
					State:       ctis.PortOpen,
				},
			},
		},
	}
	report.Relationships = []ctis.Relationship{{Type: ctis.RelExposes, FromRef: "asset-3", ToRef: "asset-4"}}

	return report
}

// createCombinedReport creates a report with both assets and findings.
func createCombinedReport() *ctis.Report {
	report := ctis.NewReport()
	report.Metadata.DurationMs = 30000

	report.Tool = &ctis.Tool{
		Name:       "trivy",
		Version:    "0.48.0",
		Vendor:     "Aqua Security",
		Techniques: []ctis.Technique{ctis.TechniqueContainer},
	}

	// Add assets
	report.Assets = []ctis.Asset{
		{
			ID:          "container-1",
			Type:        ctis.AssetTypeContainer,
			Value:       "docker.io/example/app:v1.2.3",
			Name:        "Application Container",
			Criticality: ctis.CriticalityHigh,
			Tags:        []string{"production", "container"},
		},
	}

	cvss := 9.8
	openssl := &ctis.VulnerabilityDetails{
		CWEIDs:           []string{"CWE-119"},
		PackageName:      "openssl",
		PURL:             "pkg:deb/debian/openssl@1.1.1",
		InstalledVersion: "1.1.1",
		FixedVersions:    []string{"1.1.1w"},
		ThreatSignals:    []ctis.ThreatSignal{{Type: ctis.ThreatSignalPublicExploit, Source: "nvd"}},
	}
	openssl.AddID("CVE-2024-1234", "")
	curlCVSS := 7.5
	curl := &ctis.VulnerabilityDetails{
		PackageName:      "curl",
		InstalledVersion: "7.88.0",
		FixedVersions:    []string{"7.88.1"},
	}
	curl.AddID("CVE-2024-5678", "")

	// Add findings referencing the asset
	report.Findings = []ctis.Finding{
		{
			ID:            "vuln-1",
			Type:          ctis.FindingTypeVulnerability,
			Title:         "CVE-2024-1234: Critical vulnerability in openssl",
			Description:   "A critical vulnerability in OpenSSL allows remote code execution.",
			Severity:      ctis.SeverityCritical,
			Confidence:    100,
			RuleID:        "CVE-2024-1234",
			AssetRef:      "container-1", // Reference to asset
			Vulnerability: openssl,
			Scores: []ctis.Score{{System: ctis.ScoreSystemCVSS, Version: "3.1", Value: &cvss,
				Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Source: "nvd"}},
			Remediation: &ctis.Remediation{
				Recommendation: "Upgrade openssl to version 1.1.1w or later",
				IsFixAvailable: ctis.Bool(true),
			},
		},
		{
			ID:            "vuln-2",
			Type:          ctis.FindingTypeVulnerability,
			Title:         "CVE-2024-5678: High severity in curl",
			Severity:      ctis.SeverityHigh,
			RuleID:        "CVE-2024-5678",
			AssetRef:      "container-1",
			Vulnerability: curl,
			Scores:        []ctis.Score{{System: ctis.ScoreSystemCVSS, Value: &curlCVSS}},
		},
	}

	return report
}
