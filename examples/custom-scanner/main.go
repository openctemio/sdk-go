// Example: Custom Scanner Implementation
//
// This example demonstrates how tenants can create their own scanner
// by embedding the BaseScanner and customizing the behavior.
//
// Build: go build -o custom-scanner ./examples/custom-scanner
// Run:   ./custom-scanner -target /path/to/project -api-url https://localhost:8080 -api-key YOUR_KEY
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
)

// =============================================================================
// Custom Scanner - Extends BaseScanner with custom logic
// =============================================================================

// MyCustomScanner is an example of a tenant-defined scanner.
// It embeds BaseScanner to inherit common functionality.
type MyCustomScanner struct {
	*core.BaseScanner

	// Add custom fields here
	customConfig string
	ruleset      string
}

// NewMyCustomScanner creates a new custom scanner.
func NewMyCustomScanner(ruleset string, verbose bool) *MyCustomScanner {
	// Create base scanner with custom configuration
	base := core.NewBaseScanner(&core.BaseScannerConfig{
		Name:    "my-custom-scanner",
		Version: "1.0.0",
		Binary:  "semgrep", // Using semgrep as the underlying tool

		// Custom default args - tenants can modify this
		DefaultArgs: []string{
			"scan",
			"--sarif",
			"--config", ruleset,
			"{target}",
		},

		Timeout:      30 * time.Minute,
		OKExitCodes:  []int{0, 1},
		Capabilities: []string{"sast", "secret", "custom"},
		Verbose:      verbose,
	})

	return &MyCustomScanner{
		BaseScanner: base,
		ruleset:     ruleset,
	}
}

// BuildArgs overrides the default argument building to add custom logic.
// This is where tenants can customize how arguments are constructed.
func (s *MyCustomScanner) BuildArgs(target string, opts *core.ScanOptions) []string {
	// Start with base args
	args := s.BaseScanner.BuildArgs(target, opts)

	// Add custom arguments based on tenant-specific logic
	if s.customConfig != "" {
		args = append(args, "--config", s.customConfig)
	}

	// Add exclude patterns from options
	if opts != nil {
		for _, pattern := range opts.Exclude {
			args = append(args, "--exclude", pattern)
		}
	}

	return args
}

// Scan overrides the base scan to add pre/post processing.
func (s *MyCustomScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	// Pre-scan hook - tenants can add custom logic here
	fmt.Printf("[%s] Starting custom scan on %s\n", s.Name(), target)
	fmt.Printf("[%s] Using ruleset: %s\n", s.Name(), s.ruleset)

	// Call base scan
	result, err := s.BaseScanner.Scan(ctx, target, opts)

	// Post-scan hook - process results, add metadata, etc.
	if err == nil {
		fmt.Printf("[%s] Scan completed successfully, output size: %d bytes\n",
			s.Name(), len(result.RawOutput))
	}

	return result, err
}

// SetCustomConfig allows runtime configuration changes.
func (s *MyCustomScanner) SetCustomConfig(config string) {
	s.customConfig = config
}

// =============================================================================
// Custom Parser - Example of extending parsing logic
// =============================================================================

// MyCustomParser shows how to create a custom parser.
type MyCustomParser struct {
	*core.BaseParser
}

// NewMyCustomParser creates a custom parser.
func NewMyCustomParser() *MyCustomParser {
	return &MyCustomParser{
		BaseParser: core.NewBaseParser("my-custom-parser", []string{"custom", "json"}),
	}
}

// CanParse checks if this parser can handle the data.
func (p *MyCustomParser) CanParse(data []byte) bool {
	// Add custom detection logic
	// For example, check for specific markers in the output
	return false // Defer to other parsers
}

// =============================================================================
// Main - Example usage
// =============================================================================

func main() {
	// CLI flags
	target := flag.String("target", ".", "Target directory to scan")
	apiURL := flag.String("api-url", "", "OpenCTEM API URL")
	apiKey := flag.String("api-key", "", "OpenCTEM API key")
	ruleset := flag.String("ruleset", "auto", "Semgrep ruleset to use")
	verbose := flag.Bool("verbose", false, "Verbose output")
	daemon := flag.Bool("daemon", false, "Run in daemon mode")
	interval := flag.Duration("interval", 1*time.Hour, "Scan interval in daemon mode")

	flag.Parse()

	// Create custom scanner
	scanner := NewMyCustomScanner(*ruleset, *verbose)

	// Create API client if credentials provided
	var pusher core.Pusher
	if *apiURL != "" && *apiKey != "" {
		pusher = client.New(&client.Config{
			BaseURL: *apiURL,
			APIKey:  *apiKey,
			Verbose: *verbose,
		})
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	if *daemon {
		// Run in daemon mode using BaseAgent
		runDaemon(ctx, scanner, pusher, *target, *interval, *verbose)
	} else {
		// Run single scan
		runOnce(ctx, scanner, pusher, *target, *verbose)
	}
}

func runOnce(ctx context.Context, scanner *MyCustomScanner, pusher core.Pusher, target string, verbose bool) {
	// Check if scanner is installed
	installed, version, err := scanner.IsInstalled(ctx)
	if err != nil || !installed {
		fmt.Fprintf(os.Stderr, "Scanner not installed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Using %s version %s\n", scanner.Name(), version)

	// Run scan
	result, err := scanner.Scan(ctx, target, &core.ScanOptions{
		TargetDir: target,
		Verbose:   verbose,
		Exclude:   []string{"vendor", "node_modules", ".git"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nScan completed in %d ms\n", result.DurationMs)
	fmt.Printf("Exit code: %d\n", result.ExitCode)
	fmt.Printf("Output size: %d bytes\n", len(result.RawOutput))

	// Parse results using the built-in parser registry
	parsers := core.NewParserRegistry()
	parser := parsers.FindParser(result.RawOutput)
	if parser == nil {
		parser = parsers.Get("sarif") // Default to SARIF
	}

	if parser != nil {
		report, err := parser.Parse(ctx, result.RawOutput, &core.ParseOptions{
			ToolName: scanner.Name(),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Parse failed: %v\n", err)
		} else {
			fmt.Printf("Found %d findings\n", len(report.Findings))

			// Push to OpenCTEM if configured
			if pusher != nil && len(report.Findings) > 0 {
				fmt.Println("\nPushing to OpenCTEM...")
				pushResult, err := pusher.PushFindings(ctx, report)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Push failed: %v\n", err)
				} else {
					fmt.Printf("Pushed: %d created, %d updated\n",
						pushResult.FindingsCreated, pushResult.FindingsUpdated)
				}
			}
		}
	}
}

func runDaemon(ctx context.Context, scanner *MyCustomScanner, pusher core.Pusher, target string, interval time.Duration, verbose bool) {
	// Create agent with the custom scanner
	agent := core.NewBaseAgent(&core.BaseAgentConfig{
		Name:              "custom-scanner-agent",
		Version:           "1.0.0",
		ScanInterval:      interval,
		HeartbeatInterval: 1 * time.Minute,
		Targets:           []string{target},
		Verbose:           verbose,
	}, pusher)

	// Add our custom scanner
	if err := agent.AddScanner(scanner); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add scanner: %v\n", err)
		os.Exit(1)
	}

	// Start agent
	if err := agent.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start agent: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Agent started. Press Ctrl+C to stop.")

	// Wait for context cancellation
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := agent.Stop(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "Shutdown error: %v\n", err)
	}

	fmt.Println("Agent stopped.")
}
