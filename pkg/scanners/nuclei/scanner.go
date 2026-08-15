package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

const (
	// DefaultBinary is the default nuclei binary name.
	DefaultBinary = "nuclei"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 60 * time.Minute

	// DefaultRateLimit is the default rate limit (requests per second).
	DefaultRateLimit = 150

	// DefaultConcurrency is the default concurrency level.
	DefaultConcurrency = 25
)

// Scanner implements the Scanner interface for Nuclei.
type Scanner struct {
	// Configuration
	Binary  string        // Path to nuclei binary (default: "nuclei")
	Timeout time.Duration // Scan timeout (default: 60 minutes)
	Verbose bool          // Enable verbose output

	// Scan options
	Mode        ScanMode // target, list
	TargetFile  string   // File containing list of targets
	Templates   []string // Specific templates to use
	TemplateDir string   // Directory containing templates
	Workflows   []string // Specific workflows to use
	Tags        []string // Filter templates by tags
	ExcludeTags []string // Exclude templates by tags
	Severity    []string // Filter by severity
	Author      []string // Filter by template author
	IDs         []string // Run only these template IDs (nuclei -id); used to run a single template
	ExcludeIDs  []string // Template IDs to exclude

	// Rate limiting
	RateLimit           int // Requests per second
	BulkSize            int // Bulk size for parallel processing
	Concurrency         int // Number of concurrent templates
	HeadlessBulkSize    int // Headless bulk size
	HeadlessConcurrency int // Headless concurrency

	// Output options
	OutputFile     string // Output file path (empty = stdout)
	MarkdownExport string // Export results as markdown
	SarifExport    string // Export results as SARIF

	// Interactsh options
	InteractshServer string // Custom interactsh server
	InteractshToken  string // Interactsh auth token
	NoInteractsh     bool   // Disable interactsh server

	// Network options
	Proxy           string   // HTTP/SOCKS proxy
	ProxyAuth       string   // Proxy authentication
	Headers         []string // Custom headers
	FollowRedirects bool     // Follow redirects
	MaxRedirects    int      // Maximum redirects
	DisableCookie   bool     // Disable cookie reuse
	Timeout404      int      // Timeout for 404 detection

	// Headless options
	Headless        bool // Enable headless browser
	HeadlessTimeout int  // Headless browser timeout
	PageTimeout     int  // Page load timeout
	ShowBrowser     bool // Show browser (debug)

	// Misc options
	SystemResolvers     bool // Use system DNS resolvers
	Retries             int  // Number of retries
	LeaveDefaultPorts   bool // Leave default ports in URLs
	StopAtFirstMatch    bool // Stop at first match per host
	NoColor             bool // Disable colored output
	Silent              bool // Silent mode
	AutoUpdateTemplates bool // Update templates before scan

	// Internal
	version string
}

// NewScanner creates a new Nuclei scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:      DefaultBinary,
		Timeout:     DefaultTimeout,
		Mode:        ScanModeTarget,
		RateLimit:   DefaultRateLimit,
		Concurrency: DefaultConcurrency,
		Severity:    []string{"critical", "high", "medium", "low"},
		Retries:     1,
	}
}

// NewDAST creates a scanner configured for DAST scanning with safe defaults.
func NewDAST() *Scanner {
	s := NewScanner()
	s.Tags = []string{"cve", "oast", "exposure", "misconfig", "takeover", "default-login", "file"}
	s.ExcludeTags = []string{"dos", "fuzz"}
	return s
}

// NewVulnScanner creates a scanner focused on CVE/vulnerability detection.
func NewVulnScanner() *Scanner {
	s := NewScanner()
	s.Tags = []string{"cve"}
	s.Severity = []string{"critical", "high", "medium"}
	return s
}

// NewMisconfigScanner creates a scanner focused on misconfiguration detection.
func NewMisconfigScanner() *Scanner {
	s := NewScanner()
	s.Tags = []string{"misconfig", "exposure", "config"}
	return s
}

// NewTakeoverScanner creates a scanner focused on subdomain takeover detection.
func NewTakeoverScanner() *Scanner {
	s := NewScanner()
	s.Tags = []string{"takeover"}
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "nuclei"
}

// Type returns the scanner type.
func (s *Scanner) Type() core.ScannerType {
	return "dast" // DAST scanner type
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Capabilities returns the scanner capabilities.
func (s *Scanner) Capabilities() []string {
	caps := []string{"dast", "vulnerability_scanning"}

	for _, tag := range s.Tags {
		switch tag {
		case "cve":
			caps = append(caps, "cve_detection")
		case "misconfig", "config":
			caps = append(caps, "misconfiguration")
		case "takeover":
			caps = append(caps, "subdomain_takeover")
		case "exposure":
			caps = append(caps, "exposure_detection")
		case "default-login":
			caps = append(caps, "default_credentials")
		case "oast":
			caps = append(caps, "oob_testing")
		}
	}

	return caps
}

// IsInstalled checks if Nuclei is installed.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	installed, version, err := core.CheckBinaryInstalled(ctx, binary, "-version")
	if err != nil {
		return false, "", err
	}

	if installed {
		s.version = parseVersion(version)
	}

	return installed, s.version, nil
}

// parseVersion extracts version from nuclei output.
func parseVersion(output string) string {
	// Nuclei version output: "Nuclei Engine Version: v3.1.0"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Version:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return strings.TrimSpace(output)
}

// SetVerbose enables/disables verbose output.
func (s *Scanner) SetVerbose(v bool) {
	s.Verbose = v
}

// Scan implements core.Scanner interface - returns raw JSON Lines output.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()

	// Build nuclei arguments
	args := s.buildArgs(target, opts)

	if s.Verbose {
		fmt.Printf("[nuclei] Target: %s\n", target)
		fmt.Printf("[nuclei] Tags: %v\n", s.Tags)
		fmt.Printf("[nuclei] Severity: %v\n", s.Severity)
	}

	// Execute nuclei
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	execResult, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		Timeout: timeout,
		Verbose: s.Verbose,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to execute nuclei: %w", err)
	}

	// Nuclei exit codes:
	// 0 = success, no findings
	// 1 = findings found (when -es flag is used)
	// other = error
	if execResult.ExitCode != 0 && execResult.ExitCode != 1 {
		return nil, fmt.Errorf("nuclei exited with code %d: %s", execResult.ExitCode, string(execResult.Stderr))
	}

	// Get output
	var outputData []byte
	if s.OutputFile != "" {
		outputData, err = os.ReadFile(s.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read nuclei output: %w", err)
		}
		// Clean up output file
		_ = os.Remove(s.OutputFile)
	} else {
		outputData = execResult.Stdout
	}

	result := &core.ScanResult{
		ScannerName:    s.Name(),
		ScannerVersion: s.version,
		StartedAt:      start.Unix(),
		FinishedAt:     time.Now().Unix(),
		DurationMs:     time.Since(start).Milliseconds(),
		ExitCode:       execResult.ExitCode,
		RawOutput:      outputData,
		Stderr:         string(execResult.Stderr),
	}

	if s.Verbose {
		fmt.Printf("[nuclei] Scan completed in %dms\n", result.DurationMs)
	}

	return result, nil
}

// ScanDAST performs a DAST scan and returns structured results.
func (s *Scanner) ScanDAST(ctx context.Context, targets []string, opts *core.ScanOptions) (*ScanReport, error) {
	start := time.Now()

	// If multiple targets, write to temp file
	var target string
	if len(targets) == 1 {
		target = targets[0]
	} else {
		tempFile, err := s.writeTargetsFile(targets)
		if err != nil {
			return nil, fmt.Errorf("failed to write targets file: %w", err)
		}
		defer os.Remove(tempFile) //nolint:errcheck // best-effort cleanup
		s.Mode = ScanModeList
		s.TargetFile = tempFile
		target = ""
	}

	// Run scan
	scanResult, err := s.Scan(ctx, target, opts)
	if err != nil {
		return nil, err
	}

	// Parse JSON Lines output
	results, err := s.parseJSONLines(scanResult.RawOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nuclei output: %w", err)
	}

	report := &ScanReport{
		Results: results,
		Statistics: Statistics{
			StartTime:    time.Unix(scanResult.StartedAt, 0),
			EndTime:      time.Unix(scanResult.FinishedAt, 0),
			Duration:     time.Since(start),
			HostsScanned: len(targets),
			ResultsFound: len(results),
		},
	}

	if s.Verbose {
		fmt.Printf("[nuclei] Found %d results in %dms\n", len(results), scanResult.DurationMs)
	}

	return report, nil
}

// buildArgs builds the nuclei command arguments.
func (s *Scanner) buildArgs(target string, opts *core.ScanOptions) []string {
	args := []string{}

	// Target specification
	switch s.Mode {
	case ScanModeList:
		if s.TargetFile != "" {
			args = append(args, "-l", s.TargetFile)
		}
	case ScanModeResume:
		args = append(args, "-resume")
	default:
		if target != "" {
			args = append(args, "-u", target)
		}
	}

	// Output format - JSON Lines
	args = append(args, "-jsonl")

	// Output file
	if s.OutputFile != "" {
		args = append(args, "-o", s.OutputFile)
	}

	// Custom templates from ScanOptions take priority (platform-provided templates)
	if opts != nil && opts.CustomTemplateDir != "" {
		args = append(args, "-t", opts.CustomTemplateDir)
	}

	// Template configuration (scanner-level defaults)
	if len(s.Templates) > 0 {
		for _, t := range s.Templates {
			args = append(args, "-t", t)
		}
	}
	if s.TemplateDir != "" {
		args = append(args, "-t", s.TemplateDir)
	}
	if len(s.Workflows) > 0 {
		for _, w := range s.Workflows {
			args = append(args, "-w", w)
		}
	}

	// Tag filtering
	if len(s.Tags) > 0 {
		args = append(args, "-tags", strings.Join(s.Tags, ","))
	}
	if len(s.ExcludeTags) > 0 {
		args = append(args, "-etags", strings.Join(s.ExcludeTags, ","))
	}

	// Severity filtering
	if len(s.Severity) > 0 {
		args = append(args, "-severity", strings.Join(s.Severity, ","))
	}

	// Author filtering
	if len(s.Author) > 0 {
		args = append(args, "-author", strings.Join(s.Author, ","))
	}

	// Run only specific template IDs (nuclei -id). Combined with -etags this is
	// how a single detection template is re-run non-destructively: -id selects
	// the template, -etags still hard-excludes any dangerous tag it may carry
	// (exclude wins over include in nuclei, so an excluded template loads zero).
	if len(s.IDs) > 0 {
		for _, id := range s.IDs {
			args = append(args, "-id", id)
		}
	}

	// Exclude templates
	if len(s.ExcludeIDs) > 0 {
		for _, id := range s.ExcludeIDs {
			args = append(args, "-exclude-id", id)
		}
	}

	// Rate limiting
	if s.RateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", s.RateLimit))
	}
	if s.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", s.Concurrency))
	}
	if s.BulkSize > 0 {
		args = append(args, "-bs", fmt.Sprintf("%d", s.BulkSize))
	}

	// Interactsh options
	if s.NoInteractsh {
		args = append(args, "-ni")
	}
	if s.InteractshServer != "" {
		args = append(args, "-iserver", s.InteractshServer)
	}
	if s.InteractshToken != "" {
		args = append(args, "-itoken", s.InteractshToken)
	}

	// Network options
	if s.Proxy != "" {
		args = append(args, "-proxy", s.Proxy)
	}
	if s.ProxyAuth != "" {
		args = append(args, "-proxy-auth", s.ProxyAuth)
	}
	for _, h := range s.Headers {
		args = append(args, "-header", h)
	}
	if s.FollowRedirects {
		args = append(args, "-follow-redirects")
		if s.MaxRedirects > 0 {
			args = append(args, "-max-redirects", fmt.Sprintf("%d", s.MaxRedirects))
		}
	}

	// Headless options
	if s.Headless {
		args = append(args, "-headless")
		if s.HeadlessTimeout > 0 {
			args = append(args, "-headless-timeout", fmt.Sprintf("%d", s.HeadlessTimeout))
		}
		if s.PageTimeout > 0 {
			args = append(args, "-page-timeout", fmt.Sprintf("%d", s.PageTimeout))
		}
		if s.ShowBrowser {
			args = append(args, "-show-browser")
		}
		if s.HeadlessConcurrency > 0 {
			args = append(args, "-headc", fmt.Sprintf("%d", s.HeadlessConcurrency))
		}
	}

	// Misc options
	if s.SystemResolvers {
		args = append(args, "-system-resolvers")
	}
	if s.Retries > 1 {
		args = append(args, "-retries", fmt.Sprintf("%d", s.Retries))
	}
	if s.StopAtFirstMatch {
		args = append(args, "-stop-at-first-match")
	}
	if s.NoColor {
		args = append(args, "-nc")
	}
	if s.Silent {
		args = append(args, "-silent")
	}
	if s.AutoUpdateTemplates {
		args = append(args, "-ut")
	}

	// Apply options from opts
	if opts != nil {
		for _, exclude := range opts.Exclude {
			args = append(args, "-exclude", exclude)
		}
		args = append(args, opts.ExtraArgs...)
	}

	return args
}

// writeTargetsFile writes targets to a temporary file.
func (s *Scanner) writeTargetsFile(targets []string) (string, error) {
	tempFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	for _, target := range targets {
		if _, err := tempFile.WriteString(target + "\n"); err != nil {
			return "", err
		}
	}

	return tempFile.Name(), nil
}

// parseJSONLines parses Nuclei's JSON Lines output.
func (s *Scanner) parseJSONLines(data []byte) ([]Result, error) {
	var results []Result

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Increase buffer size for large responses
	const maxCapacity = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var result Result
		if err := json.Unmarshal(line, &result); err != nil {
			if s.Verbose {
				fmt.Printf("[nuclei] Warning: Failed to parse line %d: %v\n", lineNum, err)
			}
			continue
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading output: %w", err)
	}

	return results, nil
}

// UpdateTemplates updates Nuclei templates to the latest version.
func (s *Scanner) UpdateTemplates(ctx context.Context) error {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	_, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    []string{"-ut"},
		Timeout: 5 * time.Minute,
		Verbose: s.Verbose,
	})

	return err
}

// ListTemplates lists available templates matching the given criteria.
func (s *Scanner) ListTemplates(ctx context.Context) ([]string, error) {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	args := []string{"-tl"}

	if len(s.Tags) > 0 {
		args = append(args, "-tags", strings.Join(s.Tags, ","))
	}
	if len(s.Severity) > 0 {
		args = append(args, "-severity", strings.Join(s.Severity, ","))
	}

	result, err := core.ExecuteScanner(ctx, &core.ExecConfig{
		Binary:  binary,
		Args:    args,
		Timeout: 30 * time.Second,
		Verbose: s.Verbose,
	})

	if err != nil {
		return nil, err
	}

	var templates []string
	scanner := bufio.NewScanner(bytes.NewReader(result.Stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "[") {
			templates = append(templates, line)
		}
	}

	return templates, scanner.Err()
}

// GetTemplateDir returns the default template directory.
func GetTemplateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "nuclei-templates")
}
