package gitleaks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

const (
	// DefaultBinary is the default gitleaks binary name.
	DefaultBinary = "gitleaks"

	// DefaultOutputFile is the default output file name.
	DefaultOutputFile = "gitleaks-report.json"

	// DefaultTimeout is the default scan timeout.
	DefaultTimeout = 30 * time.Minute
)

// Scanner implements the SecretScanner interface for gitleaks.
type Scanner struct {
	// Configuration
	Binary     string        // Path to gitleaks binary (default: "gitleaks")
	ConfigFile string        // Custom gitleaks config file (.gitleaks.toml)
	OutputFile string        // Output file path (default: "gitleaks-report.json")
	Timeout    time.Duration // Scan timeout (default: 30 minutes)
	Verbose    bool          // Enable verbose output

	// Internal
	version string
}

// NewScanner creates a new gitleaks scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Binary:     DefaultBinary,
		OutputFile: DefaultOutputFile,
		Timeout:    DefaultTimeout,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "gitleaks"
}

// Type returns the scanner type.
func (s *Scanner) Type() core.ScannerType {
	return core.ScannerTypeSecretDetection
}

// Version returns the scanner version.
func (s *Scanner) Version() string {
	return s.version
}

// Capabilities returns the scanner capabilities.
func (s *Scanner) Capabilities() []string {
	return []string{
		"secret_detection",
		"api_key_detection",
		"password_detection",
		"private_key_detection",
		"git_history_scan",
	}
}

// IsInstalled checks if gitleaks is installed.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	binary := s.Binary
	if binary == "" {
		binary = DefaultBinary
	}

	installed, version, err := core.CheckBinaryInstalled(ctx, binary, "version")
	if err != nil {
		return false, "", err
	}

	if installed {
		s.version = version
	}

	return installed, version, nil
}

// SetVerbose enables/disables verbose output.
func (s *Scanner) SetVerbose(v bool) {
	s.Verbose = v
}

// GenericScan implements core.Scanner interface for use with the agent.
// Returns raw JSON output that can be parsed by the gitleaks parser.
func (s *Scanner) GenericScan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()

	// Resolve target path
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target path: %w", err)
	}

	// Determine output file path
	outputFile := s.OutputFile
	if outputFile == "" {
		outputFile = DefaultOutputFile
	}
	if !filepath.IsAbs(outputFile) {
		outputFile = filepath.Join(absTarget, outputFile)
	}

	// Convert generic options to secret options
	var secretOpts *core.SecretScanOptions
	if opts != nil {
		// For gitleaks, CustomTemplateDir contains a single TOML config file
		// Use it as ConfigFile if provided
		configFile := opts.ConfigFile
		if opts.CustomTemplateDir != "" {
			// CustomTemplateDir points to a directory with TOML files
			// Find the first .toml file in the directory
			entries, err := os.ReadDir(opts.CustomTemplateDir)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() && filepath.Ext(entry.Name()) == ".toml" {
						configFile = filepath.Join(opts.CustomTemplateDir, entry.Name())
						break
					}
				}
			}
		}
		secretOpts = &core.SecretScanOptions{
			TargetDir:  opts.TargetDir,
			ConfigFile: configFile,
			Exclude:    opts.Exclude,
			Verbose:    opts.Verbose,
		}
	}

	// Build gitleaks arguments
	args := s.buildArgs(absTarget, outputFile, secretOpts)

	if s.Verbose {
		fmt.Printf("[gitleaks] Scanning %s\n", absTarget)
		fmt.Printf("[gitleaks] Output: %s\n", outputFile)
	}

	// Execute gitleaks
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
		WorkDir: absTarget,
		Timeout: timeout,
		Verbose: s.Verbose,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to execute gitleaks: %w", err)
	}

	// gitleaks exit codes:
	// 0 = no secrets found
	// 1 = secrets found (this is expected)
	// other = error
	if execResult.ExitCode != 0 && execResult.ExitCode != 1 {
		return nil, fmt.Errorf("gitleaks exited with code %d: %s", execResult.ExitCode, string(execResult.Stderr))
	}

	// Read output file
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read gitleaks output: %w", err)
	}

	// Clean up output file
	_ = os.Remove(outputFile)

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
		fmt.Printf("[gitleaks] Scan completed in %dms\n", result.DurationMs)
	}

	return result, nil
}

// Scan performs a gitleaks scan on the target directory and returns structured SecretResult.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.SecretScanOptions) (*core.SecretResult, error) {
	start := time.Now()

	// Resolve target path
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target path: %w", err)
	}

	// Determine output file path
	outputFile := s.OutputFile
	if outputFile == "" {
		outputFile = DefaultOutputFile
	}
	if !filepath.IsAbs(outputFile) {
		outputFile = filepath.Join(absTarget, outputFile)
	}

	// Build gitleaks arguments
	args := s.buildArgs(absTarget, outputFile, opts)

	if s.Verbose {
		fmt.Printf("[gitleaks] Scanning %s\n", absTarget)
		fmt.Printf("[gitleaks] Output: %s\n", outputFile)
	}

	// Execute gitleaks
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
		WorkDir: absTarget,
		Timeout: timeout,
		Verbose: s.Verbose,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to execute gitleaks: %w", err)
	}

	// gitleaks exit codes:
	// 0 = no secrets found
	// 1 = secrets found (this is expected)
	// other = error
	if execResult.ExitCode != 0 && execResult.ExitCode != 1 {
		return nil, fmt.Errorf("gitleaks exited with code %d: %s", execResult.ExitCode, string(execResult.Stderr))
	}

	// Read output file
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read gitleaks output: %w", err)
	}

	// Parse findings
	findings, err := ParseJSONBytes(outputData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	// Clean up output file
	_ = os.Remove(outputFile)

	// Convert to SecretResult
	result := s.convertFindings(findings)
	result.DurationMs = time.Since(start).Milliseconds()

	if s.Verbose {
		fmt.Printf("[gitleaks] Found %d secrets in %dms\n", len(result.Secrets), result.DurationMs)
	}

	return result, nil
}

// buildArgs builds the gitleaks command arguments.
func (s *Scanner) buildArgs(target, outputFile string, opts *core.SecretScanOptions) []string {
	args := []string{
		"dir",  // Scan directory mode
		target, // Target directory
		"--report-format", "json",
		"--report-path", outputFile,
		"--exit-code", "0", // Don't fail on findings
	}

	// Add config file if specified
	configFile := s.ConfigFile
	if opts != nil && opts.ConfigFile != "" {
		configFile = opts.ConfigFile
	}
	if configFile != "" {
		args = append(args, "--config", configFile)
	}

	// Add excludes
	if opts != nil {
		for _, exclude := range opts.Exclude {
			args = append(args, "--exclude-path", exclude)
		}
	}

	// No git mode
	if opts != nil && opts.NoGit {
		args = append(args, "--no-git")
	}

	// Ignore .gitleaksignore
	args = append(args, "--ignore-gitleaks-allow")

	// Verbose
	if s.Verbose {
		args = append(args, "--verbose")
	}

	return args
}

// convertFindings converts gitleaks findings to SecretResult.
func (s *Scanner) convertFindings(findings []Finding) *core.SecretResult {
	result := &core.SecretResult{
		Secrets: make([]core.SecretFinding, 0, len(findings)),
	}

	for _, f := range findings {
		secret := core.SecretFinding{
			RuleID:      f.RuleID,
			Fingerprint: s.generateFingerprint(f),
			SecretType:  GetSecretType(f.RuleID),
			Service:     GetServiceName(f.RuleID),

			// Location
			File:        f.File,
			StartLine:   f.StartLine,
			EndLine:     f.EndLine,
			StartColumn: f.StartColumn,
			EndColumn:   f.EndColumn,

			// Content
			Match:       f.Match,
			MaskedValue: core.MaskSecret(f.Secret),

			// Metadata
			Entropy: f.Entropy,
			Author:  f.Author,
			Commit:  f.Commit,
			Date:    f.Date,
		}

		result.Secrets = append(result.Secrets, secret)
	}

	return result
}

// generateFingerprint generates a unique fingerprint for a finding.
func (s *Scanner) generateFingerprint(f Finding) string {
	// Use gitleaks fingerprint if available
	if f.Fingerprint != "" {
		return f.Fingerprint
	}

	// Generate our own fingerprint
	return core.GenerateSecretFingerprint(f.File, f.RuleID, f.StartLine, f.Secret)
}
