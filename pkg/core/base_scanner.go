package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// =============================================================================
// BaseScanner - Base implementation that tenants can embed
// =============================================================================

// BaseScanner provides a base implementation for scanners.
// Embed this in your custom scanner to get common functionality.
type BaseScanner struct {
	// Basic info
	name         string
	version      string
	capabilities []string

	// Execution
	binary      string
	defaultArgs []string
	timeout     time.Duration
	okExitCodes []int
	workDir     string
	env         map[string]string

	// Verbose output
	verbose bool
}

// BaseScannerConfig configures a BaseScanner.
type BaseScannerConfig struct {
	Name         string            `yaml:"name" json:"name"`
	Version      string            `yaml:"version" json:"version"`
	Binary       string            `yaml:"binary" json:"binary"`
	DefaultArgs  []string          `yaml:"default_args" json:"default_args"`
	Timeout      time.Duration     `yaml:"timeout" json:"timeout"`
	OKExitCodes  []int             `yaml:"ok_exit_codes" json:"ok_exit_codes"`
	Capabilities []string          `yaml:"capabilities" json:"capabilities"`
	WorkDir      string            `yaml:"work_dir" json:"work_dir"`
	Env          map[string]string `yaml:"env" json:"env"`
	Verbose      bool              `yaml:"verbose" json:"verbose"`
}

// NewBaseScanner creates a new base scanner with the given config.
func NewBaseScanner(cfg *BaseScannerConfig) *BaseScanner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Minute
	}
	if len(cfg.OKExitCodes) == 0 {
		cfg.OKExitCodes = []int{0, 1} // Most tools return 1 when findings are found
	}
	binary := cfg.Binary
	if binary == "" {
		binary = cfg.Name
	}

	return &BaseScanner{
		name:         cfg.Name,
		version:      cfg.Version,
		capabilities: cfg.Capabilities,
		binary:       binary,
		defaultArgs:  cfg.DefaultArgs,
		timeout:      cfg.Timeout,
		okExitCodes:  cfg.OKExitCodes,
		workDir:      cfg.WorkDir,
		env:          cfg.Env,
		verbose:      cfg.Verbose,
	}
}

// Name returns the scanner name.
func (s *BaseScanner) Name() string {
	return s.name
}

// Version returns the scanner version.
func (s *BaseScanner) Version() string {
	return s.version
}

// Capabilities returns what the scanner can detect.
func (s *BaseScanner) Capabilities() []string {
	return s.capabilities
}

// IsInstalled checks if the scanner binary is available.
func (s *BaseScanner) IsInstalled(ctx context.Context) (bool, string, error) {
	cmd := exec.CommandContext(ctx, s.binary, "--version") //nolint:gosec // Scanner binary is configured, not user input
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("%s not found: %w", s.binary, err)
	}
	version := strings.TrimSpace(string(output))
	return true, version, nil
}

// Scan executes the scanner with the given options.
// This is the base implementation - override BuildArgs in your scanner for customization.
func (s *BaseScanner) Scan(ctx context.Context, target string, opts *ScanOptions) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		ScannerName:    s.name,
		ScannerVersion: s.version,
		StartedAt:      startTime.Unix(),
	}

	// Build command arguments
	args := s.BuildArgs(target, opts)

	if s.verbose || (opts != nil && opts.Verbose) {
		fmt.Printf("[%s] Running: %s %s\n", s.name, s.binary, strings.Join(args, " "))
	}

	// Create context with timeout
	execCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Create command
	cmd := exec.CommandContext(execCtx, s.binary, args...) //nolint:gosec // Scanner binary is configured, not user input

	// Set working directory
	if opts != nil && opts.TargetDir != "" {
		cmd.Dir = opts.TargetDir
	} else if s.workDir != "" {
		cmd.Dir = s.workDir
	} else {
		cmd.Dir = target
	}

	// Set environment
	cmd.Env = os.Environ()
	for k, v := range s.env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	if opts != nil {
		for k, v := range opts.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute
	err := cmd.Run()
	result.FinishedAt = time.Now().Unix()
	result.DurationMs = time.Since(startTime).Milliseconds()
	result.RawOutput = stdout.Bytes()
	result.Stderr = stderr.String()

	// Get exit code
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
	}

	// Check if exit code is acceptable
	if !s.isOKExitCode(result.ExitCode) && err != nil {
		result.Error = fmt.Sprintf("scanner failed (exit %d): %s", result.ExitCode, stderr.String())
		return result, fmt.Errorf("%s", result.Error)
	}

	if s.verbose || (opts != nil && opts.Verbose) {
		fmt.Printf("[%s] Completed in %dms (exit code: %d)\n", s.name, result.DurationMs, result.ExitCode)
	}

	return result, nil
}

// BuildArgs builds command arguments. Override this in your scanner for custom argument handling.
func (s *BaseScanner) BuildArgs(target string, opts *ScanOptions) []string {
	args := make([]string, len(s.defaultArgs))
	copy(args, s.defaultArgs)

	// Replace placeholders
	for i, arg := range args {
		args[i] = strings.ReplaceAll(arg, "{target}", target)
		if opts != nil {
			args[i] = strings.ReplaceAll(args[i], "{config}", opts.ConfigFile)
		}
	}

	// Add extra args from options
	if opts != nil {
		args = append(args, opts.ExtraArgs...)
	}

	return args
}

// isOKExitCode checks if the exit code is acceptable.
func (s *BaseScanner) isOKExitCode(code int) bool {
	return slices.Contains(s.okExitCodes, code)
}

// SetVerbose sets verbose mode.
func (s *BaseScanner) SetVerbose(v bool) {
	s.verbose = v
}

// =============================================================================
// Preset Scanner Configs - Ready to use configurations
// =============================================================================

// PresetScanners contains configurations for popular security tools.
var PresetScanners = map[string]*BaseScannerConfig{
	"semgrep": {
		Name:         "semgrep",
		Binary:       "semgrep",
		DefaultArgs:  []string{"scan", "--sarif", "--config", "auto", "{target}"},
		Timeout:      30 * time.Minute,
		OKExitCodes:  []int{0, 1},
		Capabilities: []string{"sast", "secret"},
	},
	"trivy-fs": {
		Name:         "trivy",
		Binary:       "trivy",
		DefaultArgs:  []string{"fs", "--format", "sarif", "{target}"},
		Timeout:      15 * time.Minute,
		OKExitCodes:  []int{0},
		Capabilities: []string{"sca", "vulnerability"},
	},
	"trivy-config": {
		Name:         "trivy",
		Binary:       "trivy",
		DefaultArgs:  []string{"config", "--format", "sarif", "{target}"},
		Timeout:      15 * time.Minute,
		OKExitCodes:  []int{0},
		Capabilities: []string{"iac", "misconfiguration"},
	},
	"gitleaks": {
		Name:         "gitleaks",
		Binary:       "gitleaks",
		DefaultArgs:  []string{"detect", "--source", "{target}", "--report-format", "sarif", "--report-path", "/dev/stdout", "--no-banner"},
		Timeout:      15 * time.Minute,
		OKExitCodes:  []int{0, 1},
		Capabilities: []string{"secret"},
	},
	"slither": {
		Name:         "slither",
		Binary:       "slither",
		DefaultArgs:  []string{"{target}", "--sarif", "/dev/stdout"},
		Timeout:      30 * time.Minute,
		OKExitCodes:  []int{0, 1, 255},
		Capabilities: []string{"web3", "smart-contract"},
	},
	"checkov": {
		Name:         "checkov",
		Binary:       "checkov",
		DefaultArgs:  []string{"-d", "{target}", "-o", "sarif", "--output-file-path", "/dev/stdout"},
		Timeout:      15 * time.Minute,
		OKExitCodes:  []int{0, 1},
		Capabilities: []string{"iac", "misconfiguration"},
	},
	"bandit": {
		Name:         "bandit",
		Binary:       "bandit",
		DefaultArgs:  []string{"-r", "{target}", "-f", "sarif", "-o", "/dev/stdout"},
		Timeout:      15 * time.Minute,
		OKExitCodes:  []int{0, 1},
		Capabilities: []string{"sast"},
	},
	"gosec": {
		Name:         "gosec",
		Binary:       "gosec",
		DefaultArgs:  []string{"-fmt", "sarif", "-out", "/dev/stdout", "{target}/..."},
		Timeout:      15 * time.Minute,
		OKExitCodes:  []int{0, 1},
		Capabilities: []string{"sast"},
	},
	"snyk": {
		Name:         "snyk",
		Binary:       "snyk",
		DefaultArgs:  []string{"code", "test", "{target}", "--sarif"},
		Timeout:      30 * time.Minute,
		OKExitCodes:  []int{0, 1},
		Capabilities: []string{"sast", "sca"},
	},
	"codeql": {
		Name:         "codeql",
		Binary:       "codeql",
		DefaultArgs:  []string{"database", "analyze", "{target}", "--format=sarif-latest", "--output=/dev/stdout"},
		Timeout:      60 * time.Minute,
		OKExitCodes:  []int{0},
		Capabilities: []string{"sast"},
	},
}

// NewPresetScanner creates a scanner from a preset configuration.
func NewPresetScanner(name string) (*BaseScanner, error) {
	cfg, ok := PresetScanners[name]
	if !ok {
		return nil, fmt.Errorf("unknown preset scanner: %s", name)
	}
	return NewBaseScanner(cfg), nil
}

// ListPresetScanners returns all available preset scanner names.
func ListPresetScanners() []string {
	names := make([]string, 0, len(PresetScanners))
	for name := range PresetScanners {
		names = append(names, name)
	}
	return names
}
