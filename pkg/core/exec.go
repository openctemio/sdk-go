package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// =============================================================================
// Scanner Execution Utilities
// =============================================================================

// ExecConfig configures scanner execution.
type ExecConfig struct {
	Binary  string            // Scanner binary path
	Args    []string          // Command arguments
	WorkDir string            // Working directory
	Env     map[string]string // Extra environment variables (added to the allowlisted base, see ScannerEnviron)
	Timeout time.Duration     // Execution timeout
	Verbose bool              // Stream output to logs
	// MaxOutputBytes bounds the captured stdout; 0 means
	// DefaultMaxScannerOutput. A scanner that writes more is stopped and the
	// call returns ErrScannerOutputTooLarge.
	MaxOutputBytes int64
}

// ExecResult holds the result of scanner execution.
type ExecResult struct {
	ExitCode   int
	Stdout     []byte
	Stderr     []byte
	DurationMs int64
	Error      error
}

// ExecuteScanner runs a scanner binary with real-time output streaming.
// Its stdout is bounded by cfg.MaxOutputBytes (see ErrScannerOutputTooLarge)
// and its stderr by a fixed bound past which it is cut.
func ExecuteScanner(ctx context.Context, cfg *ExecConfig) (*ExecResult, error) {
	var stdoutLine, stderrLine func(string)
	if cfg.Verbose {
		stdoutLine = func(line string) { fmt.Printf("[stdout] %s\n", line) }
		stderrLine = func(line string) { fmt.Printf("[stderr] %s\n", line) }
	}
	return runScanner(ctx, cfg, stdoutLine, stderrLine)
}

// OutputHandler processes scanner output in real-time.
type OutputHandler func(line string, isError bool)

// StreamScanner runs a scanner with real-time output handling: handler gets
// every line of stdout and stderr, without its line ending, whatever its
// length. Output is bounded as for ExecuteScanner.
func StreamScanner(ctx context.Context, cfg *ExecConfig, handler OutputHandler) (*ExecResult, error) {
	var stdoutLine, stderrLine func(string)
	if handler != nil {
		stdoutLine = func(line string) { handler(line, false) }
		stderrLine = func(line string) { handler(line, true) }
	}
	return runScanner(ctx, cfg, stdoutLine, stderrLine)
}

// runScanner runs cfg's command with the scanner environment and process
// group, capturing bounded stdout and stderr (each line also handed to the
// matching callback, when set).
func runScanner(ctx context.Context, cfg *ExecConfig, stdoutLine, stderrLine func(string)) (*ExecResult, error) {
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}
	// runCtx is canceled when the output bound is hit, which kills the
	// scanner's process group; ctx stays the caller's (for RecordProcessState).
	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	cmd := exec.CommandContext(runCtx, cfg.Binary, cfg.Args...) //nolint:gosec // Scanner binary is configured, not user input

	if cfg.WorkDir != "" {
		cmd.Dir = cfg.WorkDir
	}

	// Allowlisted environment only (see scanner_env.go): the sensor's API key
	// and other credentials must not leak into scanner processes.
	cmd.Env = ScannerEnviron(cfg.Env)
	ConfigureScannerProcess(cmd)

	// Writers, not pipes read by our own goroutines: exec copies the output
	// and Wait (with the WaitDelay ConfigureScannerProcess set) never waits
	// on a pipe forever.
	stdout := newOutputCapture(cfg.MaxOutputBytes, stdoutLine, stop)
	stderr := newOutputCapture(maxScannerStderr, stderrLine, nil)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start scanner: %w", err)
	}
	ApplyScannerPriority(cmd)

	err := cmd.Wait()
	ReapScannerProcess(cmd)
	RecordProcessState(ctx, cmd.ProcessState)
	stdout.finish()
	stderr.finish()

	result := &ExecResult{
		Stdout:     stdout.Bytes(),
		Stderr:     stderr.stderrBytes(),
		DurationMs: time.Since(start).Milliseconds(),
	}

	if stdout.Overflowed() {
		limit := cfg.MaxOutputBytes
		if limit <= 0 {
			limit = DefaultMaxScannerOutput
		}
		result.ExitCode = -1
		result.Error = fmt.Errorf("%w: %s wrote more than %d bytes and was stopped", ErrScannerOutputTooLarge, cfg.Binary, limit)
		return result, result.Error
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.Error = err
		}
	}

	return result, nil
}

// =============================================================================
// Scanner Installation Check
// =============================================================================

// CheckBinaryInstalled checks if a binary is installed and returns its
// version line: the first non-empty line of VersionOutput. Scanners whose
// version command prints several lines (nuclei, the ProjectDiscovery tools)
// should call VersionOutput and parse the whole text instead.
func CheckBinaryInstalled(ctx context.Context, binary string, versionArgs ...string) (bool, string, error) {
	installed, output, err := VersionOutput(ctx, binary, versionArgs...)
	if !installed || err != nil {
		return installed, "", err
	}
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return true, line, nil
		}
	}
	return true, "", nil
}

// VersionOutput runs `binary versionArgs...` (default "--version") and
// returns its whole output with ANSI color sequences removed. It reads
// stdout, and stderr when stdout is empty: several scanners (nuclei and the
// other ProjectDiscovery tools) print their version banner only to stderr,
// in color. A binary that cannot be started or exits non-zero is reported as
// not installed.
func VersionOutput(ctx context.Context, binary string, versionArgs ...string) (bool, string, error) {
	if len(versionArgs) == 0 {
		versionArgs = []string{"--version"}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, versionArgs...)
	cmd.Env = ScannerEnviron()
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return false, "", nil // Not installed
	}

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		output = stderr.String()
	}
	return true, StripANSI(output), nil
}

// ansiEscape matches terminal control sequences (CSI: colors, cursor moves).
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// StripANSI removes terminal escape sequences (colors) from s.
func StripANSI(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

// VersionAfterLabel returns the first word after `label` on the first line
// of output that contains it, or "" when no line does. For example
// VersionAfterLabel("[INF] Nuclei Engine Version: v3.11.1", "Engine Version:")
// returns "v3.11.1".
func VersionAfterLabel(output, label string) string {
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, label)
		if idx < 0 {
			continue
		}
		if fields := strings.Fields(line[idx+len(label):]); len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}
