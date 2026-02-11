package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
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
	Env     map[string]string // Environment variables
	Timeout time.Duration     // Execution timeout
	Verbose bool              // Stream output to logs
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
func ExecuteScanner(ctx context.Context, cfg *ExecConfig) (*ExecResult, error) {
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, cfg.Binary, cfg.Args...) //nolint:gosec // Scanner binary is configured, not user input

	if cfg.WorkDir != "" {
		cmd.Dir = cfg.WorkDir
	}

	// Set environment variables
	if len(cfg.Env) > 0 {
		env := cmd.Environ()
		for k, v := range cfg.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env
	}

	// Create pipes for stdout/stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	start := time.Now()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start scanner: %w", err)
	}

	// Capture output with optional streaming
	var wg sync.WaitGroup
	var stdoutBuf, stderrBuf []byte

	wg.Add(2)
	go func() {
		defer wg.Done()
		stdoutBuf = captureOutput(stdout, cfg.Verbose, "stdout")
	}()
	go func() {
		defer wg.Done()
		stderrBuf = captureOutput(stderr, cfg.Verbose, "stderr")
	}()

	// Wait for output capture to complete
	wg.Wait()

	// Wait for process to exit
	err = cmd.Wait()

	result := &ExecResult{
		Stdout:     stdoutBuf,
		Stderr:     stderrBuf,
		DurationMs: time.Since(start).Milliseconds(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.Error = err
		}
	}

	return result, nil
}

// captureOutput reads from a pipe and optionally streams to logs.
func captureOutput(r io.ReadCloser, stream bool, prefix string) []byte {
	var buf []byte
	reader := bufio.NewReader(r)

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			buf = append(buf, line...)
			if stream {
				fmt.Printf("[%s] %s", prefix, string(line))
			}
		}
		if err != nil {
			break
		}
	}

	return buf
}

// =============================================================================
// Scanner Output Streaming
// =============================================================================

// OutputHandler processes scanner output in real-time.
type OutputHandler func(line string, isError bool)

// StreamScanner runs a scanner with real-time output handling.
func StreamScanner(ctx context.Context, cfg *ExecConfig, handler OutputHandler) (*ExecResult, error) {
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, cfg.Binary, cfg.Args...) //nolint:gosec // Scanner binary is configured, not user input

	if cfg.WorkDir != "" {
		cmd.Dir = cfg.WorkDir
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	start := time.Now()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start scanner: %w", err)
	}

	// Stream output with handler
	var wg sync.WaitGroup
	var stdoutBuf, stderrBuf []byte

	wg.Add(2)
	go func() {
		defer wg.Done()
		stdoutBuf = streamWithHandler(stdout, handler, false)
	}()
	go func() {
		defer wg.Done()
		stderrBuf = streamWithHandler(stderr, handler, true)
	}()

	wg.Wait()
	err = cmd.Wait()

	result := &ExecResult{
		Stdout:     stdoutBuf,
		Stderr:     stderrBuf,
		DurationMs: time.Since(start).Milliseconds(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.Error = err
		}
	}

	return result, nil
}

func streamWithHandler(r io.ReadCloser, handler OutputHandler, isError bool) []byte {
	var buf []byte
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		buf = append(buf, []byte(line+"\n")...)
		if handler != nil {
			handler(line, isError)
		}
	}

	return buf
}

// =============================================================================
// Scanner Installation Check
// =============================================================================

// CheckBinaryInstalled checks if a binary is installed and returns its version.
func CheckBinaryInstalled(ctx context.Context, binary string, versionArgs ...string) (bool, string, error) {
	if len(versionArgs) == 0 {
		versionArgs = []string{"--version"}
	}

	cmd := exec.CommandContext(ctx, binary, versionArgs...)
	output, err := cmd.Output()
	if err != nil {
		return false, "", nil // Not installed
	}

	version := string(output)
	// Try to extract first line as version
	if idx := indexNewline(version); idx > 0 {
		version = version[:idx]
	}

	return true, version, nil
}

func indexNewline(s string) int {
	for i, c := range s {
		if c == '\n' || c == '\r' {
			return i
		}
	}
	return -1
}
