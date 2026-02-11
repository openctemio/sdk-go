package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CommandClient interface for command-related API operations.
type CommandClient interface {
	GetCommands(ctx context.Context) (*GetCommandsResponse, error)
	AcknowledgeCommand(ctx context.Context, cmdID string) error
	ReportCommandResult(ctx context.Context, cmdID string, result *CommandResult) error
	ReportCommandProgress(ctx context.Context, cmdID string, progress int, message string) error
}

// Command represents a server command.
type Command struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Priority  string          `json:"priority"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// CommandResult represents the result of command execution.
type CommandResult struct {
	Status        string                 `json:"status"`
	CompletedAt   time.Time              `json:"completed_at"`
	DurationMs    int64                  `json:"duration_ms"`
	ExitCode      int                    `json:"exit_code"`
	FindingsCount int                    `json:"findings_count"`
	Error         string                 `json:"error,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// GetCommandsResponse is the response from GetCommands.
type GetCommandsResponse struct {
	Commands            []*Command `json:"commands"`
	PollIntervalSeconds int        `json:"poll_interval_seconds,omitempty"`
}

// ScanCommandPayload is the payload for scan commands.
type ScanCommandPayload struct {
	Scanner         string                 `json:"scanner"`
	Target          string                 `json:"target"`
	Config          map[string]interface{} `json:"config,omitempty"`
	TimeoutSeconds  int                    `json:"timeout_seconds,omitempty"`
	ReportProgress  bool                   `json:"report_progress,omitempty"`
	CustomTemplates []EmbeddedTemplate     `json:"custom_templates,omitempty"`
}

// EmbeddedTemplate is a custom template embedded in scan command payload.
// Templates are sent from the platform and written to temp dir before scan.
type EmbeddedTemplate struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TemplateType string `json:"template_type"` // nuclei, semgrep, gitleaks
	Content      string `json:"content"`       // Base64-encoded template content (YAML/TOML)
	ContentHash  string `json:"content_hash"`  // SHA256 hash of decoded content for verification
}

// ValidTemplateTypes defines allowed template types for security validation.
var ValidTemplateTypes = map[string]bool{
	"nuclei":   true,
	"semgrep":  true,
	"gitleaks": true,
}

// MaxTemplateSize is the maximum allowed size for a single template (1MB).
const MaxTemplateSize = 1024 * 1024

// MaxTemplateNameLength is the maximum allowed length for template names.
const MaxTemplateNameLength = 128

// ValidateTemplate validates an embedded template for security issues.
// It checks for path traversal, valid template types, and size limits.
func ValidateTemplate(tpl *EmbeddedTemplate) error {
	if tpl == nil {
		return fmt.Errorf("template is nil")
	}

	// Validate ID
	if tpl.ID == "" {
		return fmt.Errorf("template ID is required")
	}

	// Validate Name - check for path traversal
	if tpl.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if len(tpl.Name) > MaxTemplateNameLength {
		return fmt.Errorf("template name too long: max %d characters", MaxTemplateNameLength)
	}

	// SECURITY: Prevent path traversal by ensuring name is just a filename
	baseName := filepath.Base(tpl.Name)
	if baseName != tpl.Name || baseName == "." || baseName == ".." {
		return fmt.Errorf("invalid template name: path traversal not allowed")
	}

	// Check for hidden files (starting with .)
	if len(baseName) > 0 && baseName[0] == '.' {
		return fmt.Errorf("invalid template name: hidden files not allowed")
	}

	// Validate template type
	if !ValidTemplateTypes[tpl.TemplateType] {
		return fmt.Errorf("invalid template type: %s (allowed: nuclei, semgrep, gitleaks)", tpl.TemplateType)
	}

	// Validate content size
	if len(tpl.Content) > MaxTemplateSize {
		return fmt.Errorf("template content too large: max %d bytes", MaxTemplateSize)
	}

	return nil
}

// CollectCommandPayload is the payload for collect commands.
type CollectCommandPayload struct {
	Collector    string                 `json:"collector"`
	SourceConfig map[string]interface{} `json:"source_config,omitempty"`
}

// CommandExecutor executes commands.
type CommandExecutor interface {
	Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error)
}

// CommandExecutionResult is the result of command execution.
type CommandExecutionResult struct {
	DurationMs    int64
	FindingsCount int
	ExitCode      int
	Metadata      map[string]interface{}
}

// CommandPoller polls the server for pending commands.
type CommandPoller struct {
	client        CommandClient
	executor      CommandExecutor
	interval      time.Duration
	maxConcurrent int
	allowedTypes  map[string]bool

	running    bool
	stopCh     chan struct{}
	mu         sync.Mutex
	activeCmds sync.WaitGroup

	verbose bool
}

// CommandPollerConfig configures a CommandPoller.
type CommandPollerConfig struct {
	PollInterval  time.Duration `yaml:"poll_interval" json:"poll_interval"`
	MaxConcurrent int           `yaml:"max_concurrent" json:"max_concurrent"`
	AllowedTypes  []string      `yaml:"allowed_types" json:"allowed_types"`
	Verbose       bool          `yaml:"verbose" json:"verbose"`
}

// DefaultCommandPollerConfig returns default config.
func DefaultCommandPollerConfig() *CommandPollerConfig {
	return &CommandPollerConfig{
		PollInterval:  30 * time.Second,
		MaxConcurrent: 5,
		AllowedTypes:  []string{"scan", "collect", "health_check"},
	}
}

// NewCommandPoller creates a new command poller.
func NewCommandPoller(client CommandClient, executor CommandExecutor, cfg *CommandPollerConfig) *CommandPoller {
	if cfg == nil {
		cfg = DefaultCommandPollerConfig()
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 5
	}

	allowedTypes := make(map[string]bool)
	for _, t := range cfg.AllowedTypes {
		allowedTypes[t] = true
	}
	if len(allowedTypes) == 0 {
		allowedTypes["scan"] = true
		allowedTypes["collect"] = true
		allowedTypes["health_check"] = true
	}

	return &CommandPoller{
		client:        client,
		executor:      executor,
		interval:      cfg.PollInterval,
		maxConcurrent: cfg.MaxConcurrent,
		allowedTypes:  allowedTypes,
		stopCh:        make(chan struct{}),
		verbose:       cfg.Verbose,
	}
}

// Start starts the command poller.
func (p *CommandPoller) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("poller already running")
	}
	p.running = true
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	if p.verbose {
		fmt.Printf("[command-poller] Starting with interval %v\n", p.interval)
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Poll immediately on start
	p.pollAndExecute(ctx)

	for {
		select {
		case <-ctx.Done():
			p.waitForActiveCommands()
			return ctx.Err()
		case <-p.stopCh:
			p.waitForActiveCommands()
			return nil
		case <-ticker.C:
			p.pollAndExecute(ctx)
		}
	}
}

// Stop stops the command poller.
func (p *CommandPoller) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return
	}
	p.running = false
	close(p.stopCh)
}

// waitForActiveCommands waits for all active commands to complete.
func (p *CommandPoller) waitForActiveCommands() {
	if p.verbose {
		fmt.Printf("[command-poller] Waiting for active commands to complete...\n")
	}
	p.activeCmds.Wait()
}

// pollAndExecute polls for commands and executes them.
func (p *CommandPoller) pollAndExecute(ctx context.Context) {
	resp, err := p.client.GetCommands(ctx)
	if err != nil {
		if p.verbose {
			fmt.Printf("[command-poller] Failed to poll commands: %v\n", err)
		}
		return
	}

	if len(resp.Commands) == 0 {
		return
	}

	if p.verbose {
		fmt.Printf("[command-poller] Received %d commands\n", len(resp.Commands))
	}

	for _, cmd := range resp.Commands {
		// Validate command type
		if !p.allowedTypes[cmd.Type] {
			if p.verbose {
				fmt.Printf("[command-poller] Skipping disallowed command type: %s\n", cmd.Type)
			}
			continue
		}

		// Check if command is expired
		if !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt) {
			if p.verbose {
				fmt.Printf("[command-poller] Skipping expired command: %s\n", cmd.ID)
			}
			continue
		}

		// Acknowledge receipt
		if err := p.client.AcknowledgeCommand(ctx, cmd.ID); err != nil {
			if p.verbose {
				fmt.Printf("[command-poller] Failed to acknowledge command %s: %v\n", cmd.ID, err)
			}
			continue
		}

		// Execute asynchronously
		p.activeCmds.Add(1)
		go p.executeCommand(ctx, cmd)
	}
}

// executeCommand executes a single command.
func (p *CommandPoller) executeCommand(ctx context.Context, cmd *Command) {
	defer p.activeCmds.Done()

	startTime := time.Now()

	if p.verbose {
		fmt.Printf("[command-poller] Executing command %s (type: %s)\n", cmd.ID, cmd.Type)
	}

	result, err := p.executor.Execute(ctx, cmd)

	reportResult := &CommandResult{
		CompletedAt: time.Now(),
		DurationMs:  time.Since(startTime).Milliseconds(),
	}

	if err != nil {
		reportResult.Status = "failed"
		reportResult.Error = err.Error()
		if p.verbose {
			fmt.Printf("[command-poller] Command %s failed: %v\n", cmd.ID, err)
		}
	} else {
		reportResult.Status = "completed"
		if result != nil {
			reportResult.DurationMs = result.DurationMs
			reportResult.FindingsCount = result.FindingsCount
			reportResult.ExitCode = result.ExitCode
			reportResult.Metadata = result.Metadata
		}
		if p.verbose {
			fmt.Printf("[command-poller] Command %s completed (findings: %d)\n", cmd.ID, reportResult.FindingsCount)
		}
	}

	// Report result back to server
	if err := p.client.ReportCommandResult(ctx, cmd.ID, reportResult); err != nil {
		if p.verbose {
			fmt.Printf("[command-poller] Failed to report result for command %s: %v\n", cmd.ID, err)
		}
	}
}

// SetVerbose sets verbose mode.
func (p *CommandPoller) SetVerbose(v bool) {
	p.verbose = v
}

// =============================================================================
// Default Command Executor
// =============================================================================

// DefaultCommandExecutor provides default command execution.
type DefaultCommandExecutor struct {
	scanners   map[string]Scanner
	collectors map[string]Collector
	pusher     Pusher
	verbose    bool
}

// NewDefaultCommandExecutor creates a new default executor.
func NewDefaultCommandExecutor(pusher Pusher) *DefaultCommandExecutor {
	return &DefaultCommandExecutor{
		scanners:   make(map[string]Scanner),
		collectors: make(map[string]Collector),
		pusher:     pusher,
	}
}

// AddScanner adds a scanner.
func (e *DefaultCommandExecutor) AddScanner(scanner Scanner) {
	e.scanners[scanner.Name()] = scanner
}

// AddCollector adds a collector.
func (e *DefaultCommandExecutor) AddCollector(collector Collector) {
	e.collectors[collector.Name()] = collector
}

// Execute executes a command.
func (e *DefaultCommandExecutor) Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	switch cmd.Type {
	case "scan":
		return e.executeScan(ctx, cmd)
	case "collect":
		return e.executeCollect(ctx, cmd)
	case "health_check":
		return e.executeHealthCheck(ctx, cmd)
	default:
		return nil, fmt.Errorf("unknown command type: %s", cmd.Type)
	}
}

func (e *DefaultCommandExecutor) executeScan(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	var payload ScanCommandPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal scan payload: %w", err)
	}

	scanner, ok := e.scanners[payload.Scanner]
	if !ok {
		return nil, fmt.Errorf("scanner not found: %s", payload.Scanner)
	}

	if e.verbose {
		fmt.Printf("[executor] Running scanner %s on %s\n", payload.Scanner, payload.Target)
	}

	// Create scan options
	opts := &ScanOptions{
		TargetDir: payload.Target,
		Verbose:   e.verbose,
	}

	// Add config options if provided
	if payload.Config != nil {
		if exclude, ok := payload.Config["exclude"].([]interface{}); ok {
			for _, ex := range exclude {
				if s, ok := ex.(string); ok {
					opts.Exclude = append(opts.Exclude, s)
				}
			}
		}
	}

	// Handle custom templates if provided
	var templateDir string
	var cleanupTemplates func()
	if len(payload.CustomTemplates) > 0 {
		var err error
		templateDir, cleanupTemplates, err = e.writeCustomTemplates(payload.Scanner, payload.CustomTemplates)
		if err != nil {
			return nil, fmt.Errorf("write custom templates: %w", err)
		}
		if cleanupTemplates != nil {
			defer cleanupTemplates()
		}
		// Set template dir in options for scanner to use
		opts.CustomTemplateDir = templateDir
		if e.verbose {
			fmt.Printf("[executor] Using custom templates from %s\n", templateDir)
		}
	}

	// Create context with timeout if specified
	if payload.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(payload.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	// Run scan
	startTime := time.Now()
	scanResult, err := scanner.Scan(ctx, payload.Target, opts)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	result := &CommandExecutionResult{
		DurationMs: time.Since(startTime).Milliseconds(),
		ExitCode:   scanResult.ExitCode,
		Metadata: map[string]interface{}{
			"scanner_name":    scanResult.ScannerName,
			"scanner_version": scanResult.ScannerVersion,
		},
	}

	// Parse and push results if pusher is configured
	if e.pusher != nil && len(scanResult.RawOutput) > 0 {
		// Parse using SARIF parser
		parser := &SARIFParser{}
		report, err := parser.Parse(ctx, scanResult.RawOutput, &ParseOptions{
			ToolName: scanner.Name(),
		})
		if err != nil {
			return result, fmt.Errorf("parse failed: %w", err)
		}

		result.FindingsCount = len(report.Findings)

		// Push findings
		_, err = e.pusher.PushFindings(ctx, report)
		if err != nil {
			return result, fmt.Errorf("push failed: %w", err)
		}
	}

	return result, nil
}

// MaxTemplatesPerCommand is the maximum number of templates allowed per command.
const MaxTemplatesPerCommand = 50

// writeCustomTemplates writes embedded templates to a temp directory.
// Returns the temp directory path and a cleanup function.
// SECURITY: This function validates all templates before writing to prevent:
// - Path traversal attacks via malicious template names
// - Oversized templates that could exhaust disk space
// - Invalid template types
func (e *DefaultCommandExecutor) writeCustomTemplates(scannerName string, templates []EmbeddedTemplate) (string, func(), error) {
	// SECURITY: Limit number of templates to prevent resource exhaustion
	if len(templates) > MaxTemplatesPerCommand {
		return "", nil, fmt.Errorf("too many templates: max %d allowed, got %d", MaxTemplatesPerCommand, len(templates))
	}

	// SECURITY: Validate all templates BEFORE creating temp directory
	for i := range templates {
		if err := ValidateTemplate(&templates[i]); err != nil {
			return "", nil, fmt.Errorf("invalid template at index %d: %w", i, err)
		}
	}

	// Create temp directory for templates
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("openctem-templates-%s-*", scannerName))
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	// Track written filenames to detect duplicates
	writtenNames := make(map[string]bool)

	// Write each template to the temp directory
	for _, tpl := range templates {
		// Verify content hash if provided (mandatory for integrity)
		if tpl.ContentHash != "" {
			hash := sha256.Sum256([]byte(tpl.Content))
			computedHash := hex.EncodeToString(hash[:])
			if computedHash != tpl.ContentHash {
				cleanup()
				return "", nil, fmt.Errorf("template %s hash mismatch: expected %s, got %s", tpl.Name, tpl.ContentHash, computedHash)
			}
		}

		// Determine file extension based on template type
		ext := ".yaml"
		if tpl.TemplateType == "gitleaks" {
			ext = ".toml"
		}

		// SECURITY: Use filepath.Base to ensure we only have filename, no directory components
		// This prevents path traversal even if validation was somehow bypassed
		filename := filepath.Base(tpl.Name)
		if filename == "." || filename == ".." || filename == "" {
			cleanup()
			return "", nil, fmt.Errorf("invalid template filename: %s", tpl.Name)
		}

		// Add extension if missing
		if filepath.Ext(filename) == "" {
			filename += ext
		}

		// SECURITY: Check for duplicate filenames (could indicate attack)
		if writtenNames[filename] {
			cleanup()
			return "", nil, fmt.Errorf("duplicate template filename: %s", filename)
		}
		writtenNames[filename] = true

		// SECURITY: Construct path and verify it's still within tmpDir
		filePath := filepath.Join(tmpDir, filename)
		if !isSubPath(tmpDir, filePath) {
			cleanup()
			return "", nil, fmt.Errorf("template path escape detected: %s", filename)
		}

		// Write template content to file with restrictive permissions
		if err := os.WriteFile(filePath, []byte(tpl.Content), 0600); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write template %s: %w", tpl.Name, err)
		}

		if e.verbose {
			fmt.Printf("[executor] Wrote custom template: %s\n", filePath)
		}
	}

	return tmpDir, cleanup, nil
}

// isSubPath checks if child is under parent directory.
// SECURITY: Used to prevent path traversal after filepath.Join.
func isSubPath(parent, child string) bool {
	parentAbs, err := filepath.Abs(parent)
	if err != nil {
		return false
	}
	childAbs, err := filepath.Abs(child)
	if err != nil {
		return false
	}

	// Ensure parent ends with separator for accurate prefix matching
	if !os.IsPathSeparator(parentAbs[len(parentAbs)-1]) {
		parentAbs += string(os.PathSeparator)
	}

	return len(childAbs) > len(parentAbs) && childAbs[:len(parentAbs)] == parentAbs
}

func (e *DefaultCommandExecutor) executeCollect(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	var payload CollectCommandPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal collect payload: %w", err)
	}

	collector, ok := e.collectors[payload.Collector]
	if !ok {
		return nil, fmt.Errorf("collector not found: %s", payload.Collector)
	}

	if e.verbose {
		fmt.Printf("[executor] Running collector %s\n", payload.Collector)
	}

	startTime := time.Now()
	collectResult, err := collector.Collect(ctx, &CollectOptions{})
	if err != nil {
		return nil, fmt.Errorf("collect failed: %w", err)
	}

	result := &CommandExecutionResult{
		DurationMs: time.Since(startTime).Milliseconds(),
		Metadata: map[string]interface{}{
			"source_name": collectResult.SourceName,
			"source_type": collectResult.SourceType,
			"total_items": collectResult.TotalItems,
		},
	}

	// Push collected findings
	if e.pusher != nil {
		for _, report := range collectResult.Reports {
			result.FindingsCount += len(report.Findings)
			_, err := e.pusher.PushFindings(ctx, report)
			if err != nil {
				return result, fmt.Errorf("push failed: %w", err)
			}
		}
	}

	return result, nil
}

func (e *DefaultCommandExecutor) executeHealthCheck(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	result := &CommandExecutionResult{
		DurationMs: 0,
		Metadata: map[string]interface{}{
			"scanners":   len(e.scanners),
			"collectors": len(e.collectors),
			"status":     "healthy",
		},
	}

	// Check all scanners
	scannerStatus := make(map[string]string)
	for name, scanner := range e.scanners {
		installed, version, err := scanner.IsInstalled(ctx)
		if err != nil || !installed {
			scannerStatus[name] = "not_installed"
		} else {
			scannerStatus[name] = version
		}
	}
	result.Metadata["scanner_status"] = scannerStatus

	return result, nil
}

// SetVerbose sets verbose mode.
func (e *DefaultCommandExecutor) SetVerbose(v bool) {
	e.verbose = v
}
