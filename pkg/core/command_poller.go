package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/resource"
)

// CommandClient interface for command-related API operations.
type CommandClient interface {
	GetCommands(ctx context.Context) (*GetCommandsResponse, error)
	AcknowledgeCommand(ctx context.Context, cmdID string) error
	StartCommand(ctx context.Context, cmdID string) error
	ReportCommandResult(ctx context.Context, cmdID string, result *CommandResult) error
	ReportCommandProgress(ctx context.Context, cmdID string, progress int, message string) error
}

// LimitedCommandClient is a CommandClient that can poll for at most limit
// commands. The CommandPoller uses it, when the client implements it, to ask
// for no more commands than it has free slots (api RFC-030 §5.9), so the
// platform keeps the rest for sensors that can run them now. *client.Client
// implements it.
type LimitedCommandClient interface {
	GetCommandsLimit(ctx context.Context, limit int) (*GetCommandsResponse, error)
}

// LoadReporter reports how busy a sensor is: the commands it runs now and
// how many it runs at once. A BaseSensor with a LoadReporter
// (BaseSensor.SetLoadReporter) puts both on every heartbeat. *CommandPoller
// implements it.
type LoadReporter interface {
	ActiveJobs() int
	MaxJobs() int
}

// Command represents a server command.
type Command struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Priority  string          `json:"priority"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	// LeaseEpoch and LeaseExpiresAt are the command's lease as the poll
	// saw it (protocol v2, api RFC-035 D6): the claim that follows starts
	// a new epoch, which the client keeps and echoes on complete and fail.
	// Zero from a platform without leases.
	LeaseEpoch     int       `json:"lease_epoch,omitempty"`
	LeaseExpiresAt time.Time `json:"lease_expires_at,omitzero"`
	// Claimed is true when the poll already claimed the command for this
	// sensor (claim-N, api RFC-046 §11). The poller still acknowledges it
	// (a replay) when it runs it, and releases it when it does not.
	Claimed bool `json:"-"`
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
	// Refusal is set when a policy refused the command (RefusalOf): it was
	// never run, or was stopped by the kill switch.
	Refusal *Refusal `json:"refusal,omitempty"`
}

// GetCommandsResponse is the response from GetCommands.
type GetCommandsResponse struct {
	Commands            []*Command `json:"commands"`
	PollIntervalSeconds int        `json:"poll_interval_seconds,omitempty"`
}

// ScanCommandPayload is the payload for scan commands.
type ScanCommandPayload struct {
	Scanner string `json:"scanner"`
	// Target is the single scan target. The platform omits it when a job has
	// several targets for a list-capable scanner (nuclei) and sends only
	// Targets; when both are set, Target is the job.
	Target string `json:"target"`
	// Targets is the full target list (additive).
	Targets         []string               `json:"targets,omitempty"`
	Config          map[string]interface{} `json:"config,omitempty"`
	TimeoutSeconds  int                    `json:"timeout_seconds,omitempty"`
	ReportProgress  bool                   `json:"report_progress,omitempty"`
	CustomTemplates []EmbeddedTemplate     `json:"custom_templates,omitempty"`
	// CustomTemplatesEnvelope is the platform's signed manifest of
	// CustomTemplates (TemplateManifest in a DSSE envelope). Custom
	// templates run only when it verifies (see TemplateVerifier.Verify).
	CustomTemplatesEnvelope *SignedEnvelope `json:"custom_templates_envelope,omitempty"`
}

// EmbeddedTemplate is a custom template embedded in scan command payload.
// Templates are sent from the platform and written to temp dir before scan.
type EmbeddedTemplate struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TemplateType string `json:"template_type"` // nuclei, semgrep, betterleaks
	Content      string `json:"content"`       // Base64-encoded template content (YAML/TOML)
	ContentHash  string `json:"content_hash"`  // SHA256 hash of decoded content for verification
}

// MultiTargetScanner is a Scanner that can scan a list of targets in one run
// (nuclei with -l). The command executor uses it when a scan command carries
// several targets.
type MultiTargetScanner interface {
	Scanner
	ScanTargets(ctx context.Context, targets []string, opts *ScanOptions) (*ScanResult, error)
}

// MaxScanTargets bounds the targets one scan command may carry (the
// platform's per-run limit).
const MaxScanTargets = 10000

// maxRefusedListed caps how many refused targets an error message names.
const maxRefusedListed = 10

// ValidTemplateTypes defines allowed template types for security validation.
// A retired type ("gitleaks") is accepted through CanonicalScannerName.
var ValidTemplateTypes = map[string]bool{
	"nuclei":           true,
	"semgrep":          true,
	ScannerBetterleaks: true,
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
	if !ValidTemplateTypes[CanonicalScannerName(tpl.TemplateType)] {
		return fmt.Errorf("invalid template type: %s (allowed: nuclei, semgrep, betterleaks)", tpl.TemplateType)
	}

	// Validate content size. Content is base64, so bound the encoded form of
	// a MaxTemplateSize template; the decoded size is checked again on write.
	if len(tpl.Content) > base64.StdEncoding.EncodedLen(MaxTemplateSize) {
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
	// gate refuses commands before they run (SetCommandGate).
	gate         atomic.Pointer[func(*Command) error]
	allowedTypes map[string]bool

	running    bool
	stopCh     chan struct{}
	mu         sync.Mutex
	activeCmds sync.WaitGroup
	// sem bounds the number of commands executing concurrently to
	// maxConcurrent. Without it a large command batch spawned an
	// unbounded number of goroutines/scans. A slot is taken BEFORE a command
	// is claimed (acknowledged) and released when it ends, so the sensor
	// never holds a claimed command it is not running: such a command was
	// re-queued by the platform's acknowledged-command reaper while this
	// sensor still held it, and then ran twice (api RFC-030 B6).
	sem chan struct{}

	// slotFreed is signaled when a command ends while the platform may
	// still have work for this sensor (backlog), so the poller claims it
	// without waiting for the next tick or doorbell ring.
	slotFreed chan struct{}
	backlog   atomic.Bool

	// verbose is atomic: SetVerbose may be called concurrently with the
	// poll/execute goroutines that read it.
	verbose atomic.Bool

	// doorbell, when set, drives polling from the heartbeat (SetDoorbell).
	doorbell   *Doorbell
	safetyPoll time.Duration

	// authGate is the heartbeat's AuthGate (SetAuthGate, or the one
	// attached to a shared doorbell): no polling while it says the
	// platform rejects the key.
	authGate *AuthGate
	// ownGate and ownNext back off this poller's own polls after a 401/403
	// when no heartbeat gate is shared with it.
	ownGate *AuthGate
	ownNext time.Time

	// resources, when set, sizes the slots from the sensor's CPU, memory
	// and learned tool costs (SetResourceManager); without it the slots
	// are MaxConcurrent.
	resources *resource.Manager
	// queue holds the commands this sensor claimed and has not finished:
	// per-host politeness, cancellation, the heartbeat's lease list.
	queue *localQueue
	// cmdBase is the parent of every command's context: the Start context
	// without its cancellation, so stopping drains instead of killing.
	cmdBase    context.Context
	draining   atomic.Bool
	drainGrace time.Duration

	// local is the sensor-local policy (SetLocalPolicy): admission before
	// every command and the kill switch. killed is true while its kill
	// switch is engaged.
	local  atomic.Pointer[LocalPolicy]
	killed atomic.Bool
}

// errKilledByLocalPolicy cancels running commands when the sensor owner
// engages the local kill switch.
var errKilledByLocalPolicy = errors.New("stopped by the local kill switch")

// KillSwitchCheckInterval is how often a poller with a local policy checks
// its kill switch file while commands run.
const KillSwitchCheckInterval = 2 * time.Second

// SetLocalPolicy makes the poller enforce the sensor-local policy (api
// RFC-040 §5.7): every command passes LocalPolicy.AdmitCommand after it is
// claimed and before any executor or tool sees it, and a refused command is
// reported failed with "refused by local policy: <rule>: …", never run and
// never dropped silently. While the kill switch is engaged the poller
// claims nothing and stops the commands it runs (reported failed). It is
// checked before the gate of SetCommandGate, so no platform policy can
// widen it. Call before Start.
func (p *CommandPoller) SetLocalPolicy(lp *LocalPolicy) {
	p.local.Store(lp)
}

// LocalKillSwitch reports whether the local kill switch is engaged now.
func (p *CommandPoller) LocalKillSwitch() bool {
	return p.local.Load().KillSwitchEngaged()
}

// checkKillSwitch notes a change of the local kill switch: engaged, it
// stops every running command.
func (p *CommandPoller) checkKillSwitch() bool {
	engaged := p.local.Load().KillSwitchEngaged()
	if p.killed.Swap(engaged) == engaged {
		return engaged
	}
	if engaged {
		fmt.Printf("[command-poller] Local kill switch engaged: claiming nothing and stopping %d running command(s)\n", p.ActiveJobs())
		p.queue.cancelAll(errKilledByLocalPolicy)
	} else {
		fmt.Printf("[command-poller] Local kill switch released: polling again\n")
	}
	return engaged
}

// CommandPollerConfig configures a CommandPoller.
type CommandPollerConfig struct {
	PollInterval  time.Duration `yaml:"poll_interval" json:"poll_interval"`
	MaxConcurrent int           `yaml:"max_concurrent" json:"max_concurrent"`
	AllowedTypes  []string      `yaml:"allowed_types" json:"allowed_types"`
	Verbose       bool          `yaml:"verbose" json:"verbose"`
	// DoorbellSafetyPoll is how often the poller still polls on its own
	// while the heartbeat doorbell is active. Default 5m.
	DoorbellSafetyPoll time.Duration `yaml:"doorbell_safety_poll" json:"doorbell_safety_poll"`
	// DrainGrace is how long a stopping poller lets running commands finish
	// before it cancels them and releases them to the platform. Default 30s.
	DrainGrace time.Duration `yaml:"drain_grace" json:"drain_grace"`
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

	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 5
	}

	p := &CommandPoller{
		client:        client,
		executor:      executor,
		interval:      cfg.PollInterval,
		maxConcurrent: maxConcurrent,
		allowedTypes:  allowedTypes,
		stopCh:        make(chan struct{}),
		sem:           make(chan struct{}, maxConcurrent),
		slotFreed:     make(chan struct{}, 1),
		safetyPoll:    cfg.DoorbellSafetyPoll,
		ownGate:       NewAuthGate(nil),
		queue:         newLocalQueue(),
		cmdBase:       context.Background(),
		drainGrace:    cfg.DrainGrace,
	}
	if p.drainGrace <= 0 {
		p.drainGrace = DefaultDrainGrace
	}
	if p.safetyPoll <= 0 {
		p.safetyPoll = DefaultDoorbellSafetyPoll
	}
	p.verbose.Store(cfg.Verbose)
	return p
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
	p.cmdBase = context.WithoutCancel(ctx)
	p.draining.Store(false)
	p.mu.Unlock()
	// Start runs the poll loop synchronously; reset running on EVERY return
	// (incl. ctx cancellation) so a later Start() isn't rejected with
	// "poller already running" when nothing is actually polling.
	defer func() {
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
	}()

	if p.verbose.Load() {
		fmt.Printf("[command-poller] Starting with interval %v\n", p.interval)
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// wake is nil (never fires) without a doorbell.
	var wake <-chan struct{}
	if p.doorbell != nil {
		wake = p.doorbell.Wake()
	}

	// The local kill switch is checked every KillSwitchCheckInterval while a
	// local policy is set (nil channel otherwise).
	var killTick <-chan time.Time
	if p.local.Load() != nil {
		kt := time.NewTicker(KillSwitchCheckInterval)
		defer kt.Stop()
		killTick = kt.C
	}

	// Poll immediately on start
	p.pollAndExecute(ctx)
	lastPoll := time.Now()

	for {
		select {
		case <-killTick:
			// Released: poll at once instead of waiting for the next tick.
			if was := p.killed.Load(); !p.checkKillSwitch() && was {
				p.pollAndExecute(ctx)
				lastPoll = time.Now()
			}
		case <-ctx.Done():
			p.drain()
			return ctx.Err()
		case <-p.stopCh:
			p.drain()
			return nil
		case <-wake:
			// The platform reported claimable work: poll now (a no-op
			// without a free slot; the next slot that frees polls).
			p.pollAndExecute(ctx)
			lastPoll = time.Now()
		case <-p.slotFreed:
			// A command ended and the last poll suggested more work.
			p.pollAndExecute(ctx)
			lastPoll = time.Now()
		case <-ticker.C:
			// With the doorbell active the fixed poll is replaced by the
			// doorbell plus a long safety poll; without hints (an older
			// server, or heartbeats failing) poll on every tick as before.
			if p.doorbell != nil && p.doorbell.HintsActive() && time.Since(lastPoll) < p.safetyPoll {
				continue
			}
			p.pollAndExecute(ctx)
			lastPoll = time.Now()
		}
	}
}

// SetDoorbell makes the poller follow the heartbeat doorbell: it polls when
// the doorbell rings, and while the server sends hints it drops the fixed
// interval for a long safety poll (CommandPollerConfig.DoorbellSafetyPoll).
// While the platform has paused or drained the sensor it claims nothing.
// Share d with the heartbeat (BaseSensor.SetDoorbell). Call before Start.
func (p *CommandPoller) SetDoorbell(d *Doorbell) {
	p.doorbell = d
	if d != nil {
		d.setCancelHandler(func(ids []string) { p.CancelCommands(ids...) })
	}
}

// SetResourceManager sizes the poller's slots from m: the jobs that fit the
// sensor's CPU and memory for its tools' learned cost, at most m's cap,
// narrowed after OOM kills, timeouts and throttling. Every finished command
// teaches m its cost. The heartbeat then reports resources and capacity.
// Call before Start.
func (p *CommandPoller) SetResourceManager(m *resource.Manager) {
	p.resources = m
	if m != nil && m.MaxSlots() != p.maxConcurrent {
		p.maxConcurrent = m.MaxSlots()
		p.sem = make(chan struct{}, p.maxConcurrent)
	}
}

// SetCommandGate sets a check every command passes before it runs: a
// non-nil error reports the command failed with it and never executes it.
// A BaseSensor's CommandToolGate refuses tools outside the platform's
// policy (api RFC-033 §6.12). nil removes the check. Safe at any time.
func (p *CommandPoller) SetCommandGate(gate func(*Command) error) {
	if gate == nil {
		p.gate.Store(nil)
		return
	}
	p.gate.Store(&gate)
}

// CancelCommands cancels held commands (the platform's cancel_command_ids):
// a running one is stopped (its context is canceled), and each is released
// back to the platform instead of reported. Ids not held are ignored.
func (p *CommandPoller) CancelCommands(ids ...string) {
	for _, id := range ids {
		if p.queue.cancel(id, errCanceledByPlatform) && p.verbose.Load() {
			fmt.Printf("[command-poller] Canceling command %s (platform)\n", id)
		}
	}
}

// QueueStats is the local queue now.
func (p *CommandPoller) QueueStats() QueueStats {
	st, _ := p.queue.snapshot(time.Now())
	return st
}

// HeldCommandIDs are the commands this sensor holds (claimed, not
// finished), sorted: the lease list a heartbeat carries as "running".
func (p *CommandPoller) HeldCommandIDs() []string {
	_, ids := p.queue.snapshot(time.Now())
	return ids
}

// ReportStatus fills a heartbeat with the poller's work: active jobs, the
// local queue, the held ids and, with a resource manager, resources and
// capacity. It implements StatusReporter.
func (p *CommandPoller) ReportStatus(status *SensorStatus) {
	if status == nil {
		return
	}
	st, ids := p.queue.snapshot(time.Now())
	active := len(p.sem)
	status.ActiveJobs = active
	status.ActiveJobsReported = true
	status.Queue = &st
	status.RunningCommands = ids
	if p.resources != nil {
		res, capacity := p.resources.Snapshot(active)
		status.Resources = &res
		status.Capacity = &capacity
		// The operator ceiling (max_concurrent_jobs) is the manager's cap.
		// Without one the poller's bound is the manager's HardMax, a safety
		// bound and not a capacity: nothing is reported and the platform
		// goes by the slots.
		if status.MaxConcurrentJobs == 0 {
			status.MaxConcurrentJobs = p.resources.Cap()
		}
	}
}

// drain stops claiming, lets running commands finish for the drain grace,
// then cancels the rest; canceled commands are released to the platform.
func (p *CommandPoller) drain() {
	p.draining.Store(true)
	done := make(chan struct{})
	go func() { p.activeCmds.Wait(); close(done) }()
	select {
	case <-done:
		return
	case <-time.After(p.drainGrace):
	}
	fmt.Printf("[command-poller] Drain grace (%s) over: releasing %d unfinished commands to the platform\n", p.drainGrace, p.ActiveJobs())
	p.queue.cancelAll(errDrained)
	<-done
}

// dropClaimed hands back a command the poll claimed for this sensor
// (claim-N) that the poller will not run, so the platform offers it to
// another sensor at once instead of after its lease. A command the poll only
// listed needs nothing: it is still pending.
func (p *CommandPoller) dropClaimed(cmd *Command, reason string) {
	if cmd == nil || !cmd.Claimed {
		return
	}
	go p.release(cmd.ID, reason)
}

// release hands a command back to the platform (best-effort).
func (p *CommandPoller) release(id, reason string) {
	rc, ok := p.client.(ReleasingCommandClient)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(p.cmdBase), 15*time.Second)
	defer cancel()
	if err := rc.ReleaseCommand(ctx, id, reason); err != nil {
		fmt.Printf("[command-poller] Could not release command %s (%s): %v\n", id, reason, err)
	} else if p.verbose.Load() {
		fmt.Printf("[command-poller] Released command %s (%s)\n", id, reason)
	}
}

// SetAuthGate shares the heartbeat's AuthGate (BaseSensor.AuthGate) with the
// poller: it does not poll while the platform rejects the key, and resumes
// with the first accepted heartbeat. A poller sharing the sensor's doorbell
// already gets it. Call before Start.
func (p *CommandPoller) SetAuthGate(g *AuthGate) {
	p.authGate = g
}

// sharedGate returns the heartbeat's AuthGate, or nil when none is shared.
func (p *CommandPoller) sharedGate() *AuthGate {
	if p.authGate != nil {
		return p.authGate
	}
	if p.doorbell != nil {
		return p.doorbell.getAuthGate()
	}
	return nil
}

// keyHint names the client's API key for log lines without revealing it.
func (p *CommandPoller) keyHint() string {
	if h, ok := p.client.(APIKeyHinter); ok {
		return h.APIKeyHint()
	}
	return "(unknown)"
}

// paused reports whether the platform paused or drained this sensor.
func (p *CommandPoller) paused() bool {
	return p.doorbell != nil && p.doorbell.Paused()
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

// ActiveJobs is the number of commands this poller holds now (claimed and
// running). It implements LoadReporter.
func (p *CommandPoller) ActiveJobs() int {
	return len(p.sem)
}

// MaxJobs is the most commands this poller runs at once: the configured
// cap (CommandPollerConfig.MaxConcurrent, or the resource manager's). The
// live slot count is at most this. It implements LoadReporter. With a
// resource manager the heartbeat reports the live slots (ReportStatus)
// rather than this bound.
func (p *CommandPoller) MaxJobs() int {
	return p.maxConcurrent
}

// slotLimit is the live slot count: MaxConcurrent, or the resource
// manager's dynamic slots.
func (p *CommandPoller) slotLimit() int {
	limit := cap(p.sem)
	if p.resources != nil {
		limit = min(limit, p.resources.Slots(len(p.sem)))
	}
	return max(limit, 1)
}

// freeSlots is the number of commands the poller can start now.
func (p *CommandPoller) freeSlots() int {
	return max(p.slotLimit()-len(p.sem), 0)
}

// getCommands polls for at most limit commands when the client supports a
// limit, else for whatever the client returns.
func (p *CommandPoller) getCommands(ctx context.Context, limit int) (*GetCommandsResponse, error) {
	if lc, ok := p.client.(LimitedCommandClient); ok {
		return lc.GetCommandsLimit(ctx, limit)
	}
	return p.client.GetCommands(ctx)
}

// waitForActiveCommands waits for all active commands to complete.
func (p *CommandPoller) waitForActiveCommands() {
	if p.verbose.Load() {
		fmt.Printf("[command-poller] Waiting for active commands to complete...\n")
	}
	p.activeCmds.Wait()
}

// pollAndExecute polls for commands and executes them.
func (p *CommandPoller) pollAndExecute(ctx context.Context) {
	// Stopping: claim nothing more.
	if p.draining.Load() {
		return
	}
	// Stopped by the sensor owner (local kill switch): claim nothing; the
	// heartbeat says "paused by local policy".
	if p.checkKillSwitch() {
		return
	}
	// Paused by the platform: claim nothing. Running commands finish.
	if p.paused() {
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Not polling: %s\n", p.doorbell.State())
		}
		return
	}
	// The platform rejects the key: polling would only collect more 401s.
	// The heartbeat keeps checking (with backoff) and lifts this.
	gate := p.sharedGate()
	if gate.Rejected() {
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Not polling: the platform rejected the API key\n")
		}
		return
	}
	if gate == nil && time.Now().Before(p.ownNext) {
		return
	}
	// No free slot: claim nothing. Claiming now would only park the command
	// here, acknowledged and not running, until the platform's reaper hands
	// it to another sensor while this one still holds it. Poll again when a
	// slot frees.
	free := p.freeSlots()
	if free <= 0 {
		p.backlog.Store(true)
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Not polling: all %d slots busy\n", p.maxConcurrent)
		}
		return
	}
	if p.verbose.Load() && p.doorbell != nil {
		fmt.Printf("[command-poller] %s Polling for commands (%d free slots)\n", time.Now().Format("15:04:05.000"), free)
	}
	resp, err := p.getCommands(ctx, free)
	if gate != nil {
		gate.MarkRejected(err, p.keyHint())
	} else if backoff := p.ownGate.Observe(err, p.keyHint()); backoff > 0 {
		p.ownNext = time.Now().Add(backoff)
	} else {
		p.ownNext = time.Time{}
	}
	if err != nil {
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Failed to poll commands: %v\n", err)
		}
		return
	}

	// A full page means the platform may hold more for us: poll again as
	// soon as a slot frees.
	p.backlog.Store(len(resp.Commands) >= free)
	if len(resp.Commands) == 0 {
		return
	}

	if p.verbose.Load() {
		fmt.Printf("[command-poller] Received %d commands\n", len(resp.Commands))
	}

	// Local order: priority class, then priority (the platform's order
	// otherwise).
	orderCommands(resp.Commands)
	limit := p.slotLimit()

	for i, cmd := range resp.Commands {
		// Paused while this batch was being claimed: leave the rest pending
		// (unacknowledged) for later or for another sensor; hand back the
		// ones the poll already claimed (claim-N).
		if p.paused() {
			for _, rest := range resp.Commands[i:] {
				p.dropClaimed(rest, "sensor paused")
			}
			return
		}
		// Validate command type
		if !p.allowedTypes[cmd.Type] {
			if p.verbose.Load() {
				fmt.Printf("[command-poller] Skipping disallowed command type: %s\n", cmd.Type)
			}
			p.dropClaimed(cmd, "command type not allowed on this sensor")
			continue
		}

		// Check if command is expired
		if !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt) {
			if p.verbose.Load() {
				fmt.Printf("[command-poller] Skipping expired command: %s\n", cmd.ID)
			}
			p.dropClaimed(cmd, "command expired")
			continue
		}

		// Take a slot BEFORE claiming, so at most the live slot count of
		// commands are claimed or running (and at most that many goroutines
		// exist). Only this loop takes slots, so the free slots counted
		// above are still free; a client that ignores the limit and returns
		// more is answered by leaving the extra commands pending (unclaimed)
		// for later or for another sensor.
		if len(p.sem) >= limit {
			p.backlog.Store(true)
			p.dropClaimed(cmd, "no free slot")
			continue
		}
		select {
		case p.sem <- struct{}{}:
		default:
			p.backlog.Store(true)
			if p.verbose.Load() {
				fmt.Printf("[command-poller] No free slot: leaving command %s pending\n", cmd.ID)
			}
			p.dropClaimed(cmd, "no free slot")
			continue
		}

		// Politeness: at most per_host_concurrency held commands touch one
		// host. A command over the limit is not claimed at all (it stays
		// pending on the platform, for later or for another sensor).
		meta := parseCommandMeta(cmd)
		perHost := meta.Limits.PerHostConcurrency
		if perHost <= 0 {
			perHost = DefaultPerHostConcurrency
		}
		if !p.queue.admit(cmd.ID, commandHosts(meta), perHost, time.Now()) {
			<-p.sem
			p.backlog.Store(true)
			if p.verbose.Load() {
				fmt.Printf("[command-poller] Leaving command %s pending: its hosts are busy here\n", cmd.ID)
			}
			p.dropClaimed(cmd, "its hosts are busy on this sensor")
			continue
		}

		// Claim (acknowledge) it now that a slot is held.
		if err := p.client.AcknowledgeCommand(ctx, cmd.ID); err != nil {
			p.queue.forget(cmd.ID)
			<-p.sem
			if p.verbose.Load() {
				fmt.Printf("[command-poller] Failed to acknowledge command %s: %v\n", cmd.ID, err)
			}
			continue
		}

		// Execute asynchronously, in a context of its own: stopping the
		// poller drains (DrainGrace) instead of killing it at once.
		cmdCtx, cancel := context.WithCancelCause(p.cmdBase)
		p.queue.setCancel(cmd.ID, cancel)
		p.activeCmds.Add(1)
		go p.executeCommand(cmdCtx, cmd)
	}
}

// executeCommand executes a single command.
func (p *CommandPoller) executeCommand(ctx context.Context, cmd *Command) {
	defer func() {
		p.queue.cancel(cmd.ID, context.Canceled) // free the context
		p.queue.forget(cmd.ID)
		<-p.sem
		if p.backlog.Load() {
			select {
			case p.slotFreed <- struct{}{}:
			default:
			}
		}
		p.activeCmds.Done()
	}()

	startTime := time.Now()
	// Results pushed while executing belong to this command: a Pusher with
	// an outbox binds them to it and reports the command only after they
	// were accepted.
	ctx = WithCommandID(ctx, cmd.ID)
	ctx, usage := withUsageRecorder(ctx)

	// Stopping (or canceled) before it started: hand it back unstarted.
	if p.draining.Load() || ctx.Err() != nil {
		p.release(cmd.ID, releaseReason(ctx, ReleaseReasonDraining))
		return
	}

	if p.verbose.Load() {
		fmt.Printf("[command-poller] Executing command %s (type: %s)\n", cmd.ID, cmd.Type)
	}

	// Transition the command to "running" before executing. The server's state
	// machine is pending -> acknowledged -> running -> completed, and it rejects
	// a completion from any state other than running ("command must be running to
	// complete"). Without this call the command executes but its result is never
	// recorded.
	//
	// A failed start means the command is not this sensor's to run: the
	// platform re-queued it (the acknowledged-command reaper), handed it to
	// another sensor, canceled it, or could not record the start. Running it
	// anyway risks scanning the customer's assets twice (api RFC-030 B6),
	// so the command is not executed; if it is still pending the platform
	// re-queues it.
	if err := p.client.StartCommand(ctx, cmd.ID); err != nil {
		fmt.Printf("[command-poller] Not running command %s: the platform did not accept its start: %v\n", cmd.ID, err)
		return
	}
	p.queue.markStarted(cmd.ID)

	// The sensor-local policy first: nothing the platform says (its tool
	// policy below, the payload) can widen it.
	if lp := p.local.Load(); lp != nil {
		if err := lp.AdmitCommand(ctx, cmd); err != nil {
			p.refuseCommand(ctx, cmd, err)
			return
		}
		for _, w := range lp.CommandWarnings(cmd) {
			fmt.Printf("[command-poller] Warning: %s\n", w)
		}
	}

	if g := p.gate.Load(); g != nil {
		if err := (*g)(cmd); err != nil {
			fmt.Printf("[command-poller] Refusing command %s: %v\n", cmd.ID, err)
			if rerr := p.client.ReportCommandResult(ctx, cmd.ID, &CommandResult{
				Status: "failed", Error: err.Error(), CompletedAt: time.Now(), Refusal: RefusalOf(err),
			}); rerr != nil && p.verbose.Load() {
				fmt.Printf("[command-poller] Failed to report refused command %s: %v\n", cmd.ID, rerr)
			}
			return
		}
	}

	// Run the executor with panic recovery — a panic in a tool or parser would
	// otherwise take down the whole sensor process, and the server would wait for
	// a result that can never arrive. Converting it to an error here routes it
	// through the normal failure path below, so the command is reported failed
	// with the panic message instead of vanishing.
	result, err := func() (res *CommandExecutionResult, e error) {
		defer func() {
			if r := recover(); r != nil {
				e = fmt.Errorf("executor panicked: %v", r)
			}
		}()
		return p.executor.Execute(ctx, cmd)
	}()

	// Stopped by the local kill switch: reported failed with the reason.
	if errors.Is(context.Cause(ctx), errKilledByLocalPolicy) {
		p.refuseCommand(context.WithoutCancel(ctx), cmd, refuse("kill_switch", "stopped by the sensor owner while running"))
		return
	}
	// Canceled by the platform or by a drain: release it (the platform
	// re-queues it at once, or it is already canceled there) instead of
	// reporting a failure that is not the command's.
	if cause := context.Cause(ctx); errors.Is(cause, errCanceledByPlatform) || errors.Is(cause, errDrained) {
		p.release(cmd.ID, releaseReason(ctx, ReleaseReasonShutdown))
		return
	}

	if p.resources != nil {
		p.resources.Observe(jobSample(cmd, parseCommandMeta(cmd), time.Since(startTime), usage, err, ctx))
	}

	reportResult := &CommandResult{
		CompletedAt: time.Now(),
		DurationMs:  time.Since(startTime).Milliseconds(),
	}

	if err != nil {
		reportResult.Status = "failed"
		reportResult.Error = err.Error()
		// The executor's own policy checks (allow_interactsh, custom
		// templates, targets) refuse with a *LocalPolicyError too.
		reportResult.Refusal = RefusalOf(err)
		if p.verbose.Load() {
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
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Command %s completed (findings: %d)\n", cmd.ID, reportResult.FindingsCount)
		}
	}

	// Report result back to server. A client with an outbox queues it behind
	// the command's results, so the platform sees the command complete only
	// after it accepted them.
	if err := p.client.ReportCommandResult(ctx, cmd.ID, reportResult); err != nil {
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Failed to report result for command %s: %v\n", cmd.ID, err)
		}
	}
}

// refuseCommand reports a command failed with err without running it (or
// after stopping it): the platform shows the reason.
func (p *CommandPoller) refuseCommand(ctx context.Context, cmd *Command, err error) {
	fmt.Printf("[command-poller] Refusing command %s: %v\n", cmd.ID, err)
	if rerr := p.client.ReportCommandResult(ctx, cmd.ID, &CommandResult{
		Status: "failed", Error: err.Error(), CompletedAt: time.Now(), Refusal: RefusalOf(err),
	}); rerr != nil {
		fmt.Printf("[command-poller] Failed to report refused command %s: %v\n", cmd.ID, rerr)
	}
}

// releaseReason names why a held command is handed back.
func releaseReason(ctx context.Context, fallback string) string {
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errCanceledByPlatform):
		return ReleaseReasonCanceled
	case errors.Is(cause, errDrained):
		return ReleaseReasonShutdown
	}
	return fallback
}

// SetVerbose sets verbose mode.
func (p *CommandPoller) SetVerbose(v bool) {
	p.verbose.Store(v)
}

// =============================================================================
// Default Command Executor
// =============================================================================

// DefaultCommandExecutor provides default command execution.
type DefaultCommandExecutor struct {
	scanners   map[string]Scanner
	collectors map[string]Collector
	pusher     Pusher
	parsers    *ParserRegistry
	// assetResolver names the asset a scan target's findings belong to; nil
	// leaves it to the parser.
	assetResolver AssetResolver
	// targetPolicy validates every scan target before a scanner runs.
	// nil means DefaultScanTargetPolicy(), captured at construction.
	targetPolicy atomic.Pointer[ScanTargetPolicy]
	// verbose is atomic: SetVerbose may race with concurrent Execute calls.
	verbose atomic.Bool
	// tools, when set, registers every scanner and collector added (see
	// SetToolRegistry).
	tools *ToolRegistry
	// templates verifies custom template manifests; nil refuses every
	// command that carries custom templates (SetTemplateVerifier).
	templates atomic.Pointer[TemplateVerifier]
	// sensorID is this sensor's own id, when known: a template manifest
	// must name it (SetSensorID).
	sensorID atomic.Pointer[string]
	// local is the sensor-local policy (SetLocalPolicy); nil: none.
	local atomic.Pointer[LocalPolicy]
}

// SetLocalPolicy makes the executor enforce the sensor-local policy (api
// RFC-040 §5.7) on every scan, behind the poller's admission check: targets
// through the scan target policy, allow_custom_templates, allow_interactsh,
// rate.max_rps and rate.max_job_seconds. Nothing in a command can loosen
// it. nil removes it (the MaxScanTimeout cap stays).
func (e *DefaultCommandExecutor) SetLocalPolicy(lp *LocalPolicy) {
	e.local.Store(lp)
}

// SetTemplateVerifier sets the pinned keys custom templates must be signed
// with (see TemplateVerifier). Without one, a command that carries custom
// templates fails with ErrNoTemplateKeys: an unsigned template never
// reaches a scanner.
func (e *DefaultCommandExecutor) SetTemplateVerifier(v *TemplateVerifier) {
	e.templates.Store(v)
}

// SetSensorID sets this sensor's own id (from its configuration, not from
// the platform): a signed template manifest for another sensor is then
// refused. Empty: manifests are bound to the command and the tenant's key
// only.
func (e *DefaultCommandExecutor) SetSensorID(id string) {
	e.sensorID.Store(&id)
}

// verifyCustomTemplates checks the command's signed template manifest: the
// templates run only if a pinned key signed exactly them for this command
// (and this sensor, when it knows its id), and the manifest has not
// expired.
func (e *DefaultCommandExecutor) verifyCustomTemplates(cmdID string, payload *ScanCommandPayload) error {
	verifier := e.templates.Load()
	if verifier == nil {
		return ErrNoTemplateKeys
	}
	contents := make([][]byte, len(payload.CustomTemplates))
	for i := range payload.CustomTemplates {
		c, err := decodeTemplateContent(&payload.CustomTemplates[i])
		if err != nil {
			return err
		}
		contents[i] = c
	}
	b := TemplateBinding{CommandID: cmdID}
	if id := e.sensorID.Load(); id != nil {
		b.SensorID = *id
	}
	if _, err := verifier.Verify(payload.CustomTemplatesEnvelope, b, payload.CustomTemplates, contents); err != nil {
		return fmt.Errorf("custom templates refused: %w", err)
	}
	return nil
}

// NewDefaultCommandExecutor creates a new default executor.
//
// Scan targets are validated with DefaultScanTargetPolicy() (SSRF blocklist,
// filesystem confinement, flag-injection guard); override with
// SetScanTargetPolicy.
func NewDefaultCommandExecutor(pusher Pusher) *DefaultCommandExecutor {
	e := &DefaultCommandExecutor{
		scanners:   make(map[string]Scanner),
		collectors: make(map[string]Collector),
		pusher:     pusher,
	}
	e.targetPolicy.Store(DefaultScanTargetPolicy())
	return e
}

// SetScanTargetPolicy replaces the policy used to validate server-supplied
// scan targets (allowed filesystem roots, private-range opt-in). A nil
// policy restores DefaultScanTargetPolicy(). Safe to call concurrently with
// Execute.
func (e *DefaultCommandExecutor) SetScanTargetPolicy(p *ScanTargetPolicy) {
	if p == nil {
		p = DefaultScanTargetPolicy()
	}
	e.targetPolicy.Store(p)
}

// ScanTargetPolicy returns the policy currently applied to scan targets.
func (e *DefaultCommandExecutor) ScanTargetPolicy() *ScanTargetPolicy {
	if p := e.targetPolicy.Load(); p != nil {
		return p
	}
	return DefaultScanTargetPolicy()
}

// SetParserRegistry supplies the registry used to convert a scanner's raw
// output into a CTIS report. executeScan uses the parser registered under the
// scanner's name, else the first parser that recognizes the content (see
// ParserRegistry.ForScanner). Without a registry only SARIF output is
// understood. Output no parser recognizes fails the command instead of being
// reported as 0 findings — register a parser for every scanner that does not
// emit SARIF (betterleaks, semgrep, trivy, nuclei).
func (e *DefaultCommandExecutor) SetParserRegistry(r *ParserRegistry) {
	e.parsers = r
}

// AssetResolver returns the asset a scan of target (already validated) should
// report its findings on, or an empty value to let the parser decide.
type AssetResolver func(scanner, target string) (ctis.AssetType, string)

// SetAssetResolver sets how executeScan names the scanned asset. Without one,
// parsers that cannot tell the asset from the scanner output (a filesystem scan
// by betterleaks, for one) send findings without an asset, which the platform
// files under a placeholder. Set it before the poller starts.
func (e *DefaultCommandExecutor) SetAssetResolver(r AssetResolver) {
	e.assetResolver = r
}

// SetToolRegistry registers the executor's scanners and collectors, those
// added already and those added later, in r, so the sensor reports them to
// the platform. Pass the sensor's registry (BaseSensor.Tools). Call before
// the poller starts.
func (e *DefaultCommandExecutor) SetToolRegistry(r *ToolRegistry) {
	e.tools = r
	if r == nil {
		return
	}
	for _, s := range sortedValues(e.scanners) {
		_ = r.RegisterScanner(s)
	}
	for _, c := range sortedValues(e.collectors) {
		_ = r.RegisterCollector(c)
	}
}

// sortedValues returns m's values ordered by key (a stable registration
// order).
func sortedValues[T any](m map[string]T) []T {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]T, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

// AddScanner adds a scanner.
func (e *DefaultCommandExecutor) AddScanner(scanner Scanner) {
	e.scanners[scanner.Name()] = scanner
	if e.tools != nil {
		_ = e.tools.RegisterScanner(scanner)
	}
}

// AddCollector adds a collector.
func (e *DefaultCommandExecutor) AddCollector(collector Collector) {
	e.collectors[collector.Name()] = collector
	if e.tools != nil {
		_ = e.tools.RegisterCollector(collector)
	}
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
	// A platform that has not migrated its scan configs still dispatches the
	// retired name ("gitleaks"); run the replacement.
	payload.Scanner = CanonicalScannerName(payload.Scanner)

	scanner, ok := e.scanners[payload.Scanner]
	if !ok {
		return nil, fmt.Errorf("scanner not found: %s", payload.Scanner)
	}

	// SECURITY: targets are server-supplied. Validate every one before any
	// scanner sees it: SSRF blocklist for network targets, confinement for
	// filesystem targets, and no leading '-' (flag injection).
	targets, err := e.validateScanTargets(ctx, &payload)
	if err != nil {
		return nil, err
	}
	// target is the single target, or "" for a multi-target run.
	var target string
	if len(targets) == 1 {
		target = targets[0]
	}
	multi, isMulti := scanner.(MultiTargetScanner)
	if len(targets) > 1 && !isMulti {
		return nil, fmt.Errorf("scanner %s takes one target per job; the command carries %d", payload.Scanner, len(targets))
	}

	if e.verbose.Load() {
		fmt.Printf("[executor] Running scanner %s on %s\n", payload.Scanner, strings.Join(targets, ", "))
	}

	// Create scan options
	opts := &ScanOptions{
		TargetDir: target,
		Verbose:   e.verbose.Load(),
	}

	local := e.local.Load()
	// Add config options if provided
	if payload.Config != nil {
		// Out-of-band callbacks only when the command says so, as a boolean:
		// anything else ("true", 1) leaves them off; and only when the local
		// policy allows them.
		if allow, ok := payload.Config["allow_interactsh"].(bool); ok && allow {
			if !local.AllowsInteractsh() {
				return nil, refuse("allow_interactsh", "the job asks for out-of-band callbacks (interactsh); this sensor's policy does not allow them")
			}
			opts.AllowInteractsh = true
		}
		if err := applyScanLimits(opts, payload.Config); err != nil {
			return nil, err
		}
		if exclude, ok := payload.Config["exclude"].([]interface{}); ok {
			for _, ex := range exclude {
				if s, ok := ex.(string); ok {
					if err := validateScanArgValue(s); err != nil {
						return nil, fmt.Errorf("invalid exclude pattern: %w", err)
					}
					opts.Exclude = append(opts.Exclude, s)
				}
			}
		}
	}

	// The rest of the config reaches the scanner only as typed settings its
	// own schema declares (api RFC-038); an invalid value fails the command.
	settings, ignoredConfig, err := scanSettings(e.scannerSettingsSchema(payload.Scanner, scanner), payload.Config)
	if err != nil {
		return nil, fmt.Errorf("invalid %s settings: %w", payload.Scanner, err)
	}
	opts.Settings = settings
	if len(ignoredConfig) > 0 && e.verbose.Load() {
		fmt.Printf("[executor] %s does not take config keys %s; they have no effect\n", payload.Scanner, strings.Join(ignoredConfig, ", "))
	}
	// The local policy's rate ceiling: no scan runs above it, whatever the
	// command asked for.
	opts.RateLimit = local.CapRate(opts.RateLimit)

	// Handle custom templates if provided
	var templateDir string
	var cleanupTemplates func()
	if len(payload.CustomTemplates) > 0 {
		if !local.AllowsCustomTemplates() {
			return nil, refuse("allow_custom_templates", "the job carries %d custom template(s); this sensor's policy does not allow platform-supplied templates", len(payload.CustomTemplates))
		}
		// SECURITY: only templates the platform signed for this command are
		// written (see verifyCustomTemplates); nothing is written before.
		if err := e.verifyCustomTemplates(cmd.ID, &payload); err != nil {
			return nil, err
		}
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
		if e.verbose.Load() {
			fmt.Printf("[executor] Using custom templates from %s\n", templateDir)
		}
	}

	// Create context with timeout if specified: never above MaxScanTimeout
	// or the local policy's rate.max_job_seconds (which also applies when
	// the command sets none).
	var requested time.Duration
	if payload.TimeoutSeconds > 0 {
		requested = time.Duration(min(int64(payload.TimeoutSeconds), int64(MaxScanTimeout/time.Second))) * time.Second
	}
	if timeout := local.CapTimeout(requested); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Run scan
	startTime := time.Now()
	var scanResult *ScanResult
	if len(targets) > 1 {
		scanResult, err = multi.ScanTargets(ctx, targets, opts)
	} else {
		scanResult, err = scanner.Scan(ctx, target, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	result := &CommandExecutionResult{
		DurationMs: time.Since(startTime).Milliseconds(),
		ExitCode:   scanResult.ExitCode,
		Metadata: map[string]interface{}{
			"scanner_name":    scanResult.ScannerName,
			"scanner_version": scanResult.ScannerVersion,
			"targets_scanned": len(targets),
		},
	}
	// Say what the config did: the settings applied, and the keys that had
	// no effect (instead of dropping them silently).
	if settings != nil {
		result.Metadata["settings_applied"] = settings.Keys()
		result.Metadata["settings_schema_digest"] = settings.SchemaDigest()
	}
	if len(ignoredConfig) > 0 {
		result.Metadata["ignored_config_keys"] = ignoredConfig
	}

	// Parse and push results if pusher is configured. Empty (or whitespace-
	// only) output is a scan that found nothing; anything else must be read by
	// a parser, or the command fails: reporting it as 0 findings would hide
	// real results behind a "completed" scan.
	if e.pusher != nil && len(bytes.TrimSpace(scanResult.RawOutput)) > 0 {
		parser, err := e.parsers.ForScanner(scanner.Name(), scanResult.RawOutput)
		if err != nil {
			return result, fmt.Errorf("parse failed: %w", err)
		}
		parseOpts := &ParseOptions{ToolName: scanner.Name()}
		if target != "" && filepath.IsAbs(target) {
			// Filesystem scan: report repo-relative paths, so a finding's
			// fingerprint does not depend on where the code was checked out.
			parseOpts.BasePath = target
		}
		if e.assetResolver != nil && target != "" {
			parseOpts.AssetType, parseOpts.AssetValue = e.assetResolver(payload.Scanner, target)
		}
		report, err := parser.Parse(ctx, scanResult.RawOutput, parseOpts)
		if err != nil {
			return result, fmt.Errorf("parse failed (%s parser): %w", parser.Name(), err)
		}
		if report.Tool == nil || report.Tool.Name == "" {
			if report.Tool == nil {
				report.Tool = &ctis.Tool{}
			}
			report.Tool.Name = scanner.Name()
		}

		result.FindingsCount = len(report.Findings)
		report.Metadata.CoverageType = scanCoverageType(report, scanResult)

		// Push findings
		_, err = e.pusher.PushFindings(ctx, report)
		if err != nil {
			return result, fmt.Errorf("push failed: %w", err)
		}
	}

	return result, nil
}

// validateScanTargets returns the command's targets, each validated by the
// scan-target policy. Target is the job when set (single-target and older
// payloads); otherwise Targets is. A refused target fails the whole command,
// naming it: scanning the rest would silently drop it from the results.
func (e *DefaultCommandExecutor) validateScanTargets(ctx context.Context, payload *ScanCommandPayload) ([]string, error) {
	raw := payload.Targets
	if payload.Target != "" {
		raw = []string{payload.Target}
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("invalid scan target: scan target is required")
	}
	if len(raw) > MaxScanTargets {
		return nil, fmt.Errorf("invalid scan target: %d targets, more than the %d allowed per command", len(raw), MaxScanTargets)
	}

	policy := e.ScanTargetPolicy()
	if lp := e.local.Load(); lp.Present() && policy.Local == nil {
		withLocal := *policy
		withLocal.Local = lp
		policy = &withLocal
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	var refused []string
	for _, t := range raw {
		v, err := policy.Validate(ctx, t)
		if err != nil {
			refused = append(refused, fmt.Sprintf("%q: %v", t, err))
			continue
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(refused) > 0 {
		listed := refused
		if len(listed) > maxRefusedListed {
			listed = append(listed[:maxRefusedListed:maxRefusedListed], fmt.Sprintf("and %d more", len(refused)-maxRefusedListed))
		}
		if len(raw) == 1 {
			return nil, fmt.Errorf("invalid scan target: %s", strings.Join(listed, "; "))
		}
		return nil, fmt.Errorf("invalid scan target: %d of %d targets refused: %s", len(refused), len(raw), strings.Join(listed, "; "))
	}
	return out, nil
}

// validateScanArgValue rejects server-supplied values that end up as scanner
// argv entries and could be parsed as flags or break argument framing.
func validateScanArgValue(v string) error {
	if v == "" {
		return fmt.Errorf("empty value")
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("value %q looks like a command-line flag", v)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("value contains control characters")
		}
	}
	return nil
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
		os.RemoveAll(tmpDir) //nolint:errcheck // best-effort cleanup
	}

	// Track written filenames to detect duplicates
	writtenNames := make(map[string]bool)

	// Write each template to the temp directory
	for _, tpl := range templates {
		// The platform sends the template base64-encoded for JSON transport,
		// and content_hash is the SHA-256 of the DECODED template (the API
		// computes it over the stored bytes). Hashing the base64 text made
		// every custom-template scan fail with a hash mismatch, and writing it
		// undecoded would have handed the scanner base64 instead of YAML.
		content, err := decodeTemplateContent(&tpl)
		if err != nil {
			cleanup()
			return "", nil, err
		}

		// Verify content hash if provided (mandatory for integrity)
		if tpl.ContentHash != "" {
			hash := sha256.Sum256(content)
			computedHash := hex.EncodeToString(hash[:])
			if !strings.EqualFold(computedHash, tpl.ContentHash) {
				cleanup()
				return "", nil, fmt.Errorf("template %s hash mismatch: expected %s, got %s", tpl.Name, tpl.ContentHash, computedHash)
			}
		}

		// Determine file extension based on template type
		ext := ".yaml"
		if CanonicalScannerName(tpl.TemplateType) == ScannerBetterleaks {
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
		if err := os.WriteFile(filePath, content, 0600); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write template %s: %w", tpl.Name, err)
		}

		if e.verbose.Load() {
			fmt.Printf("[executor] Wrote custom template: %s\n", filePath)
		}
	}

	return tmpDir, cleanup, nil
}

// decodeTemplateContent returns the template bytes carried base64-encoded in
// tpl.Content, bounded by MaxTemplateSize.
func decodeTemplateContent(tpl *EmbeddedTemplate) ([]byte, error) {
	content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tpl.Content))
	if err != nil {
		return nil, fmt.Errorf("template %s: content is not valid base64: %w", tpl.Name, err)
	}
	if len(content) > MaxTemplateSize {
		return nil, fmt.Errorf("template %s: content too large: max %d bytes", tpl.Name, MaxTemplateSize)
	}
	return content, nil
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

	if e.verbose.Load() {
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
			report.Metadata.CoverageType = collectCoverageType(report)
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
	e.verbose.Store(v)
}

// CTIS coverage_type values (spec 4.5).
const (
	coverageTypeFull        = "full"
	coverageTypePartial     = "partial"
	coverageTypeIncremental = "incremental"
)

// scanCoverageType is the coverage_type a scan command's report declares.
// Every report states one: a receiver must not read an absent value as full
// (CTIS spec 4.5), and the platform auto-resolves findings a run no longer
// reports only on full coverage.
//
//   - A run the scanner says stopped part-way (ScanResult.Error) or with
//     targets it could not scan (properties.failed_targets) is partial, even
//     when the parser declared full.
//   - Otherwise a value the parser declared is kept.
//   - A repository scan (metadata.branch set) is partial: it has its own,
//     default-branch-gated auto-resolve, and the runtime cannot tell that the
//     checkout was the whole repository.
//   - Anything else, a completed run over its targets, is full.
func scanCoverageType(report *ctis.Report, r *ScanResult) string {
	declared := report.Metadata.CoverageType
	if (r != nil && r.Error != "") || hasFailedTargets(report) {
		if declared == coverageTypeIncremental {
			return declared
		}
		return coverageTypePartial
	}
	if declared != "" {
		return declared
	}
	if report.Metadata.Branch != nil {
		return coverageTypePartial
	}
	return coverageTypeFull
}

// hasFailedTargets reports whether a report lists targets the run could not
// scan (recon scanners record them in properties.failed_targets).
func hasFailedTargets(report *ctis.Report) bool {
	v, ok := report.Properties["failed_targets"]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case []string:
		return len(t) > 0
	case []any:
		return len(t) > 0
	case string:
		return t != ""
	default:
		return true
	}
}

// collectCoverageType is the coverage_type a collector's report declares:
// the collector's own value (an import that knows it is a complete export,
// such as a Tenable scan, says full), else partial. The runtime cannot know
// that an external source returned everything.
func collectCoverageType(report *ctis.Report) string {
	if report.Metadata.CoverageType != "" {
		return report.Metadata.CoverageType
	}
	return coverageTypePartial
}
