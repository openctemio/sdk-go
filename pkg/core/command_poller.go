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
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/openctemio/ctis/outcome"
	ctissource "github.com/openctemio/ctis/source"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/reach"
	"github.com/openctemio/sdk-go/pkg/resource"
	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	"github.com/openctemio/sdk-go/pkg/webscope"
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
	// SignedJob is the platform job signer's DSSE envelope for this
	// delivery ("signed_job" of a claim answer; api RFC-040 §5.6). It binds
	// Payload's exact bytes, so Payload must be kept as received.
	SignedJob json.RawMessage `json:"signed_job,omitempty"`
	// Claimed is true when the poll already claimed the command for this
	// sensor (claim-N, api RFC-046 §11). The poller still acknowledges it
	// (a replay) when it runs it, and releases it when it does not.
	Claimed bool `json:"-"`
	// jobVerified and signedTemplates are the JobGuard's verdict: the
	// signed job verified against a pinned key, and the custom template
	// digests its statement names (equal to the payload's at that point).
	// Unexported: only JobGuard.Check sets them, never the platform's JSON.
	jobVerified     bool
	signedTemplates []string
	// signedLimits are the scope limits of the verified statement.
	signedLimits []scopelimit.Limit
	// signedContent are the content packs of the verified statement: the
	// only packs the job may mount (content_job.go).
	signedContent []jobsig.ContentRef
	// jobTenant is the organization of a verified shared (instance) job:
	// its results are bound to it. Only JobGuard.Check sets it.
	jobTenant string
	// jobZone are the private ranges a verified shared job may reach: the
	// zone of its signed statement (ParseZoneRanges), nil without one. Only
	// JobGuard.Check sets it; an unsigned command field never does.
	jobZone []netip.Prefix
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
	// ErrorCode is the platform's code for a failure (Failure.ErrorCode);
	// empty when the class has none.
	ErrorCode string `json:"error_code,omitempty"`
	// Failure is the structured class and bounded evidence of a failure that
	// is not a refusal (ClassifyFailure).
	Failure *Failure `json:"failure,omitempty"`
	// TargetOutcomes is how each target of a completed scan command ended
	// (ctis outcome.ResultKey): the platform settles the targets with an
	// outcome and hands out only the unfinished ones again.
	// On a failed command they are the targets settled before the failure
	// (FailureTargetOutcomes).
	TargetOutcomes []outcome.Target `json:"target_outcomes,omitempty"`
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
	Targets        []string               `json:"targets,omitempty"`
	Config         map[string]interface{} `json:"config,omitempty"`
	TimeoutSeconds int                    `json:"timeout_seconds,omitempty"`
	// Budget is the task's layered budget (per target, per task); nil
	// from a platform that sends none (budget.go).
	Budget *TaskBudget `json:"budget,omitempty"`
	// Deadline is when the platform stops waiting for this command (the
	// scan run's deadline); zero: none. The job's time budget ends
	// DeadlineMargin before it, so the run delivers what it settled in time
	// (run_watch.go). It can only shorten the job.
	Deadline time.Time `json:"deadline,omitzero"`
	// OutcomeRevision is the highest per-target outcome revision the platform
	// accepts (ctis outcome.Revision). Absent: 1. The sensor sends the classes
	// that say why a target was not covered (a name that is gone, an edge
	// that blocked, the sensor's own network) only at 2 or more; below it
	// they go as the closest class the platform knows.
	OutcomeRevision int `json:"outcome_revision,omitempty"`
	// aliases maps a validated target to the payload's own value when the
	// scan-target policy rewrote it (a resolved path): per-target outcomes
	// name the payload's values (validateScanTargets).
	aliases         map[string]string
	ReportProgress  bool               `json:"report_progress,omitempty"`
	CustomTemplates []EmbeddedTemplate `json:"custom_templates,omitempty"`
	// CustomTemplatesEnvelope is the platform's signed manifest of
	// CustomTemplates (TemplateManifest in a DSSE envelope). Custom
	// templates run only when it verifies (see TemplateVerifier.Verify).
	CustomTemplatesEnvelope *SignedEnvelope `json:"custom_templates_envelope,omitempty"`
	// RuleSources is which detection rules the scan runs: "both" (the
	// default, also when empty), "platform" or "tenant" (RuleSources). A
	// platform-only job carries no custom templates, a tenant-only job at
	// least one; anything else is refused (checkRuleSources).
	RuleSources string `json:"rule_sources,omitempty"`
	// Capability is the capability the job runs ("scan.ports@1"), sent to
	// a tool that reported a contract. Params are its standard params as
	// the workflow set them; the tool runtime maps them onto the tool's
	// config keys. MaxTier is the grant's tier ceiling.
	Capability string                     `json:"capability,omitempty"`
	Params     map[string]json.RawMessage `json:"params,omitempty"`
	MaxTier    string                     `json:"max_tier,omitempty"`
	// WebScope is the hosts, paths and methods a web tool may request
	// (webscope.Scope); an invalid one fails the job.
	WebScope *webscope.Scope `json:"web_scope,omitempty"`
	// HTTPPolicy is the organization's narrowing of its tools' requests
	// (OrgHTTPPolicy); the local policy decides first.
	HTTPPolicy *OrgHTTPPolicy `json:"http_policy,omitempty"`
	// Source is the repository a code-scan job fetches before the scan
	// (api RFC-091): the executor fetches exactly that commit read-only
	// into the scan workspace (pkg/source), scans the checkout instead of
	// Target, reports the findings on the repository Target names with the
	// source's branch and commit as a full scan, and removes the checkout.
	Source *ctissource.Repository `json:"source,omitempty"`
	// Exclusions are the scope exclusions that touch the job's targets
	// (addresses, CIDR prefixes, "first-last" ranges), covered by the job
	// signature with the rest of the payload. The sensor cuts its range
	// targets around them address by address before any check or tool
	// (job_exclusions.go) and hands them to the tool (ScanOptions.ExcludeHosts).
	Exclusions []string `json:"exclusions,omitempty"`
	// SettingsLayers are the tenant's and the sensor's tool settings for
	// the command's tool, set by administrators on the platform; checked
	// against the tool's own schema like the config (resolveScanSettings).
	SettingsLayers *SettingsLayers `json:"settings_layers,omitempty"`
	// Egress is the organization's proxy pool for the job's tool traffic
	// (egress_job.go): set by the platform for the claiming sensor, never
	// with credentials. Absent: no proxy (direct, as before).
	Egress *upstream.Config `json:"egress,omitempty"`
	// Content are the content packs the job runs with, pinned by digest
	// and named in the signed statement (content_job.go). A job that names
	// packs runs only when its signed statement lists exactly these.
	Content []JobContent `json:"content,omitempty"`
	// Inputs are lists the platform generated for this job from the
	// organization's own data. They are carried in the signed payload,
	// written only to the task directory and erased with it.
	Inputs []JobInput `json:"inputs,omitempty"`
}

// CapabilityScanner is a scanner that runs capability jobs: it takes the
// job's capability, standard params and tier ceiling (ScanOptions) and
// applies the tool contract to them. A job that carries them for any other
// scanner fails: they would have no effect.
type CapabilityScanner interface {
	Scanner
	TakesCapabilityJobs() bool
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
	// TargetOutcomes is how each of a scan job's targets ended, in job
	// order (target_outcomes.go); nil for other commands.
	TargetOutcomes []outcome.Target
}

// CommandPoller polls the server for pending commands.
type CommandPoller struct {
	// egressReporter sends a pooled job's egress report (SetEgressReporter).
	egressReporter atomic.Pointer[EgressReporter]
	// ledger: a shared sensor's held jobs (CommandPollerConfig.Ledger).
	ledger        *JobLedger
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
	// stopGraceNs overrides defaultStopGrace (tests; 0: the default).
	stopGraceNs atomic.Int64
	// sem bounds the number of commands executing concurrently to
	// maxConcurrent. Without it a large command batch spawned an
	// unbounded number of goroutines/scans. A slot is taken BEFORE a command
	// is claimed (acknowledged) and released when it ends, so the sensor
	// never holds a claimed command it is not running: such a command was
	// re-queued by the platform's acknowledged-command reaper while this
	// sensor still held it, and then ran twice (api RFC-030 B6).
	sem chan struct{}
	// leases watches each held job's lease (lease_watchdog.go).
	leases leaseWatch

	// slotFreed is signaled when a command ends while the platform may
	// still have work for this sensor (backlog), so the poller claims it
	// without waiting for the next tick or doorbell ring.
	slotFreed chan struct{}
	backlog   atomic.Bool
	// skippedTypes is how many commands of a type this sensor does not
	// run the last poll returned: the next poll asks for that many more,
	// so with one free slot such a command at the head of the queue does
	// not hide the sensor's own work behind it on every poll.
	skippedTypes atomic.Int32

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

	// claims backs polls off after a poll that only handed commands back,
	// and after a Retry-After from the platform (claim_backoff.go).
	// pollDeferred records that a poll was skipped for it, so the loop
	// polls once the wait is over instead of dropping the wake-up.
	claims       *claimBackoff
	pollDeferred bool

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

	// claimGate says whether the sensor may claim new jobs now (storage
	// and outbox limits; SetClaimGate). claimBlocked remembers the last
	// answer so a change is logged once.
	claimGate    atomic.Pointer[func() (bool, string)]
	claimBlocked atomic.Bool

	// journal records every job from its start to its result
	// (SetJobJournal), so the next start reports the ones a crash cut short.
	journal atomic.Pointer[JobJournal]

	// local is the sensor-local policy (SetLocalPolicy): admission before
	// every command and the kill switch. killed is true while its kill
	// switch is engaged.
	local  atomic.Pointer[LocalPolicy]
	killed atomic.Bool

	// jobs checks each command's job signature right after its claim,
	// before it is started (SetJobGuard).
	jobs atomic.Pointer[JobGuard]

	// logSink takes the poller's own lines about each command
	// (SetCommandLogSink); handBacks dedupes its hand-back lines.
	logSink   CommandLogSink
	handBacks handBackNotes
}

// errKilledByLocalPolicy cancels running commands when the sensor owner
// engages the local kill switch.
var errKilledByLocalPolicy = errors.New("stopped by the local kill switch")

// KillSwitchCheckInterval is how often a poller with a local policy checks
// its kill switch file while commands run.
const KillSwitchCheckInterval = 2 * time.Second

// SetLocalPolicy makes the poller enforce the sensor-local policy (api
// RFC-040 §5.7): every command passes LocalPolicy.AdmitCommandTargets
// after it is claimed and before any executor or tool sees it. A scan
// target it refuses is removed from the job and listed in the result
// (MetaRefusedTargets); a refused command is reported failed with "refused
// by local policy: <rule>: …", never run and never dropped silently. While the kill switch is engaged the poller
// claims nothing and stops the commands it runs (reported failed). It is
// checked before the gate of SetCommandGate, so no platform policy can
// widen it. Call before Start.
func (p *CommandPoller) SetLocalPolicy(lp *LocalPolicy) {
	p.local.Store(lp)
}

// SetJobGuard makes the poller check every command's signed job (api
// RFC-040 §5.6) right after it is claimed, before it is started and before
// the local policy, the command gate or any executor sees it. A command the
// guard refuses is reported failed with rule "job_signature" and never
// run. With a guard that verifies, commands are claimed through
// CommandClaimer when the client implements it, so the payload, the signed
// job and the lease epoch checked are those of the claim answer. Call
// before Start.
func (p *CommandPoller) SetJobGuard(g *JobGuard) {
	p.jobs.Store(g)
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
	// Ledger, on a shared sensor, holds each command while it runs, with
	// the organization its verified signed job names; the client refuses
	// results for a command the ledger does not hold (JobLedger). A
	// command without a verified organization is refused, never run.
	Ledger *JobLedger `yaml:"-" json:"-"`
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
		ledger:        cfg.Ledger,
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
		claims:        newClaimBackoff(),
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

	// Held leases are checked every LeaseWatchInterval.
	leaseTick := time.NewTicker(LeaseWatchInterval)
	defer leaseTick.Stop()

	// deferred fires when a poll skipped for the claim backoff may run.
	deferred := time.NewTimer(time.Hour)
	deferred.Stop()
	defer deferred.Stop()
	armDeferred := func() {
		if !p.pollDeferred {
			return
		}
		p.pollDeferred = false
		if w := p.claims.wait(); w > 0 {
			deferred.Reset(w)
		} else {
			deferred.Reset(0)
		}
	}

	// Poll immediately on start
	p.pollAndExecute(ctx)
	lastPoll := time.Now()

	for {
		select {
		case now := <-leaseTick.C:
			p.watchLeases(now)
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
			// without a free slot; the next slot that frees polls), or
			// once the claim backoff is over.
			p.pollAndExecute(ctx)
			lastPoll = time.Now()
			armDeferred()
		case <-p.slotFreed:
			// A command ended and the last poll suggested more work.
			p.pollAndExecute(ctx)
			lastPoll = time.Now()
			armDeferred()
		case <-deferred.C:
			// A poll skipped during the claim backoff.
			p.pollAndExecute(ctx)
			lastPoll = time.Now()
			armDeferred()
		case <-ticker.C:
			// With the doorbell active the fixed poll is replaced by the
			// doorbell plus a long safety poll; without hints (an older
			// server, or heartbeats failing) poll on every tick as before.
			if p.doorbell != nil && p.doorbell.HintsActive() && time.Since(lastPoll) < p.safetyPoll {
				continue
			}
			p.pollAndExecute(ctx)
			lastPoll = time.Now()
			armDeferred()
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
		d.setStopHandler(func(ids []string) { p.StopCommands(ids...) })
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

// StopCommands stops held commands the platform asks to stop and deliver
// (stop_command_ids): a running one's context is canceled with
// ErrStoppedByPlatform, and the run's settled targets are delivered and
// reported (partial, the rest unfinished) instead of released. Ids not
// held are ignored.
func (p *CommandPoller) StopCommands(ids ...string) {
	for _, id := range ids {
		if p.queue.cancel(id, ErrStoppedByPlatform) && p.verbose.Load() {
			fmt.Printf("[command-poller] Stopping command %s (platform: the task stalled)\n", id)
		}
	}
}

// QueueStats is the local queue now.
func (p *CommandPoller) QueueStats() QueueStats {
	st, _ := p.queue.snapshot(time.Now())
	return st
}

// LeasesRenewed records an answered heartbeat, sent at at, that listed ids
// as running: their leases were renewed (lease_watchdog.go). It implements
// LeaseRenewalObserver.
func (p *CommandPoller) LeasesRenewed(at time.Time, ids []string) {
	p.leases.renewed(at, ids)
}

// watchLeases stops the held jobs whose lease ran out without a renewal.
func (p *CommandPoller) watchLeases(now time.Time) {
	rec, _ := p.client.(LeaseLossRecorder)
	for _, id := range p.leases.expire(now, func(id string) {
		if rec != nil {
			rec.MarkLeaseLost(id)
		}
	}) {
		fmt.Printf("[command-poller] Lease of command %s not renewed for longer than the lease: stopping it\n", id)
	}
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
	status.Progress = p.queue.progress()
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
	go p.handBack(cmd.ID, reason)
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

// SetClaimGate makes the poller claim nothing while f reports false (with
// the reason): the sensor's storage is full, so results beat new work.
// Running commands finish, and polling resumes as soon as f reports true.
// The change of state is logged once each way. Safe while the poller runs;
// nil removes the gate.
func (p *CommandPoller) SetClaimGate(f func() (ok bool, reason string)) {
	if f == nil {
		p.claimGate.Store(nil)
		return
	}
	p.claimGate.Store(&f)
}

// JobJournal records the jobs the sensor runs, so the next start can report
// the ones a crash or a kill cut short (localstore's job journal through
// sensorkit). JobStarted is called once the platform accepted the start and
// before anything runs; JobFinished once the job's result was handed to the
// client (queued in the outbox), or the job was handed back. tenant is the
// organization of a verified shared job ("" on an organization sensor).
type JobJournal interface {
	JobStarted(cmdID, tenant string, leaseEpoch int) error
	JobFinished(cmdID, tenant string) error
}

// SetJobJournal makes the poller journal every job it runs. A journal that
// cannot write is logged and the job still runs (only its crash report is
// lost). nil removes it. Call before Start.
func (p *CommandPoller) SetJobJournal(j JobJournal) {
	if j == nil {
		p.journal.Store(nil)
		return
	}
	p.journal.Store(&j)
}

// claimAllowed applies the claim gate and logs a change of state once.
func (p *CommandPoller) claimAllowed() bool {
	g := p.claimGate.Load()
	if g == nil {
		return true
	}
	ok, why := (*g)()
	if !ok {
		if p.claimBlocked.CompareAndSwap(false, true) {
			fmt.Printf("[command-poller] Not claiming new jobs: %s\n", why)
		}
		return false
	}
	if p.claimBlocked.CompareAndSwap(true, false) {
		fmt.Printf("[command-poller] Claiming new jobs again\n")
	}
	return true
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

// maxSkippedTypesAsk bounds the extra commands a poll asks for after a poll
// returned commands of types this sensor does not run.
const maxSkippedTypesAsk = 8

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
	// Storage or the outbox is full: results beat new work.
	if !p.claimAllowed() {
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
	if !p.claimWaitOver() {
		return
	}
	if p.verbose.Load() && p.doorbell != nil {
		fmt.Printf("[command-poller] %s Polling for commands (%d free slots)\n", time.Now().Format("15:04:05.000"), free)
	}
	ask := free + min(int(p.skippedTypes.Load()), maxSkippedTypesAsk)
	resp, err := p.getCommands(ctx, ask)
	if gate != nil {
		gate.MarkRejected(err, p.keyHint())
	} else if backoff := p.ownGate.Observe(err, p.keyHint()); backoff > 0 {
		p.ownNext = time.Now().Add(backoff)
	} else {
		p.ownNext = time.Time{}
	}
	if err != nil {
		p.claims.retryAfter(retryAfterOf(err))
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Failed to poll commands: %v\n", err)
		}
		return
	}

	// A full page means the platform may hold more for us: poll again as
	// soon as a slot frees.
	p.backlog.Store(len(resp.Commands) >= ask)
	if len(resp.Commands) == 0 {
		p.skippedTypes.Store(0)
		return
	}

	if p.verbose.Load() {
		fmt.Printf("[command-poller] Received %d commands\n", len(resp.Commands))
	}

	// The batch is handled in the order the platform returned it, which is
	// the order its signer numbered the jobs in: the job signature check
	// below needs per-signer sequence numbers to increase, so a local
	// re-sort (by priority) would refuse valid jobs. The platform owns the
	// order (priority, aging, fairness).
	limit := p.slotLimit()

	// started and declined decide the claim backoff: a poll that started
	// nothing and handed commands back (declined) only churns.
	started, declined, skipped := 0, 0, 0
	defer func() {
		p.settleClaims(started, declined)
		p.skippedTypes.Store(int32(min(skipped, maxSkippedTypesAsk))) //nolint:gosec // bounded
	}()

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
			declined++
			skipped++
			continue
		}

		// Check if command is expired
		if !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt) {
			if p.verbose.Load() {
				fmt.Printf("[command-poller] Skipping expired command: %s\n", cmd.ID)
			}
			p.dropClaimed(cmd, "command expired")
			declined++
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
			declined++
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
			declined++
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
			declined++
			continue
		}
		// Its hosts are freed target by target as the job settles them.
		p.queue.track(cmd.ID, commandTargets(meta), meta.NetworkID)

		// Claim (acknowledge) it now that a slot is held.
		claimedAt := time.Now()
		if err := p.claim(ctx, cmd); err != nil {
			p.queue.forget(cmd.ID)
			<-p.sem
			if p.verbose.Load() {
				fmt.Printf("[command-poller] Failed to acknowledge command %s: %v\n", cmd.ID, err)
			}
			continue
		}
		// The job signature, here in the platform's order (the signer's
		// sequence numbers increase along it) and before anything runs.
		jobErr := p.jobs.Load().Check(ctx, cmd)

		// Execute asynchronously, in a context of its own: stopping the
		// poller drains (DrainGrace) instead of killing it at once.
		cmdCtx, cancel := context.WithCancelCause(p.cmdBase)
		p.queue.setCancel(cmd.ID, cancel)
		p.leases.track(cmd.ID, cmd.LeaseExpiresAt, claimedAt, cancel)
		p.activeCmds.Add(1)
		started++
		go p.executeCommand(cmdCtx, cmd, jobErr)
	}
}

// hostsFreed is called when a held command's settled targets freed hosts:
// a command handed back because they were busy may run now, so the claim
// backoff ends and a poll waiting for a free slot is woken.
func (p *CommandPoller) hostsFreed() {
	p.claims.progressed()
	if p.backlog.Load() {
		select {
		case p.slotFreed <- struct{}{}:
		default:
		}
	}
}

// claimWaitOver reports whether the poller may poll: not while the last
// poll only handed commands back or the platform asked to wait
// (Retry-After). A skipped poll is remembered and runs once the wait is over.
func (p *CommandPoller) claimWaitOver() bool {
	w := p.claims.wait()
	if w <= 0 {
		return true
	}
	p.pollDeferred = true
	if p.verbose.Load() {
		fmt.Printf("[command-poller] Not polling for %s: claim backoff\n", w.Round(time.Millisecond))
	}
	return false
}

// settleClaims updates the claim backoff after a poll that started
// started commands and handed declined back.
func (p *CommandPoller) settleClaims(started, declined int) {
	switch {
	case started > 0:
		p.claims.progressed()
	case declined > 0:
		d := p.claims.fruitless()
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Handed back %d commands and started none: next poll in %s at the earliest\n", declined, d.Round(time.Millisecond))
		}
	}
}

// claim acknowledges cmd. With a JobGuard that verifies and a client that
// returns the claim answer (CommandClaimer), the answer's payload, signed
// job and lease epoch replace the poll's: the signer signed the claim.
func (p *CommandPoller) claim(ctx context.Context, cmd *Command) error {
	claimer, ok := p.client.(CommandClaimer)
	if !ok || !p.jobs.Load().verifies() {
		return p.client.AcknowledgeCommand(ctx, cmd.ID)
	}
	ans, err := claimer.ClaimCommand(ctx, cmd.ID)
	if err != nil {
		return err
	}
	if ans.ID != cmd.ID {
		return fmt.Errorf("claim answered command %q for %q", ans.ID, cmd.ID)
	}
	cmd.LeaseEpoch = ans.LeaseEpoch
	if !ans.LeaseExpiresAt.IsZero() {
		cmd.LeaseExpiresAt = ans.LeaseExpiresAt
	}
	if len(ans.SignedJob) > 0 {
		cmd.Payload, cmd.SignedJob = ans.Payload, ans.SignedJob
	}
	return nil
}

// executeCommand executes a single command. jobErr is the JobGuard's
// verdict: a command it refused is reported failed and never started.
// releaseCommandSlot frees what a finished command held: its context, its
// queue entry, its concurrency slot and the host it claimed.
func (p *CommandPoller) releaseCommandSlot(cmd *Command) {
	p.leases.untrack(cmd.ID)
	p.queue.cancel(cmd.ID, context.Canceled) // free the context
	p.queue.forget(cmd.ID)
	<-p.sem
	// A command ended: the host it held is free, so a command handed
	// back for it may run now.
	p.claims.progressed()
	if p.backlog.Load() {
		select {
		case p.slotFreed <- struct{}{}:
		default:
		}
	}
	p.activeCmds.Done()
}

// journalJob records the job in the journal before anything of it runs and
// returns the function that closes the record; with no journal it is a no-op.
func (p *CommandPoller) journalJob(cmd *Command) func() {
	jp := p.journal.Load()
	if jp == nil {
		return func() {}
	}
	j := *jp
	if jerr := j.JobStarted(cmd.ID, cmd.jobTenant, cmd.LeaseEpoch); jerr != nil {
		fmt.Printf("[command-poller] Warning: command %s is not journaled (a crash would not be reported): %v\n", cmd.ID, jerr)
	}
	return func() {
		if jerr := j.JobFinished(cmd.ID, cmd.jobTenant); jerr != nil {
			fmt.Printf("[command-poller] Warning: closing the journal record of command %s: %v\n", cmd.ID, jerr)
		}
	}
}

// giveUpAbandoned handles an executor that ignored the stop (a bug in a tool
// runner): the command is released or reported now, so its slot and the
// platform's view never wait on it; the executor's goroutine is left behind
// and whatever it reports later is refused.
func (p *CommandPoller) giveUpAbandoned(ctx context.Context, cmd *Command) {
	fmt.Printf("[command-poller] Command %s did not stop within %s of being stopped; giving it up\n", cmd.ID, p.stopGrace())
	if cause := context.Cause(ctx); errors.Is(cause, errCanceledByPlatform) || errors.Is(cause, errDrained) {
		p.handBack(cmd.ID, releaseReason(ctx, ReleaseReasonShutdown))
		return
	}
	p.refuseCommand(context.WithoutCancel(ctx), cmd, fmt.Errorf("the job did not stop within %s of being stopped", p.stopGrace()))
}

// refuseByGate reports a command the gate refused, failed and never started.
func (p *CommandPoller) refuseByGate(ctx context.Context, cmd *Command, err error) {
	fmt.Printf("[command-poller] Refusing command %s: %v\n", cmd.ID, err)
	p.clog(ctx, cmd.ID, "error", "Refused before running: "+err.Error(), refusalFields(err))
	p.finishLog(ctx, cmd.ID)
	if rerr := p.client.ReportCommandResult(ctx, cmd.ID, &CommandResult{
		Status: "failed", Error: err.Error(), CompletedAt: time.Now(), Refusal: RefusalOf(err),
	}); rerr != nil && p.verbose.Load() {
		fmt.Printf("[command-poller] Failed to report refused command %s: %v\n", cmd.ID, rerr)
	}
}

func (p *CommandPoller) executeCommand(ctx context.Context, cmd *Command, jobErr error) {
	defer p.releaseCommandSlot(cmd)

	startTime := time.Now()
	// Results pushed while executing belong to this command: a Pusher with
	// an outbox binds them to it and reports the command only after they
	// were accepted.
	ctx = WithCommandID(ctx, cmd.ID)
	// A shared sensor holds the command (its result included, the defer
	// above releases it last) for the organization its verified job names.
	if p.ledger != nil {
		p.ledger.Hold(cmd.ID, cmd.jobTenant)
		defer p.ledger.Release(cmd.ID)
		ctx = WithJobTenant(ctx, cmd.jobTenant)
		ctx = WithJobZone(ctx, cmd.jobZone)
	}
	ctx, usage := withUsageRecorder(ctx)
	// The proxy pool a pooled job prepares, for its egress report.
	ctx, egressUsed := withEgressHolder(ctx)
	// Every target the job dials through the guarded dialer or a task
	// forwarder, and every outcome a scanner records, lands here; the
	// result carries the summary (reach.Recorder.Metadata).
	reached := reach.NewRecorder()
	ctx = reach.WithRecorder(ctx, reached)
	// Finished targets, reported on every heartbeat while the job runs.
	progress := NewProgress(0)
	ctx = WithProgress(ctx, progress)
	p.queue.setProgress(cmd.ID, progress, p.hostsFreed)

	// Stopping (or canceled) before it started: hand it back unstarted.
	if p.draining.Load() || ctx.Err() != nil {
		p.handBack(cmd.ID, releaseReason(ctx, ReleaseReasonDraining))
		return
	}

	// A job signature that does not verify (or a missing one where signed
	// jobs are required): failed from the claimed state, never started.
	if jobErr == nil && p.ledger != nil && cmd.jobTenant == "" {
		jobErr = jobRefusal("a shared sensor runs only jobs whose verified signature names the organization they belong to")
	}
	if jobErr != nil {
		p.clog(ctx, cmd.ID, "error", "Refused before running: "+jobErr.Error(), refusalFields(jobErr))
		p.finishLog(ctx, cmd.ID)
		p.refuseCommand(ctx, cmd, jobErr)
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
	// The journal knows the job before anything of it runs; the record goes
	// when this function returns: the result is queued (or the job handed
	// back) by then.
	defer p.journalJob(cmd)()
	p.clog(ctx, cmd.ID, "info", "Received by the sensor", map[string]any{"type": cmd.Type})

	// The sensor-local policy first: nothing the platform says (its tool
	// policy below, the payload) can widen it. A scan target it refuses or
	// cannot check is removed from the job (and listed in the result); the
	// job is refused when nothing is left.
	var admission *CommandAdmission
	if lp := p.local.Load(); lp != nil {
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		p.logAdmission(ctx, cmd, adm, err)
		if err != nil {
			p.finishLog(ctx, cmd.ID)
			p.refuseCommand(ctx, cmd, err)
			return
		}
		if adm.Settled {
			p.completeUnresolved(ctx, cmd, adm)
			return
		}
		if adm.Partial() {
			fmt.Printf("[command-poller] Command %s: %s; running on the rest\n", cmd.ID, refusedSummary(adm.Refused))
			admission = adm
		}
		for _, w := range lp.CommandWarnings(cmd) {
			fmt.Printf("[command-poller] Warning: %s\n", w)
		}
	}

	if g := p.gate.Load(); g != nil {
		if err := (*g)(cmd); err != nil {
			p.refuseByGate(ctx, cmd, err)
			return
		}
	}
	p.clog(ctx, cmd.ID, "info", "Started", nil)

	// Run the executor with panic recovery — a panic in a tool or parser would
	// otherwise take down the whole sensor process, and the server would wait for
	// a result that can never arrive. Converting it to an error here routes it
	// through the normal failure path below, so the command is reported failed
	// with the panic message instead of vanishing.
	result, err, abandoned := p.runExecutor(ctx, cmd)
	// The lease was lost while the platform could not be reached: the job
	// is another sensor's now. Nothing is reported or released (both would
	// be refused) and its results are not sent (Client.MarkLeaseLost).
	if errors.Is(context.Cause(ctx), ErrLeaseLost) {
		fmt.Printf("[command-poller] Command %s stopped: %v\n", cmd.ID, ErrLeaseLost)
		return
	}
	if abandoned {
		p.giveUpAbandoned(ctx, cmd)
		return
	}

	// Stopped by the local kill switch: reported failed with the reason.
	if errors.Is(context.Cause(ctx), errKilledByLocalPolicy) {
		kerr := refuse("kill_switch", "stopped by the sensor owner while running")
		p.clog(context.WithoutCancel(ctx), cmd.ID, "error", "Stopped: "+kerr.Error(), refusalFields(kerr))
		p.finishLog(ctx, cmd.ID)
		p.reportEgress(ctx, cmd, egressUsed)
		p.refuseCommand(context.WithoutCancel(ctx), cmd, kerr)
		return
	}
	// Canceled by the platform or by a drain: release it (the platform
	// re-queues it at once, or it is already canceled there) instead of
	// reporting a failure that is not the command's.
	if cause := context.Cause(ctx); errors.Is(cause, errCanceledByPlatform) || errors.Is(cause, errDrained) {
		p.handBack(cmd.ID, releaseReason(ctx, ReleaseReasonShutdown))
		return
	}

	// Stopped by the platform (the task stalled): the run delivered what it
	// finished; its result is reported under a context the stop does not
	// end.
	if errors.Is(context.Cause(ctx), ErrStoppedByPlatform) {
		ctx = context.WithoutCancel(ctx)
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
		if reportResult.Refusal == nil {
			// Not a refusal: say what kind of failure it was and what the
			// job settled before it, for the platform to decide where the
			// work goes next. The message is redacted (a dial error can
			// carry a proxy address with its credentials).
			reportResult.Error = RedactFailureText(reportResult.Error)
			reportResult.Failure = ClassifyFailure(p.failureInput(ctx, cmd, err, usage, egressUsed))
			reportResult.ErrorCode = reportResult.Failure.ErrorCode()
			if result != nil {
				reportResult.TargetOutcomes = result.TargetOutcomes
			}
		}
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
			reportResult.TargetOutcomes = result.TargetOutcomes
		}
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Command %s completed (findings: %d)\n", cmd.ID, reportResult.FindingsCount)
		}
	}
	// Targets refused at admission and by the executor's own check: the
	// command completed on the rest (partial), and the result says which
	// targets were skipped and why.
	if admission.Partial() {
		refused := append(append([]RefusedTarget(nil), admission.Refused...), refusedTargetsFrom(reportResult.Metadata)...)
		if reportResult.Metadata == nil {
			reportResult.Metadata = map[string]any{}
		}
		for k, v := range RefusedTargetsMetadata(refused) {
			reportResult.Metadata[k] = v
		}
		if reportResult.TargetOutcomes != nil {
			reportResult.TargetOutcomes = append(skippedOutcomes(admission.Refused, outcomeRevisionOf(cmd.Payload)), reportResult.TargetOutcomes...)
		}
	}
	addReachMetadata(reportResult, reached)
	p.logOutcome(ctx, cmd, reportResult, err, time.Since(startTime))
	p.finishLog(ctx, cmd.ID)
	// The pool's signals go before the result, also when the job failed.
	p.reportEgress(ctx, cmd, egressUsed)

	// Report result back to server. A client with an outbox queues it behind
	// the command's results, so the platform sees the command complete only
	// after it accepted them.
	if err := p.client.ReportCommandResult(ctx, cmd.ID, reportResult); err != nil {
		if p.verbose.Load() {
			fmt.Printf("[command-poller] Failed to report result for command %s: %v\n", cmd.ID, err)
		}
	}
}

// defaultStopGrace is how long a stopped command's executor may take to
// return before the poller gives it up (CommandPoller.runExecutor).
const defaultStopGrace = 2 * time.Minute

// stopGrace is the poller's stop grace (defaultStopGrace unless a test set
// one).
func (p *CommandPoller) stopGrace() time.Duration {
	if g := time.Duration(p.stopGraceNs.Load()); g > 0 {
		return g
	}
	return defaultStopGrace
}

// runExecutor runs the executor with panic recovery. Once ctx ends by a
// cancel, a drain or the kill switch (whose results are discarded anyway)
// the executor has stopGrace to return; abandoned reports that it did not,
// and the command must then be settled without its result. A platform stop
// (deliver what finished) is waited for.
func (p *CommandPoller) runExecutor(ctx context.Context, cmd *Command) (res *CommandExecutionResult, err error, abandoned bool) {
	type outcome struct {
		res *CommandExecutionResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if r := recover(); r != nil {
				o = outcome{err: fmt.Errorf("executor panicked: %v", r)}
			}
			done <- o
		}()
		o.res, o.err = p.executor.Execute(ctx, cmd)
	}()
	select {
	case o := <-done:
		return o.res, o.err, false
	case <-ctx.Done():
	}
	if errors.Is(context.Cause(ctx), ErrStoppedByPlatform) {
		// A stop delivers what the run finished, which may take a while:
		// it is not given up.
		o := <-done
		return o.res, o.err, false
	}
	t := time.NewTimer(p.stopGrace())
	defer t.Stop()
	select {
	case o := <-done:
		return o.res, o.err, false
	case <-t.C:
		return nil, nil, true
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

// completeUnresolved completes a scan command whose every target is a name
// that does not resolve (CommandAdmission.Settled) without running it: the
// result lists each target with its refusal (reason unresolvable, and
// whether the name is gone or the lookup failed) and carries one outcome per
// target, so the platform settles each name on its own instead of failing
// the job.
func (p *CommandPoller) completeUnresolved(ctx context.Context, cmd *Command, adm *CommandAdmission) {
	res := &CommandResult{
		Status:         "completed",
		CompletedAt:    time.Now(),
		Metadata:       RefusedTargetsMetadata(adm.Refused),
		TargetOutcomes: skippedOutcomes(adm.Refused, outcomeRevisionOf(cmd.Payload)),
	}
	p.logOutcome(ctx, cmd, res, nil, 0)
	p.finishLog(ctx, cmd.ID)
	if err := p.client.ReportCommandResult(ctx, cmd.ID, res); err != nil && p.verbose.Load() {
		fmt.Printf("[command-poller] Failed to report result for command %s: %v\n", cmd.ID, err)
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
	// egress: the local veto on proxy pools and the credential fetch
	// (egress_job.go).
	egressMu sync.Mutex
	egress   egressSetup

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
	// content delivers the packs a job pins (SetContentResolver).
	content atomic.Pointer[ContentResolver]
	// sensorID is this sensor's own id, when known: a template manifest
	// must name it (SetSensorID).
	sensorID atomic.Pointer[string]
	// local is the sensor-local policy (SetLocalPolicy); nil: none.
	local atomic.Pointer[LocalPolicy]
	// sourceCreds fetches the credential of a code-scan job's source
	// (SetSourceCredentials); nil refuses jobs whose source names one.
	sourceCreds atomic.Pointer[sourceCredentialsBox]
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

// CommandTemplates is the custom-template part of a command payload (a
// scan command, a retest command): the templates and their signed
// manifest, in the payload's own field names.
type CommandTemplates struct {
	CustomTemplates         []EmbeddedTemplate `json:"custom_templates,omitempty"`
	CustomTemplatesEnvelope *SignedEnvelope    `json:"custom_templates_envelope,omitempty"`
}

// verifyCustomTemplates is VerifyCustomTemplates for a scan command.
func (e *DefaultCommandExecutor) verifyCustomTemplates(cmd *Command, payload *ScanCommandPayload) error {
	_, err := e.VerifyCustomTemplates(cmd, CommandTemplates{CustomTemplates: payload.CustomTemplates,
		CustomTemplatesEnvelope: payload.CustomTemplatesEnvelope})
	return err
}

// VerifyCustomTemplates decides whether the custom templates a command
// carries may run, and returns their decoded contents in order. A command
// whose signed job the JobGuard verified carries them in its statement:
// the platform's job signer approved exactly these digests (api RFC-040
// P2, its scope ledger), so they run when the templates received are byte
// for byte the ones signed, with no template-signing key needed. Otherwise
// (a sensor without signed jobs) the templates run only if a pinned
// template-signing key (SetTemplateVerifier) signed exactly them for this
// command (and this sensor, when it knows its id) in a manifest that has
// not expired. This per-tenant key path is a fallback, to be removed once
// signed jobs are required everywhere. Every template then passes the
// sensor's own content check (CheckCustomTemplate): one that could run
// code here is refused whatever signed it.
//
// It is the one check for every command type that carries templates (the
// scan executor, the kit's retest executor); it does not check the local
// policy's allow_custom_templates, which the caller does first. A command
// without templates is refused: nothing was signed.
func (e *DefaultCommandExecutor) VerifyCustomTemplates(cmd *Command, t CommandTemplates) ([][]byte, error) {
	if cmd == nil || len(t.CustomTemplates) == 0 {
		return nil, errors.New("custom templates refused: the command carries none")
	}
	contents := make([][]byte, len(t.CustomTemplates))
	for i := range t.CustomTemplates {
		c, err := decodeTemplateContent(&t.CustomTemplates[i])
		if err != nil {
			return nil, err
		}
		contents[i] = c
	}
	if cmd.jobVerified {
		got := make([]string, len(contents))
		for i, c := range contents {
			got[i] = jobsig.TemplateDigest(c)
		}
		if !slices.Equal(got, cmd.signedTemplates) {
			return nil, fmt.Errorf("custom templates refused: they are not the templates the signed job names (%d signed, %d received)",
				len(cmd.signedTemplates), len(got))
		}
	} else {
		verifier := e.templates.Load()
		if verifier == nil {
			return nil, ErrNoTemplateKeys
		}
		b := TemplateBinding{CommandID: cmd.ID}
		if id := e.sensorID.Load(); id != nil {
			b.SensorID = *id
		}
		if _, err := verifier.Verify(t.CustomTemplatesEnvelope, b, t.CustomTemplates, contents); err != nil {
			return nil, fmt.Errorf("custom templates refused: %w", err)
		}
	}
	if err := checkCustomTemplateContents(t.CustomTemplates, contents); err != nil {
		return nil, err
	}
	return contents, nil
}

// checkCustomTemplateContents is the sensor's own content check of signed
// custom templates (custom_template_check.go): a template that could run
// code here is refused whatever signed it.
func checkCustomTemplateContents(tpls []EmbeddedTemplate, contents [][]byte) error {
	for i := range tpls {
		if err := CheckCustomTemplate(tpls[i].TemplateType, contents[i]); err != nil {
			return fmt.Errorf("custom template %s refused: %w", tpls[i].Name, err)
		}
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

// applyCustomTemplates writes the templates the platform signed for the command
// and points the options at them. The returned cleanup is never nil.
func (e *DefaultCommandExecutor) applyCustomTemplates(cmd *Command, payload *ScanCommandPayload, opts *ScanOptions, local *LocalPolicy) (func(), error) {
	noop := func() {}
	if len(payload.CustomTemplates) == 0 {
		return noop, nil
	}
	if !local.AllowsCustomTemplates() {
		return noop, refuse("allow_custom_templates", "the job carries %d custom template(s); this sensor's policy does not allow platform-supplied templates", len(payload.CustomTemplates))
	}
	// SECURITY: only templates the platform signed for this command are
	// written (see verifyCustomTemplates); nothing is written before.
	if err := e.verifyCustomTemplates(cmd, payload); err != nil {
		return noop, err
	}
	templateDir, cleanup, err := e.writeCustomTemplates(payload.Scanner, payload.CustomTemplates)
	if err != nil {
		return noop, fmt.Errorf("write custom templates: %w", err)
	}
	if cleanup == nil {
		cleanup = noop
	}
	// Set template dir in options for scanner to use
	opts.CustomTemplateDir = templateDir
	if e.verbose.Load() {
		fmt.Printf("[executor] Using custom templates from %s\n", templateDir)
	}
	return cleanup, nil
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

	// A code-scan job: fetch the source first and scan the checkout. The
	// repository the platform named stays the findings' asset.
	var src *fetchedSource
	if payload.Source != nil {
		fs, err := e.fetchSource(ctx, cmd, &payload)
		if err != nil {
			return nil, err
		}
		defer fs.remove()
		src = fs
	}

	// SECURITY: targets are server-supplied. Validate every one before any
	// scanner sees it: SSRF blocklist for network targets, confinement for
	// filesystem targets, and no leading '-' (flag injection).
	targets, refusedTargets, err := e.validateScanTargets(ctx, &payload)
	if err != nil {
		// Every target is a name that does not resolve: nothing was wrong
		// with the job, the names are gone. The command completes with each
		// target skipped (reason unresolvable), not failed.
		var rerr *refusedTargetsError
		if errors.As(err, &rerr) && allUnresolvable(rerr.refused) {
			return &CommandExecutionResult{
				Metadata:       RefusedTargetsMetadata(rerr.refused),
				TargetOutcomes: payload.outcomes(nil, rerr.refused),
			}, nil
		}
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

	opts, err := e.newScanOptions(cmd, target, targets, scanner, &payload)
	if err != nil {
		return nil, err
	}
	// The packs and inline lists the signed job pins, held for the job.
	releaseContent, err := e.prepareJobContent(ctx, cmd, &payload, scanner, opts)
	if err != nil {
		return nil, err
	}
	defer releaseContent()
	// A pooled job: every tool connection goes through the organization's
	// proxy pool, or the job does not run (never direct).
	if payload.Egress != nil {
		if es, ok := scanner.(EgressScanner); !ok || !es.RoutesEgress() {
			return nil, EgressNotRouted(payload.Scanner)
		}
		pool, err := e.PrepareEgress(ctx, cmd.ID, payload.Egress)
		if err != nil {
			return nil, err
		}
		opts.Egress = pool
		ctx = WithEgressDialer(ctx, pool)
	}

	local := e.local.Load()
	if err := applyJobConfig(opts, payload.Config, local); err != nil {
		return nil, err
	}

	// The rest of the config reaches the scanner only as typed settings its
	// own schema declares (api RFC-038); an invalid value fails the command.
	// The tenant's and the sensor's layers come with the command; the job's
	// limits and per-target budget reach the tool's common options; the
	// local policy caps the rate last.
	settings, ignoredConfig, err := resolveScanSettings(e.scannerSettingsSchema(payload.Scanner, scanner), payload.SettingsLayers, payload.Config,
		jobSettings{rate: opts.RateLimit, concurrency: opts.Concurrency, targetBudget: payload.Budget.Target(), capRate: local.CapRate})
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
	// The per-target budget: the wrapper passes it as the tool's own
	// per-request timeout, RunPerTarget enforces it per target.
	opts.TargetTimeout = payload.Budget.Target()
	ProgressFrom(ctx).SetTargets(targets)

	// Which rules run: the platform's, the organization's or both; a job
	// that contradicts its own templates is refused.
	ruleSources, err := checkRuleSources(payload.RuleSources, len(payload.CustomTemplates))
	if err != nil {
		return nil, err
	}
	opts.RuleSources = ruleSources

	// Handle custom templates if provided
	cleanupTemplates, err := e.applyCustomTemplates(cmd, &payload, opts, local)
	if err != nil {
		return nil, err
	}
	defer cleanupTemplates()

	// Create context with timeout if specified: never above MaxScanTimeout
	// or the local policy's rate.max_job_seconds (which also applies when
	// the command sets none).
	// Without an explicit timeout the task budget's overrun applies, so a
	// task is stopped only well past its estimate (budget.go).
	// The job's context without its time budget (deliverCtx): a run the
	// budget stopped part-way returns what it finished (partial), delivered
	// under it, which a cancel still ends.
	// The platform's deadline for the command, when it sent one, shortens
	// the budget so the result arrives before it (run_watch.go).
	ctx, deliverCtx, cancelJob := withJobTimeout(ctx, capToDeadline(local.CapTimeout(jobTimeout(payload.TimeoutSeconds, payload.Budget)), payload.Deadline, time.Now()))
	defer cancelJob()
	// Every tool run of the job is watched (run_watch.go).
	ctx = WithRunWatch(ctx, runWatchFor(payload.Budget))

	// Run scan
	startTime := time.Now()
	var scanResult *ScanResult
	if len(targets) > 1 {
		scanResult, err = multi.ScanTargets(ctx, targets, opts)
	} else {
		scanResult, err = scanner.Scan(ctx, target, opts)
	}
	if err != nil {
		// What the run settled before it failed (a target it could not
		// reach, a host its coverage gaps name) goes with the failure; every
		// other target is unfinished.
		failed := &CommandExecutionResult{DurationMs: time.Since(startTime).Milliseconds()}
		failed.TargetOutcomes = payload.outcomes(FailureTargetOutcomes(ctx, targets, payload.evidence(ctx, nil, scanResult), nil), refusedTargets)
		return failed, atStage(StageRun, fmt.Errorf("scan failed: %w", err))
	}
	ctx = deliveryContext(ctx, deliverCtx)

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
		result.Metadata["effective_settings"] = effectiveSettings(settings)
	}
	if len(ignoredConfig) > 0 {
		result.Metadata["ignored_config_keys"] = ignoredConfig
	}
	// Targets the scan-target policy refused here (a name that no longer
	// resolves, or now resolves to a denied address, since admission): the
	// scanner never saw them; the command completes as partial.
	maps.Copy(result.Metadata, RefusedTargetsMetadata(refusedTargets))
	// Hosts the scan could not fully cover: the command completes, and the
	// result says which hosts and why.
	maps.Copy(result.Metadata, CoverageGapsMetadata(scanResult))

	// Every target is done unless the report marks it (refused, failed,
	// unfinished); the report's marks are added once it is parsed.
	result.TargetOutcomes = payload.outcomes(TargetOutcomesFor(ctx, targets, payload.evidence(ctx, nil, scanResult)), refusedTargets)

	// Parse and push results if pusher is configured. Empty (or whitespace-
	// only) output is a scan that found nothing; anything else must be read by
	// a parser, or the command fails: reporting it as 0 findings would hide
	// real results behind a "completed" scan.
	if err := e.pushScanResult(ctx, scanner, scanResult, target, targets, refusedTargets, &payload, src, result); err != nil {
		return result, err
	}

	return result, nil
}

// pushScanResult parses a scan's output and pushes the report (nothing when
// no pusher is configured), counting the findings and recording each
// target's outcome (targets, with the refused ones) on result. A code-scan job
// (src) reports on its repository as a full scan of the source's branch, an
// empty report included.
func (e *DefaultCommandExecutor) pushScanResult(ctx context.Context, scanner Scanner, scanResult *ScanResult, target string,
	targets []string, refusedTargets []RefusedTarget, payload *ScanCommandPayload, src *fetchedSource, result *CommandExecutionResult) error {
	if e.pusher != nil && len(bytes.TrimSpace(scanResult.RawOutput)) > 0 {
		parser, err := e.parsers.ForScanner(scanner.Name(), scanResult.RawOutput)
		if err != nil {
			return atStage(StageParse, fmt.Errorf("parse failed: %w", err))
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
		if src != nil {
			parseOpts.AssetType, parseOpts.AssetValue = ctis.AssetTypeRepository, src.repository
		}
		report, err := parser.Parse(ctx, scanResult.RawOutput, parseOpts)
		if err != nil {
			return atStage(StageParse, fmt.Errorf("parse failed (%s parser): %w", parser.Name(), err))
		}
		if report.Tool == nil || report.Tool.Name == "" {
			if report.Tool == nil {
				report.Tool = &ctis.Tool{}
			}
			report.Tool.Name = scanner.Name()
		}

		result.FindingsCount = len(report.Findings)
		result.TargetOutcomes = payload.outcomes(TargetOutcomesFor(ctx, targets, payload.evidence(ctx, report, scanResult)), refusedTargets)
		report.Metadata.CoverageType = reachCoverageType(ctx, scanCoverageType(report, scanResult))
		src.annotate(report)

		// Push findings
		_, err = e.pusher.PushFindings(ctx, report)
		if err != nil {
			return atStage(StageUpload, fmt.Errorf("push failed: %w", err))
		}
	} else if e.pusher != nil && src != nil {
		// A full scan of a branch that found nothing still reports, so the
		// platform marks what this tool no longer sees there as fixed.
		if _, err := e.pusher.PushFindings(ctx, src.emptyReport(scanner.Name())); err != nil {
			return atStage(StageUpload, fmt.Errorf("push failed: %w", err))
		}
	} else if e.pusher != nil {
		// A scan that found nothing still reports, bound to its command like
		// any report: without it the platform cannot tell "looked and found
		// nothing" from "never looked", and a finding the scan no longer sees
		// stays open forever. The report names no asset (nothing is created);
		// which targets were really covered travels in the command result's
		// target_outcomes.
		if _, err := e.pusher.PushFindings(ctx, emptyScanReport(ctx, scanner.Name(), scanResult)); err != nil {
			return atStage(StageUpload, fmt.Errorf("push failed: %w", err))
		}
	}

	return nil
}

// withJobTimeout bounds a job's context by timeout (none when 0) and also
// returns the context before the bound.
func withJobTimeout(ctx context.Context, timeout time.Duration) (bounded, unbounded context.Context, cancel context.CancelFunc) {
	if timeout <= 0 {
		return ctx, ctx, func() {}
	}
	bounded, cancel = context.WithTimeout(ctx, timeout)
	return bounded, ctx, cancel
}

// deliveryContext is the context a scan's results are parsed and pushed
// under: the job's, or, when only the job's time budget ended (not a
// cancel), the job's without that budget, so a run stopped part-way still
// delivers what it finished.
func deliveryContext(ctx, unbounded context.Context) context.Context {
	if errors.Is(context.Cause(ctx), ErrStoppedByPlatform) {
		// The platform asked for what the run finished.
		return context.WithoutCancel(ctx)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && unbounded.Err() == nil {
		return unbounded
	}
	return ctx
}

// validateScanTargets returns the command's targets, each validated by the
// scan-target policy, and the targets it refused. Target is the job when
// set (single-target and older payloads); otherwise Targets is. A refused
// target is left out and listed with its reason (the command completes as
// partial and says so in its result); when every target is refused the
// command fails, naming them. This runs right before the scanner starts,
// after the poller's admission: a name that resolves to a denied address
// by now (DNS rebinding) is refused here.
func (e *DefaultCommandExecutor) validateScanTargets(ctx context.Context, payload *ScanCommandPayload) ([]string, []RefusedTarget, error) {
	raw := payload.Targets
	if payload.Target != "" {
		raw = []string{payload.Target}
	}
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("invalid scan target: scan target is required")
	}
	if len(raw) > MaxScanTargets {
		return nil, nil, fmt.Errorf("invalid scan target: %d targets, more than the %d allowed per command", len(raw), MaxScanTargets)
	}

	policy := e.ScanTargetPolicy()
	if lp := e.local.Load(); lp.Present() && policy.Local == nil {
		withLocal := *policy
		withLocal.Local = lp
		policy = &withLocal
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	var (
		refused []string
		details []RefusedTarget
	)
	for _, t := range raw {
		v, err := policy.ValidateFor(ctx, payload.Scanner, t)
		if err != nil && LookupOnlyCapability(payload.Capability) {
			err = e.local.Load().lookupOnlyRefusal(t, err)
		}
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, nil, cerr
			}
			refused = append(refused, fmt.Sprintf("%q: %v", t, err))
			details = append(details, guardRefusal(t, err))
			continue
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
		if v != t {
			if payload.aliases == nil {
				payload.aliases = map[string]string{}
			}
			if _, ok := payload.aliases[v]; !ok {
				payload.aliases[v] = t
			}
		}
	}
	if len(out) == 0 {
		listed := refused
		if len(listed) > maxRefusedListed {
			listed = append(listed[:maxRefusedListed:maxRefusedListed], fmt.Sprintf("and %d more", len(refused)-maxRefusedListed))
		}
		err := fmt.Errorf("invalid scan target: %s", strings.Join(listed, "; "))
		if len(raw) > 1 {
			err = fmt.Errorf("invalid scan target: %d of %d targets refused: %s", len(refused), len(raw), strings.Join(listed, "; "))
		}
		return nil, details, &refusedTargetsError{err: err, refused: details}
	}
	return out, details, nil
}

// allUnresolvable reports whether every refused target is a name that does
// not resolve.
func allUnresolvable(refused []RefusedTarget) bool {
	if len(refused) == 0 {
		return false
	}
	for _, r := range refused {
		if r.Reason != RefusedTargetUnresolvable {
			return false
		}
	}
	return true
}

// refusedTargetsError is the error of a command whose every target was
// refused: the poller lists them in the failed result.
type refusedTargetsError struct {
	err     error
	refused []RefusedTarget
}

func (e *refusedTargetsError) Error() string { return e.err.Error() }
func (e *refusedTargetsError) Unwrap() error { return e.err }

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
	dir, _, cleanup, err := writeTemplateFiles(scannerName, templates, e.verbose.Load())
	return dir, cleanup, err
}

// WriteCustomTemplates writes verified custom templates (see
// VerifyCustomTemplates; nothing unverified may be written) to a new
// private temporary directory (0700, each file 0600) and returns the
// directory, each template's file in order, and the cleanup that removes
// them. The directory is outside the sandbox's task root, so a tool's
// sandboxed child of this sensor reads it, as a scan's custom template
// directory. The same name, size, type and content-hash checks as a scan's
// templates apply.
func WriteCustomTemplates(scannerName string, templates []EmbeddedTemplate) (dir string, files []string, cleanup func(), err error) {
	return writeTemplateFiles(scannerName, templates, false)
}

// writeTemplateFiles is WriteCustomTemplates, logging each file when
// verbose.
func writeTemplateFiles(scannerName string, templates []EmbeddedTemplate, verbose bool) (string, []string, func(), error) {
	// SECURITY: Limit number of templates to prevent resource exhaustion
	if len(templates) > MaxTemplatesPerCommand {
		return "", nil, nil, fmt.Errorf("too many templates: max %d allowed, got %d", MaxTemplatesPerCommand, len(templates))
	}

	// SECURITY: Validate all templates BEFORE creating temp directory
	for i := range templates {
		if err := ValidateTemplate(&templates[i]); err != nil {
			return "", nil, nil, fmt.Errorf("invalid template at index %d: %w", i, err)
		}
	}

	// Create temp directory for templates
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("openctem-templates-%s-*", scannerName))
	if err != nil {
		return "", nil, nil, fmt.Errorf("create temp dir: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir) //nolint:errcheck // best-effort cleanup
	}

	files := make([]string, 0, len(templates))
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
			return "", nil, nil, err
		}

		// Verify content hash if provided (mandatory for integrity)
		if tpl.ContentHash != "" {
			hash := sha256.Sum256(content)
			computedHash := hex.EncodeToString(hash[:])
			if !strings.EqualFold(computedHash, tpl.ContentHash) {
				cleanup()
				return "", nil, nil, fmt.Errorf("template %s hash mismatch: expected %s, got %s", tpl.Name, tpl.ContentHash, computedHash)
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
			return "", nil, nil, fmt.Errorf("invalid template filename: %s", tpl.Name)
		}

		// Add extension if missing
		if filepath.Ext(filename) == "" {
			filename += ext
		}

		// SECURITY: Check for duplicate filenames (could indicate attack)
		if writtenNames[filename] {
			cleanup()
			return "", nil, nil, fmt.Errorf("duplicate template filename: %s", filename)
		}
		writtenNames[filename] = true

		// SECURITY: Construct path and verify it's still within tmpDir
		filePath := filepath.Join(tmpDir, filename)
		if !isSubPath(tmpDir, filePath) {
			cleanup()
			return "", nil, nil, fmt.Errorf("template path escape detected: %s", filename)
		}

		// Write template content to file with restrictive permissions
		if err := os.WriteFile(filePath, content, 0600); err != nil {
			cleanup()
			return "", nil, nil, fmt.Errorf("write template %s: %w", tpl.Name, err)
		}

		files = append(files, filePath)
		if verbose {
			fmt.Printf("[executor] Wrote custom template: %s\n", filePath)
		}
	}

	return tmpDir, files, cleanup, nil
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
				return result, atStage(StageUpload, fmt.Errorf("push failed: %w", err))
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

// addReachMetadata puts what rec recorded in the result's metadata, unless
// the executor already reported its own reach summary.
func addReachMetadata(res *CommandResult, rec *reach.Recorder) {
	meta := rec.Metadata()
	if meta == nil {
		return
	}
	if _, ok := res.Metadata[reach.MetaReach]; ok {
		return
	}
	if res.Metadata == nil {
		res.Metadata = map[string]any{}
	}
	maps.Copy(res.Metadata, meta)
}

// reachCoverageType makes a full coverage partial when the job's recorder
// saw targets it could not reach: what the scan did not report on them is
// not "no findings".
func reachCoverageType(ctx context.Context, coverage string) string {
	if coverage != coverageTypeFull {
		return coverage
	}
	if rec := reach.FromContext(ctx); rec != nil && rec.Report().Unreached > 0 {
		return coverageTypePartial
	}
	return coverage
}

// scanCoverageType is the coverage_type a scan command's report declares.
// Every report states one: a receiver must not read an absent value as full
// (CTIS spec 4.5), and the platform auto-resolves findings a run no longer
// reports only on full coverage.
//
//   - A run the scanner says stopped part-way (ScanResult.Error), with
//     targets it could not scan (properties.failed_targets) or with hosts
//     it could not fully cover (ScanResult.CoverageGaps) is partial, even
//     when the parser declared full.
//   - Otherwise a value the parser declared is kept.
//   - A repository scan (metadata.branch set) is partial: it has its own,
//     default-branch-gated auto-resolve, and the runtime cannot tell that the
//     checkout was the whole repository.
//   - Anything else, a completed run over its targets, is full.
func scanCoverageType(report *ctis.Report, r *ScanResult) string {
	declared := report.Metadata.CoverageType
	if (r != nil && (r.Error != "" || r.HasCoverageGaps())) || hasFailedTargets(report) {
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

// emptyScanReport is the report of a scan that found nothing: the tool and
// the coverage the run proves (partial when a target was not covered, by the
// same rules as a report with findings).
func emptyScanReport(ctx context.Context, tool string, r *ScanResult) *ctis.Report {
	report := ctis.NewReport()
	report.Tool = &ctis.Tool{Name: tool}
	if r != nil && r.ScannerVersion != "" {
		report.Tool.Version = r.ScannerVersion
	}
	report.Metadata.CoverageType = reachCoverageType(ctx, scanCoverageType(report, r))
	return report
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
