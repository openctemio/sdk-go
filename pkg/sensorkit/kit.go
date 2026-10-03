package sensorkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/platform"
	"github.com/openctemio/sdk-go/pkg/resource"
)

// Options configure a Kit. The zero value is a server-controlled sensor that
// reads its settings from the environment: every field left zero takes the
// environment variable named in its comment, then the default. A sensor with
// its own flags or configuration file sets the fields it resolved.
type Options struct {
	// Name is the sensor's name on the platform (SENSOR_NAME; default
	// "sensor-<hostname>").
	Name string
	// Version is the sensor binary's version, reported on every heartbeat.
	Version string
	// ProductName, Commit and BuildTime describe the binary on every
	// heartbeat (all optional; see core.BaseSensorConfig). A ProductName is
	// also the product in the User-Agent of every request.
	ProductName, Commit, BuildTime string
	// Region is the deployment region (REGION, AWS_REGION, ...).
	Region string

	// APIURL is the platform's URL (API_URL).
	APIURL string
	// APIKey is the sensor's API key (API_KEY).
	APIKey string
	// SensorID is the sensor's id, when the key is not bound to one
	// (SENSOR_ID).
	SensorID string
	// Protocol is the sensor protocol: auto, v1 or v2 (SENSOR_PROTOCOL;
	// default auto: v2 for everything the platform offers on hello, v1 for
	// the rest).
	Protocol string
	// Timeout bounds one request to the platform (default 30s).
	Timeout time.Duration
	// CACertFile is a PEM file with the platform's private CA
	// (SENSOR_CA_CERT_FILE), or the CA of a TLS-inspecting egress proxy:
	// trusted besides the system trust store for platform requests and
	// content downloads.
	CACertFile string
	// TemplateSigningKeys are the platform's template-signing public keys
	// (SENSOR_TEMPLATE_SIGNING_KEYS; base64 Ed25519, comma-separated), as
	// the platform shows them for the sensor's tenant. Custom templates in
	// a scan command must carry a signature one of them verifies; without
	// any, such commands fail (core.ErrNoTemplateKeys).
	TemplateSigningKeys string
	// ControlProxy, ContentProxy and ScanProxy are the proxy settings of
	// the three outbound paths (SENSOR_CONTROL_PROXY, SENSOR_CONTENT_PROXY,
	// SENSOR_SCAN_PROXY; see ResolveProxies for values and precedence).
	// Unset, the platform and content paths use HTTP(S)_PROXY / NO_PROXY
	// and scanners inherit them (api RFC-034).
	ControlProxy string
	ContentProxy string
	ScanProxy    string
	// Standalone runs without the platform: scheduled scans only, results
	// are not sent.
	Standalone bool
	// CredentialsHelp words the error of a sensor started without the
	// platform URL or key (see CheckCredentials).
	CredentialsHelp CredentialsHelp

	// DisableCommands runs no platform commands (scheduled scans and
	// collections only). By default the sensor runs the scans the platform
	// dispatches.
	DisableCommands bool
	// CommandPollInterval is how often the sensor polls for commands when
	// the platform gives no doorbell hints (default 30s).
	CommandPollInterval time.Duration
	// DisableDoorbell ignores the heartbeat doorbell and polls on the fixed
	// interval.
	DisableDoorbell bool
	// MaxJobs caps the commands run at once, 1-100 (SENSOR_MAX_JOBS; default
	// no cap: the slots follow the CPU, memory and tools' learned cost).
	MaxJobs int
	// ScannerPriority is the priority of scanner processes: "low" (default)
	// or "normal" (SENSOR_SCANNER_PRIORITY; see ResolveScannerPriority).
	ScannerPriority string
	// ProtectFromOOM protects the sensor itself from the OOM killer
	// (SENSOR_PROTECT_FROM_OOM; default off): Run writes SensorOOMScoreAdj
	// to its oom_score_adj. Linux only, and it needs CAP_SYS_RESOURCE
	// (docker run --cap-add SYS_RESOURCE, or root under systemd); without
	// it the sensor warns and runs unprotected. Scanners never inherit the
	// protection. true wins over the environment.
	ProtectFromOOM bool
	// Tools is an operator allowlist of tool names (SENSOR_TOOLS): scanners
	// whose name (or As name) is not in it are neither run nor reported. nil
	// reads SENSOR_TOOLS; an empty non-nil slice sets no allowlist.
	Tools []string

	// Targets are scanned by every scanner each ScanInterval (default 1h);
	// collectors run each CollectInterval (default 15m). A server-controlled
	// sensor usually has no targets of its own.
	Targets         []string
	ScanInterval    time.Duration
	CollectInterval time.Duration
	// HeartbeatInterval is the heartbeat period when the platform advises
	// none (default 1m).
	HeartbeatInterval time.Duration

	// Outbox are the durable outbox's settings (results are on disk before
	// the first send and survive restarts); SENSOR_OUTBOX* override them and
	// OutboxOverrides beat those. On by default.
	Outbox          OutboxSettings
	OutboxOverrides OutboxOverrides
	// StateDir keeps the sensor's local state: the API key it renews and the
	// tool cost history (SENSOR_STATE_DIR; default /var/lib/openctem/state
	// when writable, else ~/.openctem; platform.ResolveStateDir). Mount a
	// persistent volume there.
	StateDir string

	// Key auto-renewal (api RFC-032 Phase 0): the API key is renewed before
	// it expires and when the platform asks, kept in CredentialsFile
	// (default sensor-credentials.json in StateDir; one an earlier version
	// kept in ~/.openctem is moved there) and preferred over the configured
	// key on the next start, unless the configured key changed since.
	// KeyAutoRenew forces renewal on, NoKeyAutoRenew forces it off; with
	// neither, PLATFORM_KEY_AUTORENEW=true|false decides, and unset it is on
	// only when StateDir survives the sensor being recreated (outside a
	// container always; inside, on a mounted, non-tmpfs volume).
	KeyAutoRenew    bool
	NoKeyAutoRenew  bool
	CredentialsFile string

	// Content is the sensor's scanner content, when it manages any (see
	// Content).
	Content Content
	// ScanTargetPolicy restricts the targets of dispatched scans (nil: the
	// SDK default, core.DefaultScanTargetPolicy). Its AllowedRoots are
	// logged as the scan workspace.
	ScanTargetPolicy *core.ScanTargetPolicy
	// LocalPolicy is the sensor-local policy the network owner set at
	// install time (api RFC-040 §5.7): every dispatched job is checked
	// against it before any tool runs, and refused jobs are reported failed
	// with "refused by local policy: <rule>". nil: New loads it from
	// LocalPolicyPath (core.LoadLocalPolicy); a policy that cannot be loaded
	// stops New (fail closed). Nothing the platform sends changes it.
	LocalPolicy *core.LocalPolicy
	// LocalPolicyPath is the policy file (SENSOR_LOCAL_POLICY; default
	// core.DefaultLocalPolicyPath when that file exists). Without a file,
	// SENSOR_ALLOWED_RANGES / SENSOR_ALLOWED_PORTS make a shorthand policy;
	// without those the policy is absent: the sensor works as before and
	// reports local_policy "absent".
	LocalPolicyPath string
	// WorkDir is where scans write; its free disk is part of the slot
	// sizing (default StateDir).
	WorkDir string
	// AssetResolver names the asset a scan's findings belong to when the
	// parser does not; CommandAssetResolver replaces it for dispatched scans.
	AssetResolver        core.AssetResolver
	CommandAssetResolver core.AssetResolver
	// UnavailableReason explains why an added scanner cannot run here: its
	// IsInstalled said no, with checkErr. name is its As name, else its
	// Name. nil: the check's error.
	UnavailableReason func(ctx context.Context, name string, checkErr error) string

	// Verbose logs every heartbeat and poll.
	Verbose bool
	// Stdout and Stderr receive the kit's log lines (default os.Stdout and
	// os.Stderr).
	Stdout, Stderr io.Writer
}

// Content is scanner content the sensor manages (vulnerability databases,
// templates, rules): every heartbeat reports, per tool, the content it scans
// with (api RFC-031). A Content may also implement ContentStarter (refresh in
// the background) and PusherWrapper (stamp results with the content their
// scan used).
type Content interface {
	// Decorate adds each tool's content to the heartbeat's report.
	Decorate(core.CapabilityReport) core.CapabilityReport
}

// ContentStarter is a Content with background work: Run calls Start once,
// before the first heartbeat, with the context Run stops on.
type ContentStarter interface {
	Start(ctx context.Context)
}

// PusherWrapper is a Content that stamps the results of dispatched commands
// (with the content their scan used): the kit sends them through WrapPusher.
type PusherWrapper interface {
	WrapPusher(core.Pusher) core.Pusher
}

// Default command settings.
const (
	DefaultCommandPollInterval = 30 * time.Second
	// costStateFile keeps the tools' learned cost in the state directory.
	costStateFile = "tool-costs.json"
)

// defaultCommandTypes are the command types the SDK's executor serves.
var defaultCommandTypes = []string{"scan", "collect", "health_check"}

// settings are the Options and environment, resolved by New.
type settings struct {
	name, apiURL, apiKey, sensorID, protocol string
	commands                                 bool
	verbose                                  bool
	maxJobs                                  int
	drainGrace                               time.Duration
	pollInterval                             time.Duration
	allow                                    []string // nil: no allowlist
	scannerPriority                          *core.ScannerPriority
	protectFromOOM                           bool
	outbox                                   OutboxPlan
	stateDir                                 string
	key                                      startKey
	templates                                *core.TemplateVerifier
	local                                    *core.LocalPolicy
}

// scannerEntry is an added scanner.
type scannerEntry struct {
	s    core.Scanner
	as   string
	caps []string
}

// label names the scanner the way the operator configured it.
func (e scannerEntry) label() string {
	if e.as != "" {
		return e.as
	}
	return e.s.Name()
}

type middleware struct {
	wrap  func(core.CommandExecutor) core.CommandExecutor
	types []string
}

// Kit is a sensor's runtime: the platform connection, heartbeat, doorbell,
// command queue, outbox, key renewal and shutdown. A sensor adds its tools
// and calls Run.
type Kit struct {
	opts      Options
	s         settings
	out, errw io.Writer

	client *client.Client
	sensor *core.BaseSensor
	bcfg   core.BaseSensorConfig

	scanners    []scannerEntry
	collectors  []core.Collector
	parsers     []core.Parser
	handlers    map[string]core.CommandExecutor
	middlewares []middleware
	ran         bool
}

// New resolves the settings, checks them, connects the platform client and
// opens the outbox. It prints what an operator needs to know (the outbox,
// a renewed key in use). An error carries the exit code (ExitCode).
func New(opts Options) (*Kit, error) {
	if err := MigrateLegacyEnv(); err != nil {
		return nil, err
	}
	k := &Kit{opts: opts, out: orStdout(opts.Stdout), errw: orStderr(opts.Stderr), handlers: map[string]core.CommandExecutor{}}
	s := &k.s
	s.apiURL = envOr(opts.APIURL, EnvAPIURL)
	s.apiKey = envOr(opts.APIKey, EnvAPIKey)
	s.sensorID = envOr(opts.SensorID, EnvSensorID)
	s.commands = !opts.DisableCommands
	s.verbose = opts.Verbose

	if s.commands && !opts.Standalone {
		if err := CheckCredentials(s.apiURL, s.apiKey, opts.CredentialsHelp); err != nil {
			return nil, err
		}
	}
	// Scan-target switches the SDK would otherwise misread silently.
	if err := core.CheckEnv(); err != nil {
		return nil, err
	}
	// The sensor-local policy: a policy that cannot be loaded stops the
	// sensor (fail closed); none at all keeps today's behavior, with a
	// warning (api RFC-040 Q3 (a)).
	local, err := k.loadLocalPolicy()
	if err != nil {
		return nil, err
	}
	s.local = local
	protocol, err := ResolveProtocol(opts.Protocol, "")
	if err != nil {
		return nil, err
	}
	s.protocol = protocol
	if s.outbox, err = ResolveOutbox(opts.Outbox, opts.OutboxOverrides, true); err != nil {
		return nil, err
	}
	if f := envOr(opts.CACertFile, EnvCACertFile); f != "" {
		pool, err := httpsec.LoadCAFile(f)
		if err != nil {
			return nil, err
		}
		httpsec.SetAPIRootCAs(pool)
		httpsec.SetContentRootCAs(pool)
	}
	if keys := envOr(opts.TemplateSigningKeys, EnvTemplateSigningKeys); strings.TrimSpace(keys) != "" {
		v, err := core.ParseTemplateSigningKeys(keys)
		if err != nil {
			return nil, usageError(fmt.Errorf("%s: %w", EnvTemplateSigningKeys, err))
		}
		s.templates = v
	}
	proxyOpts := ProxyOptions{Control: opts.ControlProxy, Content: opts.ContentProxy, Scan: opts.ScanProxy}
	proxies, err := ResolveProxies(proxyOpts)
	if err != nil {
		return nil, err
	}
	proxies.Apply()
	proxies.report(k.out, k.errw, proxyOpts)

	s.stateDir = ResolveStateDir(opts.StateDir)

	// The API key: a key renewed by an earlier run is in the state
	// directory (the renewal retired the configured one), whether or not
	// this run renews.
	if !opts.Standalone {
		renewSetting := os.Getenv(EnvKeyAutoRenew)
		switch {
		case opts.KeyAutoRenew:
			renewSetting = "true"
		case opts.NoKeyAutoRenew:
			renewSetting = "false"
		}
		sk, err := resolveStartKey(opts.CredentialsFile, s.stateDir, s.apiKey, s.sensorID, renewSetting)
		if err != nil {
			return nil, fmt.Errorf("credentials file: %w", err)
		}
		if sk.fromStateFile {
			_, _ = fmt.Fprintf(k.errw, "Using the renewed API key from %s\n", sk.file)
		}
		s.apiKey, s.key = sk.key, sk
	}

	if !opts.Standalone && s.apiURL != "" && s.apiKey != "" {
		k.client = client.New(&client.Config{
			BaseURL:  s.apiURL,
			APIKey:   s.apiKey,
			SensorID: s.sensorID,
			Timeout:  opts.Timeout,
			Verbose:  s.verbose,
			Protocol: protocol,
		})
		// Durable outbox: results are on disk before the first send.
		if err := EnableOutbox(k.client, s.outbox, s.verbose, k.out, k.errw); err != nil {
			k.closeClient()
			return nil, fmt.Errorf("outbox: %w", err)
		}
		if s.verbose {
			_, _ = fmt.Fprintf(k.out, "  Sensor protocol: %s\n", protocol)
		}
	}

	if s.drainGrace, err = ResolveDrainGrace(); err != nil {
		k.closeClient()
		return nil, err
	}
	if opts.MaxJobs != 0 {
		s.maxJobs, err = checkMaxJobs("MaxJobs", opts.MaxJobs)
	} else {
		s.maxJobs, err = ResolveMaxJobs(MaxJobsSetting{}, MaxJobsSetting{})
	}
	if err != nil {
		k.closeClient()
		return nil, err
	}
	if s.scannerPriority, err = ResolveScannerPriority(opts.ScannerPriority); err != nil {
		k.closeClient()
		return nil, err
	}
	if s.protectFromOOM, err = ResolveProtectFromOOM(opts.ProtectFromOOM); err != nil {
		k.closeClient()
		return nil, err
	}
	s.pollInterval = opts.CommandPollInterval
	if s.pollInterval <= 0 {
		s.pollInterval = DefaultCommandPollInterval
	}
	switch {
	case opts.Tools != nil:
		if len(opts.Tools) > 0 {
			s.allow = opts.Tools
		}
	default:
		s.allow = ParseToolList(os.Getenv(EnvTools))
	}

	s.name = firstNonEmpty(opts.Name, os.Getenv(EnvSensorName))
	if s.name == "" {
		hostname, _ := os.Hostname()
		s.name = fmt.Sprintf("sensor-%s", hostname)
	}
	k.bcfg = core.BaseSensorConfig{
		Name:              s.name,
		Version:           opts.Version,
		ProductName:       opts.ProductName,
		Commit:            opts.Commit,
		BuildTime:         opts.BuildTime,
		Region:            opts.Region,
		ScanInterval:      opts.ScanInterval,
		CollectInterval:   opts.CollectInterval,
		HeartbeatInterval: opts.HeartbeatInterval,
		Targets:           opts.Targets,
		Verbose:           s.verbose,
	}
	var pusher core.Pusher
	if k.client != nil {
		pusher = k.client
	}
	// NewBaseSensor fills the config's defaults (the banner prints them).
	k.sensor = core.NewBaseSensor(&k.bcfg, pusher)
	// Every heartbeat and manifest reports the local policy (to a platform
	// that reads it).
	k.sensor.SetLocalPolicy(s.local)
	return k, nil
}

// loadLocalPolicy is Options.LocalPolicy, else the policy loaded from
// Options.LocalPolicyPath, and logs it with its warnings.
func (k *Kit) loadLocalPolicy() (*core.LocalPolicy, error) {
	lp := k.opts.LocalPolicy
	if lp == nil {
		var err error
		if lp, err = core.LoadLocalPolicy(core.LocalPolicyOptions{Path: k.opts.LocalPolicyPath}); err != nil {
			return nil, usageError(err)
		}
	}
	_, _ = fmt.Fprintf(k.out, "  Local policy: %s\n", lp.Describe())
	for _, w := range lp.Warnings() {
		_, _ = fmt.Fprintf(k.errw, "Warning: %s\n", w)
	}
	return lp, nil
}

func (k *Kit) closeClient() {
	if k.client != nil {
		_ = k.client.Close()
	}
}

// ScannerOption configures an added scanner.
type ScannerOption func(*scannerEntry)

// As is the name the operator configured the scanner under when it differs
// from its Name ("trivy-fs" runs the "trivy" scanner): a command dispatched
// under that name finds it, the allowlist matches it and log lines use it.
func As(name string) ScannerOption {
	return func(e *scannerEntry) { e.as = strings.TrimSpace(name) }
}

// WithCapabilities adds capabilities the scanner serves besides the ones its
// Capabilities words map to ("container" for an image scanner).
func WithCapabilities(caps ...string) ScannerOption {
	return func(e *scannerEntry) { e.caps = append(e.caps, caps...) }
}

// AddScanner adds a tool. Every heartbeat reports it (installed or not, with
// its version: the platform dispatches by that report), dispatched scans for
// it run it, and, when it is installed at start, it scans the Targets on
// schedule. Call before Run.
func (k *Kit) AddScanner(s core.Scanner, opts ...ScannerOption) {
	if s == nil {
		return
	}
	e := scannerEntry{s: s}
	for _, o := range opts {
		o(&e)
	}
	k.scanners = append(k.scanners, e)
}

// AddCollector adds a collector: it runs on schedule and for dispatched
// collect commands. Call before Run.
func (k *Kit) AddCollector(c core.Collector) {
	if c != nil {
		k.collectors = append(k.collectors, c)
	}
}

// AddParser adds a parser for a tool's own output format (the SDK reads
// SARIF and CTIS by itself); scheduled and dispatched scans use it. Call
// before Run.
func (k *Kit) AddParser(p core.Parser) {
	if p != nil {
		k.parsers = append(k.parsers, p)
	}
}

// HandleCommand runs the platform's commands of type typ with e instead of
// the SDK's executor (which serves scan, collect and health_check), and
// makes the sensor accept that type. Call before Run.
func (k *Kit) HandleCommand(typ string, e core.CommandExecutor) {
	if typ != "" && e != nil {
		k.handlers[typ] = e
	}
}

// UseCommandMiddleware wraps the command executor: every command passes
// through mw before the handlers and the SDK's executor (the first
// middleware added is the outermost). types are command types mw serves by
// itself; the sensor accepts them. Call before Run.
func (k *Kit) UseCommandMiddleware(mw func(next core.CommandExecutor) core.CommandExecutor, types ...string) {
	if mw != nil {
		k.middlewares = append(k.middlewares, middleware{wrap: mw, types: types})
	}
}

// Tools is the tool registry every heartbeat reports: register tools the
// sensor runs some other way, or capabilities it serves whatever its tools
// (AddCapabilities("validate")). The scanners added with AddScanner are
// registered by Run, after anything registered here.
func (k *Kit) Tools() *core.ToolRegistry { return k.sensor.Tools() }

// Client is the platform client (nil when standalone or not configured).
func (k *Kit) Client() *client.Client { return k.client }

// Sensor is the underlying core.BaseSensor, for settings the kit does not
// cover. Change it only before Run.
func (k *Kit) Sensor() *core.BaseSensor { return k.sensor }

// Name is the sensor's name.
func (k *Kit) Name() string { return k.s.name }

// allowed reports whether the allowlist lets e through.
func (k *Kit) allowed(e scannerEntry) bool {
	if k.s.allow == nil {
		return true
	}
	for _, a := range k.s.allow {
		if strings.EqualFold(a, e.s.Name()) || (e.as != "" && strings.EqualFold(a, e.as)) {
			return true
		}
	}
	return false
}

// Run runs the sensor until ctx is canceled (or SIGINT/SIGTERM, unless ctx
// comes from SignalContext): it reports the tools, checks the platform
// accepts the key (waiting while it does not), then heartbeats, runs the
// dispatched commands and the scheduled scans. On shutdown it drains: no
// new command is claimed, running ones get the drain grace
// (SENSOR_DRAIN_GRACE) and are then stopped and handed back to the platform;
// undelivered results stay in the outbox. It returns nil after a clean
// shutdown.
func (k *Kit) Run(ctx context.Context) error {
	if k.ran {
		return errors.New("sensorkit: Run called twice")
	}
	k.ran = true
	if ctx.Value(signalKey{}) == nil {
		var stop context.CancelFunc
		ctx, stop = SignalContext(ctx, k.out)
		defer stop()
	}
	defer k.closeClient()

	s, out, errw := k.sensor, k.out, k.errw
	for _, p := range k.parsers {
		s.AddParser(p)
	}
	if k.opts.AssetResolver != nil {
		s.SetAssetResolver(k.opts.AssetResolver)
	}

	// The tool inventory: every allowed scanner, installed or not, in the
	// order added; the heartbeat probes them.
	reg := s.Tools()
	scanners := k.inventory(reg)
	reg.SetMaxConcurrentJobs(k.s.maxJobs)
	// A tool's version check runs in the background after the first one: on
	// a saturated sensor it takes seconds, and the heartbeat must not wait
	// for it (api RFC-035 §5.1).
	reg.SetBackgroundRefresh(true)
	// Scanner processes yield the CPU and the disk to the sensor and are
	// OOM-killed before it (api RFC-035 §5.3).
	core.SetScannerPriority(k.s.scannerPriority)
	if p := k.s.scannerPriority; p != nil {
		_, _ = fmt.Fprintf(out, "  Scanner priority: low (nice +%d, I/O best-effort %d, oom_score_adj %d; %s=normal turns it off)\n",
			p.Nice, p.IOLevel, p.OOMScoreAdj, EnvScannerPriority)
	} else {
		_, _ = fmt.Fprintf(out, "  Scanner priority: normal (the sensor's own)\n")
	}
	// Opt-in: the sensor itself is the OOM killer's last choice. Before any
	// scanner starts; ApplyScannerPriority keeps scanners from inheriting it.
	if k.s.protectFromOOM {
		protectFromOOM(out, errw, writeSelfOOMScoreAdj)
	}

	// Scheduled scans: the scanners installed now.
	for _, e := range scanners {
		installed, _, err := e.s.IsInstalled(ctx)
		if err != nil || !installed {
			_, _ = fmt.Fprintf(errw, "Warning: Scanner %s skipped: %s\n", e.label(), k.unavailableReason(ctx, e.label(), err))
			continue
		}
		if err := s.AddScanner(e.s); err != nil {
			_, _ = fmt.Fprintf(errw, "Error adding scanner %s: %v\n", e.label(), err)
			continue
		}
		_, _ = fmt.Fprintf(out, "  Added scanner: %s\n", e.s.Name())
	}
	for _, c := range k.collectors {
		if err := s.AddCollector(c); err != nil {
			_, _ = fmt.Fprintf(errw, "Error adding collector %s: %v\n", c.Name(), err)
			continue
		}
		_, _ = fmt.Fprintf(out, "  Added collector: %s\n", c.Name())
	}

	// API-key auto-renewal: on schedule, and at once when the platform's
	// heartbeat says rotate_key.
	var renewal *platform.KeyRenewManager
	if k.s.key.autoRenew && k.client != nil {
		m, err := startKeyRenewal(ctx, &k.s, k.client, out)
		if err != nil {
			_, _ = fmt.Fprintf(errw, "Warning: key auto-renew failed to start: %v\n", err)
		} else {
			renewal = m
			_, _ = fmt.Fprintf(out, "  Key auto-renew: enabled, %s (credentials: %s)\n", k.s.key.why, k.s.key.file)
		}
	} else if k.client != nil && k.s.key.why != "" {
		_, _ = fmt.Fprintf(out, "  Key auto-renew: %s\n", k.s.key.why)
	}
	defer func() {
		if renewal != nil {
			renewal.Stop()
		}
	}()

	// Heartbeat doorbell: the heartbeat answer says when work is waiting
	// (poll now), pauses or drains the sensor, and asks for key rotation.
	var doorbell *core.Doorbell
	if k.client != nil && !k.opts.DisableDoorbell {
		var renewNow func()
		if renewal != nil {
			renewNow = renewal.RenewNow
		}
		doorbell = core.NewDoorbell(&core.DoorbellConfig{OnRotateKey: renewNow, Verbose: k.s.verbose})
		s.SetDoorbell(doorbell)
	}

	if cs, ok := k.opts.Content.(ContentStarter); ok {
		cs.Start(ctx)
	}
	// Every heartbeat (the first one included) reports the tools really
	// installed, with versions and content, the capabilities served and the
	// concurrency cap (api RFC-029 §4.3.1).
	if k.client != nil {
		s.SetCapabilityReporter(&capabilityReporter{tools: reg, content: k.opts.Content})
	}

	var poller *core.CommandPoller
	if k.s.commands && k.client != nil {
		poller = k.newPoller(scanners, doorbell)
	}

	// Connection check: the first heartbeat, sent after the poller is set
	// up (it carries the load report) and before the poller starts, so the
	// platform knows the capacity before the first poll (api RFC-030). While
	// the platform rejects the key the sensor stays up and retries with a
	// capped backoff instead of exiting into a restart loop.
	if k.client != nil && !waitForAcceptedKey(ctx, s.FirstHeartbeat, sleepCtx, out) {
		_, _ = fmt.Fprintln(out, "Sensor stopped.")
		return nil
	}

	// pollerDone closes when the poller has drained.
	pollerDone := make(chan struct{})
	if poller != nil {
		go func() {
			defer close(pollerDone)
			if err := poller.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
				_, _ = fmt.Fprintf(errw, "Command poller error: %v\n", err)
			}
		}()
	} else {
		close(pollerDone)
	}

	if err := s.Start(ctx); err != nil {
		return fmt.Errorf("failed to start sensor: %w", err)
	}
	k.printBanner(doorbell != nil)

	<-ctx.Done()

	if renewal != nil {
		renewal.Stop()
		renewal = nil
	}
	// Drain: claim nothing more, let running commands finish for the drain
	// grace, then stop them and release them to the platform so another
	// sensor takes them at once (api RFC-030). Commands do not run under
	// ctx, so the signal does not kill them.
	if poller != nil {
		poller.Stop()
		if st := poller.QueueStats(); st.Claimed > 0 {
			_, _ = fmt.Fprintf(out, "Draining: %d command(s) running; up to %s before they are stopped and handed back to the platform (%s)\n",
				st.Claimed, k.s.drainGrace, EnvDrainGrace)
		}
	}
	<-pollerDone

	// Undelivered results stay in the outbox for the next start.
	if k.client != nil {
		if st, ok := k.client.OutboxStats(); ok && (st.PendingCount > 0 || st.DeadLetterCount > 0) {
			_, _ = fmt.Fprintf(out, "Outbox: %d result(s) wait for delivery, %d dead letter(s) (%s)\n",
				st.PendingCount, st.DeadLetterCount, k.client.Outbox().Dir())
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Stop(shutdownCtx); err != nil {
		_, _ = fmt.Fprintf(errw, "Shutdown error: %v\n", err)
	}
	if k.client != nil {
		if err := k.client.Close(); err != nil && k.s.verbose {
			_, _ = fmt.Fprintf(out, "Warning: Error closing client: %v\n", err)
		}
		k.client = nil
	}
	_, _ = fmt.Fprintln(out, "Sensor stopped.")
	return nil
}

// inventory registers the scanners the sensor runs: those SENSOR_TOOLS and
// the local policy's tools.allow let through, in the order added. The rest
// are neither run nor reported, so the platform routes no job for them here.
func (k *Kit) inventory(reg *core.ToolRegistry) []scannerEntry {
	var scanners []scannerEntry
	for _, e := range k.scanners {
		if !k.allowed(e) {
			_, _ = fmt.Fprintf(k.errw, "Note: scanner %s is not in %s; it is not run\n", e.label(), EnvTools)
			continue
		}
		if !k.s.local.AllowsTool(e.label()) && !k.s.local.AllowsTool(e.s.Name()) {
			_, _ = fmt.Fprintf(k.errw, "Note: scanner %s is not in the local policy's tools.allow; it is not run\n", e.label())
			continue
		}
		scanners = append(scanners, e)
		if err := reg.RegisterScanner(e.s, e.caps...); err != nil && k.s.verbose {
			_, _ = fmt.Fprintf(k.errw, "Warning: scanner %s is not reported to the platform: %v\n", e.label(), err)
		}
	}
	return scanners
}

// newPoller sets up the command executor and poller.
func (k *Kit) newPoller(scanners []scannerEntry, doorbell *core.Doorbell) *core.CommandPoller {
	out := k.out
	var pusher core.Pusher = k.client
	if pw, ok := k.opts.Content.(PusherWrapper); ok {
		pusher = pw.WrapPusher(pusher)
	}
	executor := core.NewDefaultCommandExecutor(pusher)
	// Each tool's output goes to the parser of its format; output no parser
	// reads fails its command rather than reporting 0 findings.
	parsers := core.NewParserRegistry()
	for _, p := range k.parsers {
		parsers.Register(p)
	}
	executor.SetParserRegistry(parsers)
	executor.SetTemplateVerifier(k.s.templates)
	if k.s.sensorID != "" {
		// Configured locally (SENSOR_ID), so a template manifest signed
		// for another sensor is refused.
		executor.SetSensorID(k.s.sensorID)
	}
	if k.opts.ScanTargetPolicy != nil {
		executor.SetScanTargetPolicy(k.opts.ScanTargetPolicy)
	}
	// The local policy, behind the poller's admission check: targets
	// (through the scan target policy), templates, callbacks, rate and
	// run time.
	executor.SetLocalPolicy(k.s.local)
	if r := k.opts.CommandAssetResolver; r != nil {
		executor.SetAssetResolver(r)
	} else if r := k.opts.AssetResolver; r != nil {
		executor.SetAssetResolver(r)
	}
	tools := make([]string, 0, len(scanners))
	for _, e := range scanners {
		executor.AddScanner(e.s)
		// Also answer to the configured name when it differs.
		if e.as != "" && e.as != e.s.Name() {
			executor.AddScanner(aliasScanner{Scanner: e.s, name: e.as})
		}
		tools = append(tools, strings.ToLower(e.s.Name()))
	}
	for _, c := range k.collectors {
		executor.AddCollector(c)
	}

	types := slices.Clone(defaultCommandTypes)
	var exec core.CommandExecutor = executor
	if len(k.handlers) > 0 {
		exec = &commandRouter{handlers: k.handlers, fallback: executor}
		for t := range k.handlers {
			types = appendType(types, t)
		}
	}
	for i := len(k.middlewares) - 1; i >= 0; i-- {
		exec = k.middlewares[i].wrap(exec)
		for _, t := range k.middlewares[i].types {
			types = appendType(types, t)
		}
	}

	// Slots follow what this sensor may use (cgroup-aware CPU and memory)
	// and its tools' learned cost, at most the operator's cap.
	workDir := firstNonEmpty(k.opts.WorkDir, k.s.stateDir)
	var stateFile string
	if k.s.stateDir != "" {
		stateFile = filepath.Join(k.s.stateDir, costStateFile)
	}
	rcfg := resource.ManagerConfig{
		Cap:       k.s.maxJobs,
		Tools:     tools,
		StateFile: stateFile,
		Prober:    &resource.Prober{WorkDir: workDir},
		OnError:   func(err error) { _, _ = fmt.Fprintf(k.errw, "Warning: %v\n", err) },
	}
	if hints := k.sensor.Tools().CostHints(); len(hints) > 0 {
		rcfg.CostHints = hints
	}
	resources := resource.NewManager(rcfg)

	poller := core.NewCommandPoller(k.client, exec, &core.CommandPollerConfig{
		DrainGrace:    k.s.drainGrace,
		PollInterval:  k.s.pollInterval,
		MaxConcurrent: resources.MaxSlots(),
		AllowedTypes:  types,
		Verbose:       k.s.verbose,
	})
	poller.SetResourceManager(resources)
	if doorbell != nil {
		poller.SetDoorbell(doorbell)
	}
	// No polling while the platform rejects the key (also without the
	// doorbell); polling resumes with the first accepted heartbeat.
	poller.SetAuthGate(k.sensor.AuthGate())
	// Heartbeats report the commands running now and the slot count.
	k.sensor.SetLoadReporter(poller)
	// Commands for tools outside the platform's policy fail instead of
	// running (api RFC-033 §6.12, a second line behind the platform's gates).
	poller.SetCommandGate(k.sensor.CommandToolGate())
	// The sensor-local policy decides first: admission before any executor
	// or tool, and the local kill switch (api RFC-040 §5.7).
	poller.SetLocalPolicy(k.s.local)

	if p := k.opts.ScanTargetPolicy; p != nil && len(p.AllowedRoots) > 0 {
		_, _ = fmt.Fprintf(out, "  Scan workspace: %s\n", strings.Join(p.AllowedRoots, string(filepath.ListSeparator)))
	}
	if doorbell != nil {
		_, _ = fmt.Fprintf(out, "  Command polling: on the heartbeat doorbell (fixed %s interval with a server that sends no hints)\n", k.s.pollInterval)
	} else {
		_, _ = fmt.Fprintf(out, "  Command polling: enabled (interval: %s)\n", k.s.pollInterval)
	}
	if k.s.maxJobs > 0 {
		_, _ = fmt.Fprintf(out, "  Concurrent jobs: up to %d (now %d, from CPU, memory and tool costs)\n", k.s.maxJobs, resources.Slots(0))
	} else {
		_, _ = fmt.Fprintf(out, "  Concurrent jobs: %d now (from CPU, memory and tool costs; cap with %s)\n", resources.Slots(0), EnvMaxJobs)
	}
	return poller
}

func appendType(types []string, t string) []string {
	if t != "" && !slices.Contains(types, t) {
		types = append(types, t)
	}
	return types
}

func (k *Kit) unavailableReason(ctx context.Context, name string, err error) string {
	if k.opts.UnavailableReason != nil {
		return k.opts.UnavailableReason(ctx, name, err)
	}
	if err != nil {
		return fmt.Sprintf("its check failed: %v", err)
	}
	return "not installed"
}

// mode names how the sensor gets its work.
func (k *Kit) mode() string {
	switch {
	case k.s.commands && len(k.bcfg.Targets) > 0:
		return "Hybrid (scheduled + server-controlled)"
	case k.s.commands:
		return "Server-Controlled"
	default:
		return "Standalone"
	}
}

func (k *Kit) printBanner(doorbell bool) {
	out := k.out
	_, _ = fmt.Fprintf(out, "\n%s started\n", k.s.name)
	_, _ = fmt.Fprintln(out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	_, _ = fmt.Fprintf(out, "  Mode: %s\n", k.mode())
	_, _ = fmt.Fprintf(out, "  Targets: %v\n", k.bcfg.Targets)
	if k.bcfg.ScanInterval > 0 && len(k.bcfg.Targets) > 0 {
		_, _ = fmt.Fprintf(out, "  Scan interval: %s\n", k.bcfg.ScanInterval)
	}
	if doorbell {
		_, _ = fmt.Fprintf(out, "  Heartbeat: %s, or as the platform advises (doorbell on)\n", k.bcfg.HeartbeatInterval)
	} else {
		_, _ = fmt.Fprintf(out, "  Heartbeat: %s\n", k.bcfg.HeartbeatInterval)
	}
	if k.s.sensorID != "" {
		_, _ = fmt.Fprintf(out, "  Sensor ID: %s\n", k.s.sensorID)
	}
	if k.opts.Region != "" {
		_, _ = fmt.Fprintf(out, "  Region: %s\n", k.opts.Region)
	}
	_, _ = fmt.Fprintln(out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	_, _ = fmt.Fprintln(out, "\nPress Ctrl+C to stop.")
}

// aliasScanner exposes a scanner under the name it was configured with.
type aliasScanner struct {
	core.Scanner
	name string
}

func (a aliasScanner) Name() string { return a.name }

// SettingsSchema forwards the wrapped scanner's settings schema, so a scan
// dispatched under the configured name gets the same typed settings.
func (a aliasScanner) SettingsSchema() *core.SettingsSchema {
	if p, ok := a.Scanner.(core.SettingsSchemaProvider); ok {
		return p.SettingsSchema()
	}
	return nil
}

// commandRouter runs the handled command types with their executor and the
// rest with the SDK's.
type commandRouter struct {
	handlers map[string]core.CommandExecutor
	fallback core.CommandExecutor
}

func (r *commandRouter) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	if cmd != nil {
		if h, ok := r.handlers[cmd.Type]; ok {
			return h.Execute(ctx, cmd)
		}
	}
	return r.fallback.Execute(ctx, cmd)
}
