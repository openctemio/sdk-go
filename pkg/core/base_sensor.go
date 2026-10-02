package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// =============================================================================
// BaseSensor - Base implementation for sensors
// =============================================================================

// BaseSensor provides a base implementation for sensors.
// Embed this in your custom sensor to get common functionality.
type BaseSensor struct {
	name     string
	version  string
	hostname string
	region   string

	// Components
	scanners   map[string]Scanner
	collectors map[string]Collector
	pusher     Pusher
	parsers    *ParserRegistry

	// Configuration
	scanInterval      time.Duration
	collectInterval   time.Duration
	heartbeatInterval time.Duration
	targets           []string

	// State
	status   *SensorStatus
	statusMu sync.RWMutex
	running  bool
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Verbose output
	verbose bool

	// doorbell, when set, makes the heartbeat announce the doorbell and act
	// on the platform's hints (see SetDoorbell).
	doorbell *Doorbell

	// authGate turns rejected heartbeats (401/403) into a capped backoff,
	// stops command polling while the key is rejected and logs connection
	// trouble without verbose mode (see AuthGate).
	authGate *AuthGate

	// firstHeartbeatNext is the delay FirstHeartbeat returned; the heartbeat
	// loop waits it instead of sending at once (guarded by statusMu).
	firstHeartbeatNext time.Duration
	firstHeartbeatSent bool

	// assetResolver names the asset a scheduled scan's findings belong to
	// (see SetAssetResolver).
	assetResolver AssetResolver

	// capReporter supplies the capability report on every heartbeat (see
	// SetCapabilityReporter); nil reports the tool registry.
	capReporter CapabilityReporter

	// tools is the sensor's tool registry: AddScanner and AddCollector
	// register into it, and it is the default capability report (see
	// Tools).
	tools *ToolRegistry

	// loadReporter supplies the active and maximum jobs on every heartbeat
	// (see SetLoadReporter).
	loadReporter LoadReporter

	// manifest is the registration state of the sensor manifest (api
	// RFC-033, manifest.go).
	manifest manifestState
}

// manifestState is what a BaseSensor knows about its registered manifest.
type manifestState struct {
	mu sync.Mutex
	// local is the digest of the manifest last registered, platform the
	// digest the platform returned for it (echoed on every heartbeat).
	local, platform string
	// requested: a heartbeat answer asked for the manifest again.
	requested bool
	// retryAt delays a registration after a failure.
	retryAt time.Time
}

// manifestRetryDelay is how long a failed registration waits; the heartbeat
// keeps reporting meanwhile.
const manifestRetryDelay = time.Minute

// syncManifest registers the sensor's manifest when the platform accepts
// one and it is new, changed or asked for, and puts the platform's digest on
// the heartbeat. It never fails the heartbeat: without a registration the
// platform derives the manifest from the heartbeat itself.
func (a *BaseSensor) syncManifest(ctx context.Context, status *SensorStatus) {
	mp, ok := a.pusher.(ManifestPusher)
	if !ok || status == nil || status.Tools == nil {
		return
	}
	model := ""
	switch {
	case status.Capacity != nil:
		model = ConcurrencyModelDynamic
	case status.MaxConcurrentJobs > 0:
		model = ConcurrencyModelFixed
	}
	m := BuildManifest(status, status.Resources, model)
	local, err := m.Digest()
	if err != nil {
		return
	}

	st := &a.manifest
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	if local == st.local && !st.requested {
		status.ManifestDigest = st.platform
		return
	}
	if now.Before(st.retryAt) {
		// Changed but backing off: the old digest would be asked for again
		// and the platform derives meanwhile, so send none.
		return
	}
	ack, err := mp.PutManifest(ctx, &m)
	switch {
	case errors.Is(err, ErrManifestUnsupported):
		st.local, st.platform, st.requested = "", "", false
		return
	case err != nil:
		st.retryAt = now.Add(manifestRetryDelay)
		if a.verbose {
			fmt.Printf("[%s] Manifest not registered (retry in %s): %v\n", a.name, manifestRetryDelay, err)
		}
		return
	}
	st.local, st.platform, st.requested, st.retryAt = local, ack.Digest, false, time.Time{}
	status.ManifestDigest = ack.Digest
	if a.verbose || len(ack.Ignored) > 0 {
		fmt.Printf("[%s] Manifest registered: %s (%d tools accepted, %d items ignored)\n",
			a.name, shortDigest(ack.Digest), len(ack.AcceptedTools), len(ack.Ignored))
		for _, i := range ack.Ignored {
			fmt.Printf("[%s]   ignored %s %q: %s\n", a.name, i.Path, i.Value, i.Reason)
		}
	}
}

// manifestAsked notes a heartbeat answer that asks for the manifest.
func (a *BaseSensor) manifestAsked(hints *HeartbeatHints) {
	if hints == nil || !slices.Contains(hints.Actions, HeartbeatActionSendManifest) {
		return
	}
	a.manifest.mu.Lock()
	a.manifest.requested = true
	a.manifest.mu.Unlock()
}

func shortDigest(d string) string {
	if len(d) > len("sha256:")+12 {
		return d[:len("sha256:")+12]
	}
	return d
}

// SetLoadReporter makes every heartbeat carry r's load: the commands the
// sensor runs now (active_jobs, sent even when 0), its dynamic slots when r
// is a StatusReporter with a resource manager (capacity), and otherwise,
// when the capability report does not already say it, its fixed
// concurrency (max_concurrent_jobs). Pass the sensor's *CommandPoller. Call
// before Start.
func (a *BaseSensor) SetLoadReporter(r LoadReporter) {
	a.statusMu.Lock()
	a.loadReporter = r
	a.statusMu.Unlock()
}

// SetCapabilityReporter makes every heartbeat carry r's report instead of
// the tool registry's (see Tools): the tools the sensor actually has, the
// capabilities it serves and its concurrency. The platform dispatches by it
// (an administrator can only narrow it). nil goes back to the registry. A
// reporter that returns an empty CapabilityReport reports nothing, and the
// platform keeps using its administrator's settings. Call before Start.
func (a *BaseSensor) SetCapabilityReporter(r CapabilityReporter) {
	a.statusMu.Lock()
	a.capReporter = r
	a.statusMu.Unlock()
}

// Tools returns the sensor's tool registry. Every heartbeat reports it
// (unless SetCapabilityReporter replaced it): the scanners and collectors
// added with AddScanner and AddCollector are in it already; register any
// other tool the sensor runs (an executor's scanners:
// DefaultCommandExecutor.SetToolRegistry), the capabilities it serves
// whatever the tools (AddCapabilities) and its cap (SetMaxConcurrentJobs).
// The platform needs no list of a sensor's tools: it learns them here.
func (a *BaseSensor) Tools() *ToolRegistry {
	return a.tools
}

// withCapabilities applies the reporter's report to a heartbeat status.
func (a *BaseSensor) withCapabilities(ctx context.Context, status *SensorStatus) *SensorStatus {
	a.statusMu.RLock()
	r := a.capReporter
	lr := a.loadReporter
	a.statusMu.RUnlock()
	if r == nil && a.tools != nil {
		r = a.tools
	}
	if r != nil && status != nil {
		r.CapabilityReport(ctx).Apply(status)
	}
	if lr != nil && status != nil {
		status.ActiveJobs = lr.ActiveJobs()
		status.ActiveJobsReported = true
		if sr, ok := lr.(StatusReporter); ok {
			sr.ReportStatus(status)
		}
		// max_concurrent_jobs is the operator's ceiling. A load reporter
		// that reports dynamic slots (Capacity) sizes them itself; its
		// MaxJobs is then only the resource manager's upper bound (64 when
		// the operator set no cap), not a capacity, and reporting it made
		// the platform hand a 4-core sensor more jobs than it runs. Without
		// slots, MaxJobs is the fixed concurrency and stays the report.
		if status.MaxConcurrentJobs == 0 && status.Capacity == nil {
			status.MaxConcurrentJobs = lr.MaxJobs()
		}
	}
	return status
}

// BaseSensorConfig configures a BaseSensor.
type BaseSensorConfig struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
	// ProductName, Commit and BuildTime describe the sensor binary on every
	// heartbeat ("sensor"); all optional. ProductName defaults to the name
	// given to useragent.SetProduct, then to the executable's name;
	// BuildTime is RFC 3339.
	ProductName       string        `yaml:"product_name" json:"product_name"`
	Commit            string        `yaml:"commit" json:"commit"`
	BuildTime         string        `yaml:"build_time" json:"build_time"`
	Region            string        `yaml:"region" json:"region"` // Deployment region (e.g., "us-east-1", "ap-southeast-1")
	ScanInterval      time.Duration `yaml:"scan_interval" json:"scan_interval"`
	CollectInterval   time.Duration `yaml:"collect_interval" json:"collect_interval"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval" json:"heartbeat_interval"`
	Targets           []string      `yaml:"targets" json:"targets"`
	Verbose           bool          `yaml:"verbose" json:"verbose"`
}

// detectRegion detects the deployment region from config or environment variables.
// Priority: config > REGION > AWS_REGION > GOOGLE_CLOUD_REGION > AZURE_REGION
func detectRegion(configRegion string) string {
	if configRegion != "" {
		return configRegion
	}

	// Check environment variables in priority order
	// REGION is the recommended generic variable
	// Cloud-specific variables are auto-detected for convenience
	envVars := []string{
		"REGION",
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
		"GOOGLE_CLOUD_REGION",
		"AZURE_REGION",
	}

	for _, env := range envVars {
		if val := os.Getenv(env); val != "" {
			return val
		}
	}

	return ""
}

// NewBaseSensor creates a new base sensor.
func NewBaseSensor(cfg *BaseSensorConfig, pusher Pusher) *BaseSensor {
	hostname, _ := os.Hostname()
	region := detectRegion(cfg.Region)

	// Set defaults
	if cfg.ScanInterval == 0 {
		cfg.ScanInterval = 1 * time.Hour
	}
	if cfg.CollectInterval == 0 {
		cfg.CollectInterval = 15 * time.Minute
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 1 * time.Minute
	}

	return &BaseSensor{
		name:              cfg.Name,
		version:           cfg.Version,
		hostname:          hostname,
		region:            region,
		scanners:          make(map[string]Scanner),
		collectors:        make(map[string]Collector),
		pusher:            pusher,
		parsers:           NewParserRegistry(),
		scanInterval:      cfg.ScanInterval,
		collectInterval:   cfg.CollectInterval,
		heartbeatInterval: cfg.HeartbeatInterval,
		targets:           cfg.Targets,
		status: &SensorStatus{
			Name:       cfg.Name,
			Status:     SensorStateStopped,
			Scanners:   []string{},
			Collectors: []string{},
			Region:     region,
			Version:    cfg.Version,
			Hostname:   hostname,
			OS:         HostOS(),
			Arch:       HostArch(),
			SDK:        sdkInfoPtr(),
			Sensor:     sensorBuildPtr(cfg),
		},
		stopCh:   make(chan struct{}),
		verbose:  cfg.Verbose,
		authGate: NewAuthGate(nil),
		tools:    NewToolRegistry(),
	}
}

// Name returns the sensor name.
func (a *BaseSensor) Name() string {
	return a.name
}

// AddScanner adds a scanner to the sensor.
func (a *BaseSensor) AddScanner(scanner Scanner) error {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()

	name := scanner.Name()
	if _, exists := a.scanners[name]; exists {
		return fmt.Errorf("scanner %s already exists", name)
	}

	a.scanners[name] = scanner
	a.status.Scanners = append(a.status.Scanners, name)
	if err := a.tools.RegisterScanner(scanner); err != nil && a.verbose {
		fmt.Printf("[%s] Scanner %s is not reported to the platform: %v\n", a.name, name, err)
	}

	if a.verbose {
		fmt.Printf("[%s] Added scanner: %s\n", a.name, name)
	}

	return nil
}

// AddCollector adds a collector to the sensor.
func (a *BaseSensor) AddCollector(collector Collector) error {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()

	name := collector.Name()
	if _, exists := a.collectors[name]; exists {
		return fmt.Errorf("collector %s already exists", name)
	}

	a.collectors[name] = collector
	a.status.Collectors = append(a.status.Collectors, name)
	if err := a.tools.RegisterCollector(collector); err != nil && a.verbose {
		fmt.Printf("[%s] Collector %s is not reported to the platform: %v\n", a.name, name, err)
	}

	if a.verbose {
		fmt.Printf("[%s] Added collector: %s\n", a.name, name)
	}

	return nil
}

// RemoveScanner removes a scanner from the sensor.
func (a *BaseSensor) RemoveScanner(name string) error {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()

	if _, exists := a.scanners[name]; !exists {
		return fmt.Errorf("scanner %s not found", name)
	}

	delete(a.scanners, name)
	a.tools.Unregister(name)

	// Update status
	newScanners := make([]string, 0)
	for _, s := range a.status.Scanners {
		if s != name {
			newScanners = append(newScanners, s)
		}
	}
	a.status.Scanners = newScanners

	return nil
}

// RemoveCollector removes a collector from the sensor.
func (a *BaseSensor) RemoveCollector(name string) error {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()

	if _, exists := a.collectors[name]; !exists {
		return fmt.Errorf("collector %s not found", name)
	}

	delete(a.collectors, name)
	a.tools.Unregister(name)

	// Update status
	newCollectors := make([]string, 0)
	for _, c := range a.status.Collectors {
		if c != name {
			newCollectors = append(newCollectors, c)
		}
	}
	a.status.Collectors = newCollectors

	return nil
}

// Status returns the current sensor status.
func (a *BaseSensor) Status() *SensorStatus {
	a.statusMu.RLock()
	defer a.statusMu.RUnlock()

	// Return a copy with calculated uptime
	status := *a.status
	if status.StartedAt > 0 {
		status.Uptime = time.Now().Unix() - status.StartedAt
	}
	return &status
}

// Start starts the sensor.
func (a *BaseSensor) Start(ctx context.Context) error {
	a.statusMu.Lock()
	if a.running {
		a.statusMu.Unlock()
		return fmt.Errorf("sensor already running")
	}
	a.running = true
	// The provided edit contained HTTP-related code that is syntactically incorrect
	// in this context and appears to be a copy-paste error.
	// Reverting to original logic for sensor status and start time.
	a.status.Status = SensorStateRunning
	a.status.StartedAt = time.Now().Unix()
	a.stopCh = make(chan struct{})
	a.statusMu.Unlock()

	if a.verbose {
		fmt.Printf("[%s] Starting sensor (version %s)\n", a.name, a.version)
		fmt.Printf("[%s] Scanners: %v\n", a.name, a.status.Scanners)
		fmt.Printf("[%s] Collectors: %v\n", a.name, a.status.Collectors)
		fmt.Printf("[%s] Targets: %v\n", a.name, a.targets)
	}

	// Start heartbeat loop
	a.wg.Add(1)
	go a.heartbeatLoop(ctx)

	// Start scan loop
	if len(a.scanners) > 0 && len(a.targets) > 0 {
		a.wg.Add(1)
		go a.scanLoop(ctx)
	}

	// Start collect loop
	if len(a.collectors) > 0 {
		a.wg.Add(1)
		go a.collectLoop(ctx)
	}

	return nil
}

// Stop stops the sensor gracefully.
func (a *BaseSensor) Stop(ctx context.Context) error {
	a.statusMu.Lock()
	if !a.running {
		a.statusMu.Unlock()
		return nil
	}
	a.running = false
	a.status.Status = SensorStateStopping
	close(a.stopCh)
	a.statusMu.Unlock()

	if a.verbose {
		fmt.Printf("[%s] Stopping sensor...\n", a.name)
	}

	// Wait for goroutines to finish
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-ctx.Done():
		return ctx.Err()
	}

	// Send final heartbeat
	a.statusMu.Lock()
	a.status.Status = SensorStateStopped
	a.statusMu.Unlock()

	// A final heartbeat with a rejected key would only be another 401.
	if a.pusher != nil && !a.authGate.Rejected() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := a.pusher.SendHeartbeat(ctx2, a.withCapabilities(ctx2, a.Status())); err != nil {
			if a.verbose {
				fmt.Printf("[%s] Final heartbeat error: %v\n", a.name, err)
			}
		}
		cancel()
	}

	if a.verbose {
		fmt.Printf("[%s] Sensor stopped\n", a.name)
	}

	return nil
}

// SetDoorbell makes the sensor act on the heartbeat doorbell: heartbeats
// announce the feature, their hints go to d, the advised interval replaces
// the configured one, and scheduled scans and collections are skipped while
// the platform has paused or drained the sensor. Share d with the
// CommandPoller (CommandPoller.SetDoorbell) so it polls when the doorbell
// rings. The pusher must implement DoorbellPusher (*client.Client does);
// otherwise heartbeats stay plain. Call before Start.
func (a *BaseSensor) SetDoorbell(d *Doorbell) {
	a.doorbell = d
	if d != nil {
		// A poller that shares this doorbell also stops polling while the
		// platform rejects the key (CommandPoller.SetDoorbell).
		d.setAuthGate(a.authGate)
	}
}

// AuthGate returns the gate that tracks whether the platform accepts this
// sensor's heartbeats. Share it with a CommandPoller (SetAuthGate) so the
// poller stops polling while the key is rejected; a poller sharing the
// sensor's doorbell gets it automatically.
func (a *BaseSensor) AuthGate() *AuthGate {
	return a.authGate
}

// SetAuthGate replaces the sensor's AuthGate (nil is ignored). Call before
// Start.
func (a *BaseSensor) SetAuthGate(g *AuthGate) {
	if g == nil {
		return
	}
	a.authGate = g
	if a.doorbell != nil {
		a.doorbell.setAuthGate(g)
	}
}

// keyHint names the pusher's API key for log lines without revealing it.
func (a *BaseSensor) keyHint() string {
	if h, ok := a.pusher.(APIKeyHinter); ok {
		return h.APIKeyHint()
	}
	return "(unknown)"
}

// afterHeartbeat reports a heartbeat outcome to the auth gate and returns the
// delay before the next heartbeat: the gate's backoff while the key is
// rejected, otherwise next.
func (a *BaseSensor) afterHeartbeat(err error, next time.Duration) time.Duration {
	if backoff := a.authGate.Observe(err, a.keyHint()); backoff > 0 {
		return backoff
	}
	return next
}

// sendHeartbeat sends one heartbeat and returns the delay before the next.
func (a *BaseSensor) sendHeartbeat(ctx context.Context) time.Duration {
	next, _ := a.heartbeatOnce(ctx, a.Status())
	return next
}

// FirstHeartbeat sends the sensor's first heartbeat now, before Start, and
// returns the delay before the next one and the heartbeat's error. It is the
// daemon's connection check: it goes through the doorbell and the AuthGate
// exactly like the heartbeat loop, so a rejected key is logged and backed off
// the same way (AuthFailureStatus(err) != 0; wait the returned delay before
// trying again). The next Start does not send another heartbeat at once: its
// first one follows the returned delay. Without this, a daemon that checked
// the connection with Pusher.TestConnection sent two heartbeats back to back.
func (a *BaseSensor) FirstHeartbeat(ctx context.Context) (time.Duration, error) {
	status := a.Status()
	if status.Status == SensorStateStopped {
		// About to start; "stopped" would mislead the platform.
		status.Status = SensorStateRunning
	}
	next, err := a.heartbeatOnce(ctx, status)
	a.statusMu.Lock()
	a.firstHeartbeatNext = next
	a.firstHeartbeatSent = true
	a.statusMu.Unlock()
	return next, err
}

// heartbeatOnce sends one heartbeat and returns the delay before the next and
// the heartbeat's error.
func (a *BaseSensor) heartbeatOnce(ctx context.Context, status *SensorStatus) (time.Duration, error) {
	next := a.heartbeatInterval
	if a.pusher == nil {
		return next, nil
	}
	status = a.withCapabilities(ctx, status)
	a.syncManifest(ctx, status)
	dp, doorbell := a.pusher.(DoorbellPusher)
	if a.doorbell == nil || !doorbell {
		err := a.pusher.SendHeartbeat(ctx, status)
		if err != nil {
			if a.verbose {
				fmt.Printf("[%s] Heartbeat error: %v\n", a.name, err)
			}
		} else if a.verbose {
			fmt.Printf("[%s] Heartbeat sent\n", a.name)
		}
		return a.afterHeartbeat(err, next), err
	}

	if state := a.doorbell.State(); state != "running" {
		status.Message = state
	}
	hints, err := dp.SendHeartbeatWithHints(ctx, status)
	if err != nil {
		if AuthFailureStatus(err) != 0 {
			// The auth gate logs this and stops polling; the doorbell's
			// "fixed-interval polling" fallback does not apply.
			a.doorbell.heartbeatRejected()
		} else {
			a.doorbell.HeartbeatFailed()
		}
		if a.verbose {
			fmt.Printf("[%s] Heartbeat error: %v\n", a.name, err)
		}
		return a.afterHeartbeat(err, next), err
	}
	a.doorbell.Handle(hints)
	a.manifestAsked(hints)
	if hints.NextHeartbeat > 0 {
		next = hints.NextHeartbeat
	}
	return a.afterHeartbeat(nil, next), nil
}

// paused reports whether the platform paused or drained this sensor.
func (a *BaseSensor) paused() bool {
	return a.doorbell != nil && a.doorbell.Paused()
}

// heartbeatLoop sends heartbeats: every heartbeatInterval, or as often as the
// platform advises when a doorbell is set.
func (a *BaseSensor) heartbeatLoop(ctx context.Context) {
	defer a.wg.Done()

	// Send the initial heartbeat, unless FirstHeartbeat just did.
	a.statusMu.Lock()
	first, sent := a.firstHeartbeatNext, a.firstHeartbeatSent
	a.firstHeartbeatSent = false
	a.statusMu.Unlock()
	if !sent {
		first = a.sendHeartbeat(ctx)
	}
	timer := time.NewTimer(first)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-timer.C:
			timer.Reset(a.sendHeartbeat(ctx))
		}
	}
}

// scanLoop performs periodic scans.
func (a *BaseSensor) scanLoop(ctx context.Context) {
	defer a.wg.Done()

	// Run initial scan
	a.runAllScans(ctx)

	ticker := time.NewTicker(a.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.runAllScans(ctx)
		}
	}
}

// collectLoop performs periodic collections.
func (a *BaseSensor) collectLoop(ctx context.Context) {
	defer a.wg.Done()

	// Run initial collection
	a.runAllCollections(ctx)

	ticker := time.NewTicker(a.collectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.runAllCollections(ctx)
		}
	}
}

// runAllScans runs all scanners on all targets.
func (a *BaseSensor) runAllScans(ctx context.Context) {
	if a.paused() {
		if a.verbose {
			fmt.Printf("[%s] Skipping scheduled scans: %s\n", a.name, a.doorbell.State())
		}
		return
	}
	a.statusMu.RLock()
	scanners := make(map[string]Scanner)
	for k, v := range a.scanners {
		scanners[k] = v
	}
	targets := make([]string, len(a.targets))
	copy(targets, a.targets)
	a.statusMu.RUnlock()

	for _, target := range targets {
		for name, scanner := range scanners {
			if a.paused() {
				return // paused mid-run: start nothing more
			}
			if a.verbose {
				fmt.Printf("[%s] Running scanner %s on %s\n", a.name, name, target)
			}

			// Run scan
			result, err := scanner.Scan(ctx, target, &ScanOptions{
				TargetDir: target,
				Verbose:   a.verbose,
			})

			if err != nil {
				a.incrementErrors()
				if a.verbose {
					fmt.Printf("[%s] Scan error: %v\n", a.name, err)
				}
				continue
			}

			// Parse result
			report, err := a.parseResult(ctx, scanner, target, result)
			if err != nil {
				a.incrementErrors()
				if a.verbose {
					fmt.Printf("[%s] Parse error: %v\n", a.name, err)
				}
				continue
			}

			// Push findings
			if a.pusher != nil && len(report.Findings) > 0 {
				pushResult, err := a.pusher.PushFindings(ctx, report)
				if err != nil {
					a.incrementErrors()
					if a.verbose {
						fmt.Printf("[%s] Push error: %v\n", a.name, err)
					}
				} else {
					a.recordScan(int64(len(report.Findings)))
					if a.verbose {
						if pushResult != nil && pushResult.Queued {
							fmt.Printf("[%s] Queued %d findings in the outbox (report %s); delivered when the platform accepts them\n",
								a.name, len(report.Findings), pushResult.ReportID)
						} else {
							fmt.Printf("[%s] Pushed %d findings (%d created, %d updated)\n",
								a.name, len(report.Findings),
								pushResult.FindingsCreated, pushResult.FindingsUpdated)
						}
					}
				}
			}
		}
	}
}

// runAllCollections runs all collectors.
func (a *BaseSensor) runAllCollections(ctx context.Context) {
	if a.paused() {
		if a.verbose {
			fmt.Printf("[%s] Skipping scheduled collections: %s\n", a.name, a.doorbell.State())
		}
		return
	}
	a.statusMu.RLock()
	collectors := make(map[string]Collector)
	for k, v := range a.collectors {
		collectors[k] = v
	}
	a.statusMu.RUnlock()

	for name, collector := range collectors {
		if a.verbose {
			fmt.Printf("[%s] Running collector %s\n", a.name, name)
		}

		result, err := collector.Collect(ctx, &CollectOptions{})
		if err != nil {
			a.incrementErrors()
			if a.verbose {
				fmt.Printf("[%s] Collect error: %v\n", a.name, err)
			}
			continue
		}

		// Push all collected reports
		for _, report := range result.Reports {
			if a.pusher != nil && len(report.Findings) > 0 {
				pushResult, err := a.pusher.PushFindings(ctx, report)
				if err != nil {
					a.incrementErrors()
					if a.verbose {
						fmt.Printf("[%s] Push error: %v\n", a.name, err)
					}
				} else {
					a.recordCollect(int64(len(report.Findings)))
					if a.verbose {
						fmt.Printf("[%s] Pushed %d findings from %s\n",
							a.name, len(report.Findings), name)
						_ = pushResult // silence unused
					}
				}
			}
		}
	}
}

// parseResult parses scanner output to CTIS format.
func (a *BaseSensor) parseResult(ctx context.Context, scanner Scanner, target string, result *ScanResult) (*ctis.Report, error) {
	// Try to find a parser that can handle this output
	parser := a.parsers.FindParser(result.RawOutput)
	if parser == nil {
		// Default to SARIF parser
		parser = a.parsers.Get("sarif")
	}

	if parser == nil {
		return nil, fmt.Errorf("no suitable parser found for scanner %s", scanner.Name())
	}

	opts := &ParseOptions{ToolName: scanner.Name()}
	if filepath.IsAbs(target) {
		// Filesystem scan: repo-relative paths, as the command executor does.
		opts.BasePath = target
	}
	a.statusMu.RLock()
	resolve := a.assetResolver
	a.statusMu.RUnlock()
	if resolve != nil && target != "" {
		opts.AssetType, opts.AssetValue = resolve(scanner.Name(), target)
	}
	return parser.Parse(ctx, result.RawOutput, opts)
}

// SetAssetResolver names the asset a scheduled scan's findings are filed on
// (for example the repository a directory belongs to). Without it a parser
// may emit findings without an asset, which protocol v2 rejects (RFC-026).
func (a *BaseSensor) SetAssetResolver(r AssetResolver) {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	a.assetResolver = r
}

// recordScan updates scan statistics.
func (a *BaseSensor) recordScan(findings int64) {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	a.status.TotalScans++
	a.status.TotalFindings += findings
	a.status.LastScan = time.Now().Unix()
}

// recordCollect updates collect statistics.
func (a *BaseSensor) recordCollect(findings int64) {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	a.status.TotalFindings += findings
	a.status.LastCollect = time.Now().Unix()
}

// incrementErrors increments the error counter.
func (a *BaseSensor) incrementErrors() {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	a.status.Errors++
}

// SetVerbose sets verbose mode.
func (a *BaseSensor) SetVerbose(v bool) {
	a.verbose = v
}

// AddParser adds a custom parser to the sensor.
func (a *BaseSensor) AddParser(parser Parser) {
	a.parsers.Register(parser)
}

func sdkInfoPtr() *SDKInfo {
	i := CurrentSDKInfo()
	return &i
}

func sensorBuildPtr(cfg *BaseSensorConfig) *SensorBuild {
	b := NewSensorBuild(cfg.ProductName, cfg.Version, cfg.Commit, cfg.BuildTime)
	return &b
}
