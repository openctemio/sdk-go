package core

import (
	"context"
	"fmt"
	"os"
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
}

// BaseSensorConfig configures a BaseSensor.
type BaseSensorConfig struct {
	Name              string        `yaml:"name" json:"name"`
	Version           string        `yaml:"version" json:"version"`
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
		},
		stopCh:  make(chan struct{}),
		verbose: cfg.Verbose,
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

	if a.pusher != nil {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := a.pusher.SendHeartbeat(ctx2, a.Status()); err != nil {
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
}

// sendHeartbeat sends one heartbeat and returns the delay before the next.
func (a *BaseSensor) sendHeartbeat(ctx context.Context) time.Duration {
	next := a.heartbeatInterval
	if a.pusher == nil {
		return next
	}
	status := a.Status()
	dp, doorbell := a.pusher.(DoorbellPusher)
	if a.doorbell == nil || !doorbell {
		if err := a.pusher.SendHeartbeat(ctx, status); err != nil {
			if a.verbose {
				fmt.Printf("[%s] Heartbeat error: %v\n", a.name, err)
			}
		} else if a.verbose {
			fmt.Printf("[%s] Heartbeat sent\n", a.name)
		}
		return next
	}

	if state := a.doorbell.State(); state != "running" {
		status.Message = state
	}
	hints, err := dp.SendHeartbeatWithHints(ctx, status)
	if err != nil {
		a.doorbell.HeartbeatFailed()
		if a.verbose {
			fmt.Printf("[%s] Heartbeat error: %v\n", a.name, err)
		}
		return next
	}
	a.doorbell.Handle(hints)
	if hints.NextHeartbeat > 0 {
		next = hints.NextHeartbeat
	}
	return next
}

// paused reports whether the platform paused or drained this sensor.
func (a *BaseSensor) paused() bool {
	return a.doorbell != nil && a.doorbell.Paused()
}

// heartbeatLoop sends heartbeats: every heartbeatInterval, or as often as the
// platform advises when a doorbell is set.
func (a *BaseSensor) heartbeatLoop(ctx context.Context) {
	defer a.wg.Done()

	// Send initial heartbeat
	timer := time.NewTimer(a.sendHeartbeat(ctx))
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
			report, err := a.parseResult(ctx, scanner, result)
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
						fmt.Printf("[%s] Pushed %d findings (%d created, %d updated)\n",
							a.name, len(report.Findings),
							pushResult.FindingsCreated, pushResult.FindingsUpdated)
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
func (a *BaseSensor) parseResult(ctx context.Context, scanner Scanner, result *ScanResult) (*ctis.Report, error) {
	// Try to find a parser that can handle this output
	parser := a.parsers.FindParser(result.RawOutput)
	if parser == nil {
		// Default to SARIF parser
		parser = a.parsers.Get("sarif")
	}

	if parser == nil {
		return nil, fmt.Errorf("no suitable parser found for scanner %s", scanner.Name())
	}

	return parser.Parse(ctx, result.RawOutput, &ParseOptions{
		ToolName: scanner.Name(),
	})
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
