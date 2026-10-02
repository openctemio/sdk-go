package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/resource"
)

// The tool registry: a sensor registers the tools it runs when it starts,
// and the SDK tells the platform about them on every heartbeat (api RFC-029
// §4.3.1). Only the sensor knows what it has; the platform dispatches by
// this report, and its administrator can only narrow it. Nobody has to
// declare a sensor's tools on the platform.
//
//	s := core.NewBaseSensor(cfg, apiClient)
//	s.AddScanner(myScanner)               // registered: probed with IsInstalled
//	s.Tools().Register(core.ToolSpec{     // a tool the sensor runs some other way
//		Name: "zap", Version: "2.15.0", Capabilities: []string{"dast"},
//	})
//	s.Tools().AddCapabilities("validate") // served whatever the tools
//
// A BaseSensor reports its registry unless SetCapabilityReporter replaces
// it. A sensor that registers nothing reports nothing, and the platform then
// keeps using its administrator's settings.

// ToolKind says what a registered tool does.
type ToolKind string

const (
	// ToolKindScanner runs scans the platform dispatches (the default).
	ToolKindScanner ToolKind = "scanner"
	// ToolKindCollector pulls data from an external source.
	ToolKindCollector ToolKind = "collector"
)

// ToolProbe reports whether a tool is usable here and its version. It has
// the signature of Scanner.IsInstalled. An error counts as not installed.
type ToolProbe func(ctx context.Context) (installed bool, version string, err error)

// ToolSpec registers one tool.
type ToolSpec struct {
	// Name is the tool's catalog name ("nuclei", "semgrep"): lowercase
	// letters, digits, '.', '_' and '-', at most 64 characters (it is
	// lowercased and trimmed). The platform keeps only names in its tool
	// catalog.
	Name string
	// Kind defaults to ToolKindScanner.
	Kind ToolKind
	// Version is reported when the probe gives none (or there is no probe).
	Version string
	// Capabilities the tool serves when it is usable, besides its own name
	// (the platform dispatches a scan with the tool's name as the required
	// capability). Words the platform does not know are dropped there.
	Capabilities []string
	// Probe checks the tool; nil means it is always usable (an in-process
	// tool).
	Probe ToolProbe
	// Cost is an optional estimate of one job's cost, the prior of the
	// resource manager until it has learned the tool (see CostHints).
	Cost *resource.ToolCostHint
}

// Default probe settings.
const (
	// DefaultToolProbeTTL is how long a probe result is reused: probes run
	// a tool's version check, too slow for every heartbeat. A tool installed
	// while the sensor runs shows up within this time (or at Refresh).
	DefaultToolProbeTTL = 10 * time.Minute
	// DefaultToolProbeTimeout bounds one probe.
	DefaultToolProbeTimeout = 30 * time.Second

	maxToolNameLen = 64
)

// registryCapabilities are the platform's built-in capability names; a
// scanner's own descriptive words (Scanner.Capabilities) that are one of
// these are reported, the rest are not (the platform would drop them).
var registryCapabilities = map[string]bool{
	"ai_triage": true, "api": true, "cloud": true, "compliance": true, "container": true,
	"crawler": true, "dast": true, "dns": true, "docker": true, "http": true, "iac": true,
	"mobile": true, "pipeline": true, "portscan": true, "recon": true, "reporting": true,
	"sast": true, "sbom": true, "sca": true, "secrets": true, "security_analysis": true,
	"subdomain": true, "tech_detect": true, "terraform": true, "url_discovery": true,
	"web": true, "xss": true,
}

// capabilityAliases map scanners' own words to registry names.
var capabilityAliases = map[string]string{
	"secret_detection": "secrets",
	"secret":           "secrets",
}

// registryCapability maps a scanner's descriptive capability word to a
// registry name, or "" when the platform has none for it.
func registryCapability(word string) string {
	w := strings.ToLower(strings.TrimSpace(word))
	if a, ok := capabilityAliases[w]; ok {
		return a
	}
	if registryCapabilities[w] {
		return w
	}
	return ""
}

// normalizeToolName lowercases and checks a tool name.
func normalizeToolName(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || len(n) > maxToolNameLen {
		return "", false
	}
	for _, c := range n {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return "", false
		}
	}
	return n, true
}

// normalizeCapability lowercases and checks a capability name (tool-name
// characters plus ':'); "" when invalid.
func normalizeCapability(c string) string {
	n := strings.ToLower(strings.TrimSpace(c))
	if n == "" || len(n) > maxToolNameLen {
		return ""
	}
	for _, r := range n {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' && r != ':' {
			return ""
		}
	}
	return n
}

// appendUnique appends the valid, new capabilities of add to dst.
func appendUnique(dst []string, add ...string) []string {
	for _, c := range add {
		if c = normalizeCapability(c); c != "" && !slices.Contains(dst, c) {
			dst = append(dst, c)
		}
	}
	return dst
}

// registeredTool is a tool and its last probe.
type registeredTool struct {
	spec ToolSpec
	// probedAt is zero until the first probe (and after Refresh).
	probedAt  time.Time
	installed bool
	version   string
}

// ToolRegistry is the inventory a sensor reports: the tools it registered,
// how to check each one, the capabilities it serves and its concurrency. It
// implements CapabilityReporter. Safe for concurrent use.
type ToolRegistry struct {
	mu        sync.Mutex
	tools     []*registeredTool
	limit     []string // nil: no limit
	sensorCap []string
	maxJobs   int
	// everRegistered: once a tool was registered, an empty inventory is
	// reported as "none" rather than as "nothing reported".
	everRegistered bool

	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time
}

var _ CapabilityReporter = (*ToolRegistry)(nil)

// NewToolRegistry returns an empty registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{ttl: DefaultToolProbeTTL, timeout: DefaultToolProbeTimeout, now: time.Now}
}

// errNilTool is returned for a nil scanner or collector.
var errNilTool = errors.New("tool registry: nil tool")

// Register adds a tool. A second registration of the same name (another
// mode of one tool, such as trivy fs and trivy image) adds its capabilities
// to the first; the first registration's probe and version stay.
func (r *ToolRegistry) Register(spec ToolSpec) error {
	name, ok := normalizeToolName(spec.Name)
	if !ok {
		return fmt.Errorf("tool registry: invalid tool name %q (lowercase letters, digits, '.', '_', '-'; at most %d)", spec.Name, maxToolNameLen)
	}
	switch spec.Kind {
	case "":
		spec.Kind = ToolKindScanner
	case ToolKindScanner, ToolKindCollector:
	default:
		return fmt.Errorf("tool registry: unknown kind %q for %s", spec.Kind, name)
	}
	spec.Name = name
	spec.Capabilities = appendUnique(nil, spec.Capabilities...)
	if spec.Cost != nil {
		c := *spec.Cost
		spec.Cost = &c
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.everRegistered = true
	for _, t := range r.tools {
		if t.spec.Name == name {
			t.spec.Capabilities = appendUnique(t.spec.Capabilities, spec.Capabilities...)
			if t.spec.Cost == nil {
				t.spec.Cost = spec.Cost
			}
			return nil
		}
	}
	r.tools = append(r.tools, &registeredTool{spec: spec})
	return nil
}

// RegisterScanner registers a scanner: probed with its IsInstalled, serving
// the registry capabilities its Capabilities words map to (descriptive words
// the platform does not know are left out) plus extraCaps as given.
func (r *ToolRegistry) RegisterScanner(s Scanner, extraCaps ...string) error {
	if s == nil {
		return errNilTool
	}
	var caps []string
	for _, w := range s.Capabilities() {
		if c := registryCapability(w); c != "" {
			caps = append(caps, c)
		}
	}
	return r.Register(ToolSpec{
		Name:         s.Name(),
		Kind:         ToolKindScanner,
		Capabilities: append(caps, extraCaps...),
		Probe:        s.IsInstalled,
	})
}

// RegisterCollector registers a collector (always usable: it runs in
// process) serving caps.
func (r *ToolRegistry) RegisterCollector(c Collector, caps ...string) error {
	if c == nil {
		return errNilTool
	}
	return r.Register(ToolSpec{Name: c.Name(), Kind: ToolKindCollector, Capabilities: caps})
}

// Unregister removes a tool (no-op when absent).
func (r *ToolRegistry) Unregister(name string) {
	n, ok := normalizeToolName(name)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools = slices.DeleteFunc(r.tools, func(t *registeredTool) bool { return t.spec.Name == n })
}

// Limit narrows the report to the named tools: an operator allowlist (for
// example the SENSOR_TOOLS of a sensor image). Registered tools outside it
// are neither reported nor served. No names lifts the limit.
func (r *ToolRegistry) Limit(names ...string) {
	var limit []string
	for _, n := range names {
		if v, ok := normalizeToolName(n); ok && !slices.Contains(limit, v) {
			limit = append(limit, v)
		}
	}
	if len(limit) == 0 {
		limit = nil
	}
	r.mu.Lock()
	r.limit = limit
	r.mu.Unlock()
}

// Allowed reports whether the limit (if any) lets name through.
func (r *ToolRegistry) Allowed(name string) bool {
	n, ok := normalizeToolName(name)
	if !ok {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allowedLocked(n)
}

func (r *ToolRegistry) allowedLocked(name string) bool {
	return r.limit == nil || slices.Contains(r.limit, name)
}

// AddCapabilities adds capabilities the sensor serves whatever its tools
// ("validate" for a sensor that runs validation jobs).
func (r *ToolRegistry) AddCapabilities(caps ...string) {
	r.mu.Lock()
	r.sensorCap = appendUnique(r.sensorCap, caps...)
	r.mu.Unlock()
}

// SetMaxConcurrentJobs sets the operator ceiling the report carries (the
// most jobs the sensor may run at once, SENSOR_MAX_JOBS); 0 or less reports
// none. What the sensor can run now is its dynamic slot count, reported
// separately (SensorStatus.Capacity).
func (r *ToolRegistry) SetMaxConcurrentJobs(n int) {
	r.mu.Lock()
	r.maxJobs = max(n, 0)
	r.mu.Unlock()
}

// SetProbeTTL sets how long a probe result is reused (default
// DefaultToolProbeTTL); 0 probes on every report.
func (r *ToolRegistry) SetProbeTTL(d time.Duration) {
	r.mu.Lock()
	r.ttl = max(d, 0)
	r.mu.Unlock()
}

// SetProbeTimeout bounds one probe (default DefaultToolProbeTimeout).
func (r *ToolRegistry) SetProbeTimeout(d time.Duration) {
	if d <= 0 {
		d = DefaultToolProbeTimeout
	}
	r.mu.Lock()
	r.timeout = d
	r.mu.Unlock()
}

// Refresh makes the next report probe every tool again.
func (r *ToolRegistry) Refresh() {
	r.mu.Lock()
	for _, t := range r.tools {
		t.probedAt = time.Time{}
	}
	r.mu.Unlock()
}

// Len is the number of registered tools.
func (r *ToolRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tools)
}

// Names returns the registered tools allowed by the limit, in registration
// order (for resource.ManagerConfig.Tools).
func (r *ToolRegistry) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.tools))
	for _, t := range r.tools {
		if r.allowedLocked(t.spec.Name) {
			out = append(out, t.spec.Name)
		}
	}
	return out
}

// HasKind reports whether an allowed tool of kind k is registered.
func (r *ToolRegistry) HasKind(k ToolKind) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tools {
		if t.spec.Kind == k && r.allowedLocked(t.spec.Name) {
			return true
		}
	}
	return false
}

// CostHints returns the cost hints of the allowed tools that have one (for
// resource.ManagerConfig.CostHints).
func (r *ToolRegistry) CostHints() map[string]resource.ToolCostHint {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]resource.ToolCostHint{}
	for _, t := range r.tools {
		if t.spec.Cost != nil && r.allowedLocked(t.spec.Name) {
			out[t.spec.Name] = *t.spec.Cost
		}
	}
	return out
}

// Installed returns the inventory: every allowed tool, probed (results are
// reused for the probe TTL).
func (r *ToolRegistry) Installed(ctx context.Context) []ToolInfo {
	return r.CapabilityReport(ctx).Tools
}

// CapabilityReport implements CapabilityReporter: the allowed tools (probed,
// results reused for the probe TTL), the capabilities of the usable ones
// plus the sensor-wide ones, and the concurrency. The slices are the
// caller's.
func (r *ToolRegistry) CapabilityReport(ctx context.Context) CapabilityReport {
	// Probes run tools; they run under the lock so two heartbeats never
	// probe the same tool at once (heartbeats are sequential anyway).
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	rep := CapabilityReport{MaxConcurrentJobs: r.maxJobs}
	if r.everRegistered {
		rep.Tools = make([]ToolInfo, 0, len(r.tools))
	}
	var caps []string
	for _, t := range r.tools {
		if !r.allowedLocked(t.spec.Name) {
			continue
		}
		if t.probedAt.IsZero() || now.Sub(t.probedAt) >= r.ttl {
			t.installed, t.version = r.probeLocked(ctx, t.spec)
			t.probedAt = now
		}
		info := ToolInfo{Name: t.spec.Name, Kind: t.spec.Kind, Version: t.version, Installed: t.installed}
		if len(t.spec.Capabilities) > 0 {
			info.Capabilities = slices.Clone(t.spec.Capabilities)
		}
		rep.Tools = append(rep.Tools, info)
		if t.installed {
			caps = appendUnique(caps, t.spec.Name)
			caps = appendUnique(caps, t.spec.Capabilities...)
		}
	}
	caps = appendUnique(caps, r.sensorCap...)
	if caps != nil || rep.Tools != nil {
		rep.Capabilities = caps
		if rep.Capabilities == nil {
			rep.Capabilities = []string{}
		}
	}
	return rep
}

// probeLocked runs one tool's probe under the probe timeout.
func (r *ToolRegistry) probeLocked(ctx context.Context, spec ToolSpec) (bool, string) {
	if spec.Probe == nil {
		return true, spec.Version
	}
	pctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	installed, version, err := spec.Probe(pctx)
	if err != nil || !installed {
		return false, ""
	}
	if version == "" {
		version = spec.Version
	}
	return true, version
}
