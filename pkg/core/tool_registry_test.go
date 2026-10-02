package core

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/resource"
)

// registryScanner is a Scanner whose IsInstalled answer the test controls
// and counts.
type registryScanner struct {
	name      string
	caps      []string
	installed bool
	version   string
	err       error
	calls     atomic.Int32
}

func (s *registryScanner) Name() string           { return s.name }
func (s *registryScanner) Version() string        { return "static-" + s.name }
func (s *registryScanner) Capabilities() []string { return s.caps }
func (s *registryScanner) Scan(context.Context, string, *ScanOptions) (*ScanResult, error) {
	return &ScanResult{}, nil
}
func (s *registryScanner) IsInstalled(context.Context) (bool, string, error) {
	s.calls.Add(1)
	return s.installed, s.version, s.err
}

type registryCollector struct{ name string }

func (c *registryCollector) Name() string { return c.name }
func (c *registryCollector) Type() string { return "api" }
func (c *registryCollector) Collect(context.Context, *CollectOptions) (*CollectResult, error) {
	return &CollectResult{}, nil
}
func (c *registryCollector) TestConnection(context.Context) error { return nil }

func toolNames(tools []ToolInfo) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name)
	}
	return out
}

func TestToolRegistryEmptyReportsNothing(t *testing.T) {
	r := NewToolRegistry()
	rep := r.CapabilityReport(context.Background())
	if rep.Tools != nil || rep.Capabilities != nil || rep.MaxConcurrentJobs != 0 {
		t.Fatalf("an empty registry must report nothing (the platform keeps its settings): %+v", rep)
	}
	if r.Len() != 0 || len(r.Names()) != 0 {
		t.Fatalf("empty registry: len %d names %v", r.Len(), r.Names())
	}
}

func TestToolRegistryRegisterScanner(t *testing.T) {
	r := NewToolRegistry()
	semgrep := &registryScanner{name: "semgrep", caps: []string{"sast", "taint_tracking", "code_quality"}, installed: true, version: "1.90.0"}
	leaks := &registryScanner{name: "betterleaks", caps: []string{"secret_detection", "api_key_detection"}, installed: true, version: "1.1.0"}
	nuclei := &registryScanner{name: "nuclei", caps: []string{"dast"}, installed: false, version: "3.0.0"}
	broken := &registryScanner{name: "trivy", caps: []string{"sca"}, installed: true, version: "0.69.3", err: errors.New("exit 1")}
	for _, s := range []*registryScanner{semgrep, leaks, nuclei, broken} {
		if err := r.RegisterScanner(s); err != nil {
			t.Fatalf("register %s: %v", s.name, err)
		}
	}

	rep := r.CapabilityReport(context.Background())
	want := []ToolInfo{
		{Name: "semgrep", Kind: ToolKindScanner, Version: "1.90.0", Installed: true},
		{Name: "betterleaks", Kind: ToolKindScanner, Version: "1.1.0", Installed: true},
		// Not installed, or its check failed: reported, but not installed and
		// without a version.
		{Name: "nuclei", Kind: ToolKindScanner, Installed: false},
		{Name: "trivy", Kind: ToolKindScanner, Installed: false},
	}
	if !slices.EqualFunc(rep.Tools, want, func(a, b ToolInfo) bool {
		return a.Name == b.Name && a.Kind == b.Kind && a.Version == b.Version && a.Installed == b.Installed
	}) {
		t.Fatalf("tools = %+v, want %+v", rep.Tools, want)
	}
	// Each installed tool serves its name and the registry capabilities its
	// own words map to; descriptive words the platform does not know are
	// dropped; tools that are not usable serve nothing.
	wantCaps := []string{"semgrep", "sast", "betterleaks", "secrets"}
	if !slices.Equal(rep.Capabilities, wantCaps) {
		t.Fatalf("capabilities = %v, want %v", rep.Capabilities, wantCaps)
	}
	if !slices.Equal(r.Names(), []string{"semgrep", "betterleaks", "nuclei", "trivy"}) {
		t.Fatalf("names = %v", r.Names())
	}
}

func TestToolRegistryExplicitSpec(t *testing.T) {
	r := NewToolRegistry()
	// A custom tool: explicit capabilities are the author's and pass through
	// (normalized), an in-process tool without a probe is installed, and the
	// static version is reported.
	if err := r.Register(ToolSpec{Name: "  MyScanner ", Version: "2.0", Capabilities: []string{"SAST", "custom:thing", "sast"}}); err != nil {
		t.Fatal(err)
	}
	// A probe that reports no version keeps the static one.
	if err := r.Register(ToolSpec{Name: "zap", Version: "2.15", Kind: ToolKindScanner,
		Probe: func(context.Context) (bool, string, error) { return true, "", nil }}); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(context.Background())
	if len(rep.Tools) != 2 || rep.Tools[0].Name != "myscanner" || rep.Tools[0].Version != "2.0" || !rep.Tools[0].Installed || rep.Tools[0].Kind != ToolKindScanner {
		t.Fatalf("tools = %+v", rep.Tools)
	}
	if rep.Tools[1].Version != "2.15" {
		t.Fatalf("static version not kept: %+v", rep.Tools[1])
	}
	if want := []string{"myscanner", "sast", "custom:thing", "zap"}; !slices.Equal(rep.Capabilities, want) {
		t.Fatalf("capabilities = %v, want %v", rep.Capabilities, want)
	}
}

func TestToolRegistryRejectsInvalidNames(t *testing.T) {
	r := NewToolRegistry()
	for _, name := range []string{"", "   ", "has space", "a/b", "semi;colon", strings.Repeat("a", 65)} {
		if err := r.Register(ToolSpec{Name: name}); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if err := r.Register(ToolSpec{Name: "ok", Kind: "robot"}); err == nil {
		t.Error("unknown kind accepted")
	}
	if err := r.RegisterScanner(nil); err == nil {
		t.Error("nil scanner accepted")
	}
	if err := r.RegisterCollector(nil); err == nil {
		t.Error("nil collector accepted")
	}
	// Invalid capability words are dropped, not fatal.
	if err := r.Register(ToolSpec{Name: "x", Capabilities: []string{"bad word", "ok"}}); err != nil {
		t.Fatal(err)
	}
	if rep := r.CapabilityReport(context.Background()); !slices.Equal(rep.Capabilities, []string{"x", "ok"}) {
		t.Fatalf("capabilities = %v", rep.Capabilities)
	}
	if r.Len() != 1 {
		t.Fatalf("len = %d", r.Len())
	}
}

func TestToolRegistryMergesModesOfOneTool(t *testing.T) {
	r := NewToolRegistry()
	fs := &registryScanner{name: "trivy", caps: []string{"vulnerability", "sca"}, installed: true, version: "0.69.3"}
	img := &registryScanner{name: "trivy", caps: []string{"vulnerability"}, installed: true, version: "0.69.3"}
	if err := r.RegisterScanner(fs); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterScanner(img, "container"); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(context.Background())
	if len(rep.Tools) != 1 {
		t.Fatalf("one tool expected: %+v", rep.Tools)
	}
	if want := []string{"trivy", "sca", "container"}; !slices.Equal(rep.Capabilities, want) {
		t.Fatalf("capabilities = %v, want %v", rep.Capabilities, want)
	}
	// The first registration's probe answers for the tool.
	if fs.calls.Load() != 1 || img.calls.Load() != 0 {
		t.Fatalf("probes: fs %d img %d", fs.calls.Load(), img.calls.Load())
	}
}

func TestToolRegistryCollector(t *testing.T) {
	r := NewToolRegistry()
	if err := r.RegisterCollector(&registryCollector{name: "github"}, "cloud"); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(context.Background())
	if len(rep.Tools) != 1 || rep.Tools[0].Kind != ToolKindCollector || !rep.Tools[0].Installed {
		t.Fatalf("tools = %+v", rep.Tools)
	}
	if !slices.Equal(rep.Capabilities, []string{"github", "cloud"}) {
		t.Fatalf("capabilities = %v", rep.Capabilities)
	}
	if !r.HasKind(ToolKindCollector) || r.HasKind(ToolKindScanner) {
		t.Fatal("HasKind")
	}
}

func TestToolRegistryLimit(t *testing.T) {
	r := NewToolRegistry()
	for _, n := range []string{"semgrep", "nuclei", "trivy"} {
		if err := r.RegisterScanner(&registryScanner{name: n, installed: true}); err != nil {
			t.Fatal(err)
		}
	}
	r.AddCapabilities("validate")
	r.Limit("NUCLEI", " trivy", "")
	rep := r.CapabilityReport(context.Background())
	if !slices.Equal(toolNames(rep.Tools), []string{"nuclei", "trivy"}) {
		t.Fatalf("limited tools = %v", toolNames(rep.Tools))
	}
	if !slices.Equal(rep.Capabilities, []string{"nuclei", "trivy", "validate"}) {
		t.Fatalf("limited capabilities = %v", rep.Capabilities)
	}
	if !r.Allowed("nuclei") || r.Allowed("semgrep") {
		t.Fatal("Allowed")
	}
	// A limit naming nothing registered reports that no tool is available
	// (an empty, non-nil list), not "nothing reported".
	r.Limit("codeql")
	rep = r.CapabilityReport(context.Background())
	if rep.Tools == nil || len(rep.Tools) != 0 {
		t.Fatalf("limit to an absent tool: tools = %#v", rep.Tools)
	}
	if !slices.Equal(rep.Capabilities, []string{"validate"}) {
		t.Fatalf("sensor-wide capabilities must stay: %v", rep.Capabilities)
	}
	// No names lifts the limit.
	r.Limit()
	if rep = r.CapabilityReport(context.Background()); len(rep.Tools) != 3 || !r.Allowed("semgrep") {
		t.Fatalf("unlimited tools = %v", toolNames(rep.Tools))
	}
}

func TestToolRegistrySensorWideCapabilitiesAndConcurrency(t *testing.T) {
	r := NewToolRegistry()
	r.AddCapabilities("validate", "Validate", "bad word")
	r.SetMaxConcurrentJobs(4)
	rep := r.CapabilityReport(context.Background())
	// No tool registered: the inventory is not reported, the rest is.
	if rep.Tools != nil {
		t.Fatalf("tools = %#v", rep.Tools)
	}
	if !slices.Equal(rep.Capabilities, []string{"validate"}) || rep.MaxConcurrentJobs != 4 {
		t.Fatalf("report = %+v", rep)
	}
	r.SetMaxConcurrentJobs(-1)
	if rep = r.CapabilityReport(context.Background()); rep.MaxConcurrentJobs != 0 {
		t.Fatalf("negative max = %d", rep.MaxConcurrentJobs)
	}
}

func TestToolRegistryCachesProbes(t *testing.T) {
	r := NewToolRegistry()
	now := time.Unix(1_000_000, 0)
	r.now = func() time.Time { return now }
	r.SetProbeTTL(time.Minute)
	s := &registryScanner{name: "nuclei", installed: true, version: "3.4.1"}
	if err := r.RegisterScanner(s); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r.CapabilityReport(ctx)
	r.CapabilityReport(ctx)
	if s.calls.Load() != 1 {
		t.Fatalf("probed %d times within the TTL", s.calls.Load())
	}
	now = now.Add(time.Minute)
	r.CapabilityReport(ctx)
	if s.calls.Load() != 2 {
		t.Fatalf("not re-probed after the TTL: %d", s.calls.Load())
	}
	r.Refresh()
	r.CapabilityReport(ctx)
	if s.calls.Load() != 3 {
		t.Fatalf("not re-probed after Refresh: %d", s.calls.Load())
	}
	// A newly registered tool is probed at once (the cache is per tool).
	s2 := &registryScanner{name: "trivy", installed: true}
	if err := r.RegisterScanner(s2); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(ctx)
	if len(rep.Tools) != 2 || s2.calls.Load() != 1 || s.calls.Load() != 3 {
		t.Fatalf("tools %v, probes %d/%d", toolNames(rep.Tools), s.calls.Load(), s2.calls.Load())
	}
	// Installed probes the same way.
	if got := r.Installed(ctx); !slices.Equal(toolNames(got), []string{"nuclei", "trivy"}) {
		t.Fatalf("Installed = %v", toolNames(got))
	}
}

func TestToolRegistryProbeTimeout(t *testing.T) {
	r := NewToolRegistry()
	r.SetProbeTimeout(20 * time.Millisecond)
	if err := r.Register(ToolSpec{Name: "slow", Probe: func(ctx context.Context) (bool, string, error) {
		<-ctx.Done()
		return true, "1", ctx.Err()
	}}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rep := r.CapabilityReport(context.Background())
	if time.Since(start) > 2*time.Second {
		t.Fatal("probe timeout not applied")
	}
	if len(rep.Tools) != 1 || rep.Tools[0].Installed {
		t.Fatalf("a timed-out probe is not installed: %+v", rep.Tools)
	}
}

func TestToolRegistryReportIsACopy(t *testing.T) {
	r := NewToolRegistry()
	if err := r.RegisterScanner(&registryScanner{name: "semgrep", caps: []string{"sast"}, installed: true}); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(context.Background())
	rep.Tools[0].Name = "changed"
	rep.Capabilities[0] = "changed"
	again := r.CapabilityReport(context.Background())
	if again.Tools[0].Name != "semgrep" || again.Capabilities[0] != "semgrep" {
		t.Fatalf("report aliases the cache: %+v", again)
	}
}

func TestToolRegistryUnregister(t *testing.T) {
	r := NewToolRegistry()
	_ = r.RegisterScanner(&registryScanner{name: "semgrep", installed: true})
	_ = r.RegisterScanner(&registryScanner{name: "nuclei", installed: true})
	r.Unregister("SEMGREP")
	r.Unregister("absent")
	if got := toolNames(r.CapabilityReport(context.Background()).Tools); !slices.Equal(got, []string{"nuclei"}) {
		t.Fatalf("tools = %v", got)
	}
	// Removing the last tool reports an empty inventory: the sensor had
	// tools and now has none.
	r.Unregister("nuclei")
	if rep := r.CapabilityReport(context.Background()); rep.Tools == nil || len(rep.Tools) != 0 {
		t.Fatalf("tools = %#v", rep.Tools)
	}
}

func TestToolRegistryCostHints(t *testing.T) {
	r := NewToolRegistry()
	hint := &resource.ToolCostHint{Cores: 2, MemBytes: 2 << 30, SecondsPerTarget: 30}
	if err := r.Register(ToolSpec{Name: "zap", Cost: hint}); err != nil {
		t.Fatal(err)
	}
	_ = r.Register(ToolSpec{Name: "plain"})
	hints := r.CostHints()
	if len(hints) != 1 || hints["zap"] != *hint {
		t.Fatalf("hints = %+v", hints)
	}
	// The resource manager uses a hint as the prior of a tool it has no
	// history for.
	m := resource.NewManager(resource.ManagerConfig{Tools: r.Names(), CostHints: hints})
	est := m.Book().Estimate("zap")
	if est.MemBytes != 2<<30 || est.CPUSeconds != 60 || est.ThroughputTargetsPerMin != 2 {
		t.Fatalf("estimate = %+v", est)
	}
}

func TestToolRegistryConcurrentUse(t *testing.T) {
	r := NewToolRegistry()
	r.SetProbeTTL(0)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = r.RegisterScanner(&registryScanner{name: []string{"a", "b", "c", "d"}[i%4], installed: true})
			r.Limit()
			r.AddCapabilities("validate")
		}()
		go func() {
			defer wg.Done()
			_ = r.CapabilityReport(context.Background())
			_ = r.Names()
		}()
	}
	wg.Wait()
	if r.Len() != 4 {
		t.Fatalf("len = %d", r.Len())
	}
}

// --- BaseSensor: the registry is the default source of the report ----------

func TestBaseSensorReportsRegisteredScannersByDefault(t *testing.T) {
	s := NewBaseSensor(&BaseSensorConfig{Name: "s"}, nil)
	ctx := context.Background()
	if got := s.withCapabilities(ctx, s.Status()); got.Tools != nil || got.Capabilities != nil {
		t.Fatalf("a sensor without tools must report nothing: %+v", got)
	}
	if err := s.AddScanner(&registryScanner{name: "semgrep", caps: []string{"sast"}, installed: true, version: "1.90.0"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCollector(&registryCollector{name: "github"}); err != nil {
		t.Fatal(err)
	}
	got := s.withCapabilities(ctx, s.Status())
	if !slices.Equal(toolNames(got.Tools), []string{"semgrep", "github"}) || got.Tools[0].Version != "1.90.0" {
		t.Fatalf("tools = %+v", got.Tools)
	}
	if !slices.Equal(got.Capabilities, []string{"semgrep", "sast", "github"}) {
		t.Fatalf("capabilities = %v", got.Capabilities)
	}
	if s.Tools() == nil || s.Tools().Len() != 2 {
		t.Fatal("Tools() must expose the registry")
	}

	if err := s.RemoveScanner("semgrep"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveCollector("github"); err != nil {
		t.Fatal(err)
	}
	if got := s.withCapabilities(ctx, s.Status()); got.Tools == nil || len(got.Tools) != 0 {
		t.Fatalf("after removing every tool: %#v", got.Tools)
	}
}

func TestBaseSensorCapabilityReporterOverridesRegistry(t *testing.T) {
	s := NewBaseSensor(&BaseSensorConfig{Name: "s"}, nil)
	ctx := context.Background()
	_ = s.AddScanner(&registryScanner{name: "semgrep", installed: true})
	s.SetCapabilityReporter(StaticCapabilities(CapabilityReport{MaxConcurrentJobs: 3}))
	if got := s.withCapabilities(ctx, s.Status()); got.Tools != nil || got.MaxConcurrentJobs != 3 {
		t.Fatalf("an explicit reporter replaces the registry: %+v", got)
	}
	// nil goes back to the registry.
	s.SetCapabilityReporter(nil)
	if got := s.withCapabilities(ctx, s.Status()); len(got.Tools) != 1 {
		t.Fatalf("nil reporter must fall back to the registry: %+v", got)
	}
}

func TestDefaultCommandExecutorRegistersTools(t *testing.T) {
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(&registryScanner{name: "nuclei", caps: []string{"dast"}, installed: true})
	r := NewToolRegistry()
	e.SetToolRegistry(r)
	e.AddScanner(&registryScanner{name: "trivy", caps: []string{"sca"}, installed: true})
	e.AddCollector(&registryCollector{name: "github"})
	rep := r.CapabilityReport(context.Background())
	if !slices.Equal(toolNames(rep.Tools), []string{"nuclei", "trivy", "github"}) {
		t.Fatalf("tools = %v", toolNames(rep.Tools))
	}
	if !slices.Equal(rep.Capabilities, []string{"nuclei", "dast", "trivy", "sca", "github"}) {
		t.Fatalf("capabilities = %v", rep.Capabilities)
	}
	// Sharing the sensor's registry makes the heartbeat report the executor's tools.
	s := NewBaseSensor(&BaseSensorConfig{Name: "s"}, nil)
	e2 := NewDefaultCommandExecutor(nil)
	e2.SetToolRegistry(s.Tools())
	e2.AddScanner(&registryScanner{name: "semgrep", installed: true})
	if got := s.withCapabilities(context.Background(), s.Status()); !slices.Equal(toolNames(got.Tools), []string{"semgrep"}) {
		t.Fatalf("heartbeat tools = %v", toolNames(got.Tools))
	}
}

// Each reported tool carries its own capabilities and kind, so the platform
// knows which tool serves what (live: every tool arrived with neither and
// only the flat list said "dast", "sast", ...).
func TestToolRegistryReportsPerToolCapabilities(t *testing.T) {
	r := NewToolRegistry()
	installed := func(context.Context) (bool, string, error) { return true, "v3.11.1", nil }
	if err := r.Register(ToolSpec{Name: "nuclei", Capabilities: []string{"dast", "validate:nuclei"}, Probe: installed}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(ToolSpec{Name: "nuclei", Capabilities: []string{"web"}}); err != nil { // a second mode adds
		t.Fatal(err)
	}
	if err := r.Register(ToolSpec{Name: "inventory", Kind: ToolKindCollector}); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(context.Background())
	if len(rep.Tools) != 2 {
		t.Fatalf("tools = %+v", rep.Tools)
	}
	n := rep.Tools[0]
	if n.Kind != ToolKindScanner || strings.Join(n.Capabilities, ",") != "dast,validate:nuclei,web" {
		t.Fatalf("nuclei = %+v", n)
	}
	if c := rep.Tools[1]; c.Kind != ToolKindCollector || c.Capabilities != nil {
		t.Fatalf("collector = %+v", c)
	}
	// The report's slices are the caller's.
	n.Capabilities[0] = "x"
	if again := r.CapabilityReport(context.Background()).Tools[0].Capabilities[0]; again != "dast" {
		t.Fatalf("registry shares its slice: %q", again)
	}

	var st SensorStatus
	rep.Apply(&st)
	b, err := json.Marshal(st.Tools)
	if err != nil {
		t.Fatal(err)
	}
	const want = `[{"name":"nuclei","kind":"scanner","version":"v3.11.1","installed":true,"capabilities":["x","validate:nuclei","web"]},{"name":"inventory","kind":"collector","installed":true}]`
	if string(b) != want {
		t.Fatalf("wire = %s\nwant %s", b, want)
	}
}
