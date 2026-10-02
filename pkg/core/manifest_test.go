package core

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/resource"
)

// The capability report's tools and flat list become a manifest whose
// sensor-wide capabilities are the ones no installed tool provides; content
// timestamps are left out.
func TestBuildManifest(t *testing.T) {
	at := time.Now()
	status := &SensorStatus{
		OS: "linux", Arch: "amd64",
		Sensor: &SensorBuild{Name: "openctemio-sensor", Version: "0.7.0"},
		SDK:    &SDKInfo{Name: "openctem-sdk-go", Version: "0.13.0"},
		Tools: []ToolInfo{
			{Name: "nuclei", Kind: ToolKindScanner, Version: "v3.11.1", Installed: true, Capabilities: []string{"dast", "validate:nuclei"},
				Content: []ContentInfo{{Name: "nuclei-templates", Version: "v10.4.9", Managed: true, CheckedAt: &at}}},
			{Name: "trivy", Kind: ToolKindScanner, Installed: false, Capabilities: []string{"sca"}},
		},
		Capabilities: []string{"nuclei", "dast", "validate:nuclei", "validate"},
	}
	m := BuildManifest(status, &resource.HostResources{CPUCores: 4, MemTotalBytes: 8 << 30, CPUUsedPct: 93}, ConcurrencyModelDynamic)
	if !reflect.DeepEqual(m.Capabilities, []string{"validate"}) {
		t.Fatalf("sensor-wide = %v", m.Capabilities)
	}
	if m.Concurrency == nil || m.Concurrency.Ceiling != 0 || m.Concurrency.Model != ConcurrencyModelDynamic {
		t.Fatalf("concurrency = %+v", m.Concurrency)
	}
	if m.Resources == nil || m.Resources.CPUCores != 4 || len(m.Tools) != 2 || m.Tools[0].Content[0].Version != "v10.4.9" {
		t.Fatalf("manifest = %+v", m)
	}
	d1, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// Load (CPU use) and content timestamps do not change it; a version does.
	later := at.Add(time.Hour)
	status.Tools[0].Content[0].CheckedAt = &later
	if d2, _ := BuildManifest(status, &resource.HostResources{CPUCores: 4, MemTotalBytes: 8 << 30, CPUUsedPct: 5}, ConcurrencyModelDynamic).Digest(); d2 != d1 {
		t.Fatal("load or a timestamp changed the digest")
	}
	status.Tools[0].Version = "v3.12.0"
	if d3, _ := BuildManifest(status, nil, ConcurrencyModelDynamic).Digest(); d3 == d1 {
		t.Fatal("a tool version bump kept the digest")
	}
}

// The digest is the platform's canonical form (api pkg/domain/sensor
// ManifestDigest pins the same value): sorted members, no whitespace, no
// HTML escaping.
func TestManifestDigestMatchesPlatform(t *testing.T) {
	m := Manifest{Schema: 1, Capabilities: []string{"validate"},
		Tools: []ManifestTool{{Name: "nuclei", Kind: ToolKindScanner, Installed: true, Capabilities: []string{"dast", "<x>"}}}}
	got, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const want = manifestDigestPinned
	if got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
}

// manifestPusher is a doorbell pusher that also registers manifests.
type manifestPusher struct {
	mu          sync.Mutex
	unsupported bool
	fail        error
	puts        []Manifest
	beats       []string // manifest_digest of each heartbeat
	ask         bool     // answer the next heartbeat with send_manifest
	// Phase 2 (api RFC-033 §6.12).
	policy   *ManifestPolicy
	omit     bool
	cv       string // config_version every heartbeat answers
	gets     int
	statuses []SensorStatus
}

func (p *manifestPusher) GetManifestState(context.Context) (*ManifestAck, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gets++
	if len(p.puts) == 0 {
		return nil, ErrManifestNotRegistered
	}
	d, _ := p.puts[len(p.puts)-1].Digest()
	return &ManifestAck{Digest: "platform:" + d, Policy: p.policy, OmitInventory: p.omit}, nil
}

func (p *manifestPusher) PutManifest(_ context.Context, m *Manifest) (*ManifestAck, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unsupported {
		return nil, ErrManifestUnsupported
	}
	if p.fail != nil {
		return nil, p.fail
	}
	p.puts = append(p.puts, *m)
	d, _ := m.Digest()
	return &ManifestAck{Digest: "platform:" + d, Changed: true, Policy: p.policy, OmitInventory: p.omit}, nil
}

func (p *manifestPusher) SendHeartbeatWithHints(_ context.Context, s *SensorStatus) (*HeartbeatHints, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beats = append(p.beats, s.ManifestDigest)
	p.statuses = append(p.statuses, *s)
	h := &HeartbeatHints{Present: true, ConfigVersion: p.cv}
	if p.ask {
		p.ask = false
		h.Actions = []HeartbeatAction{HeartbeatActionSendManifest}
	}
	return h, nil
}
func (p *manifestPusher) SendHeartbeat(context.Context, *SensorStatus) error { return nil }
func (p *manifestPusher) PushFindings(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *manifestPusher) PushAssets(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *manifestPusher) TestConnection(context.Context) error { return nil }

func (p *manifestPusher) counts() (puts int, lastBeat string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.beats) > 0 {
		lastBeat = p.beats[len(p.beats)-1]
	}
	return len(p.puts), lastBeat
}

func newManifestSensor(t *testing.T, p *manifestPusher) *BaseSensor {
	t.Helper()
	s := NewBaseSensor(&BaseSensorConfig{Name: "m", HeartbeatInterval: time.Hour}, p)
	d, _ := newTestDoorbell(t, nil)
	s.SetDoorbell(d)
	s.Tools().SetProbeTTL(0)
	if err := s.Tools().Register(ToolSpec{Name: "nuclei", Version: "v3.11.1", Capabilities: []string{"dast"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

// The life of a manifest: registered before the first heartbeat, echoed by
// every heartbeat, not re-sent while unchanged, re-sent when a tool changes
// and when the platform asks.
func TestBaseSensor_RegistersManifest(t *testing.T) {
	ctx := context.Background()
	p := &manifestPusher{}
	s := newManifestSensor(t, p)

	if _, err := s.FirstHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	puts, beat := p.counts()
	if puts != 1 || beat == "" || beat[:9] != "platform:" {
		t.Fatalf("first heartbeat: %d puts, digest %q", puts, beat)
	}
	if m := p.puts[0]; len(m.Tools) != 1 || m.Tools[0].Name != "nuclei" || m.Schema != ManifestSchema {
		t.Fatalf("manifest %+v", m)
	}
	first := beat

	s.sendHeartbeat(ctx)
	if puts, beat = p.counts(); puts != 1 || beat != first {
		t.Fatalf("unchanged: %d puts, digest %q", puts, beat)
	}

	if err := s.Tools().Register(ToolSpec{Name: "semgrep", Capabilities: []string{"sast"}}); err != nil {
		t.Fatal(err)
	}
	s.sendHeartbeat(ctx)
	if puts, beat = p.counts(); puts != 2 || beat == first {
		t.Fatalf("new tool: %d puts, digest %q", puts, beat)
	}

	p.mu.Lock()
	p.ask = true
	p.mu.Unlock()
	s.sendHeartbeat(ctx) // answered with send_manifest
	s.sendHeartbeat(ctx) // re-registers
	if puts, _ = p.counts(); puts != 3 {
		t.Fatalf("send_manifest: %d puts, want 3", puts)
	}
}

// A platform without manifests: nothing registered, no digest, and the
// heartbeat carries the inventory as before. A failed registration backs
// off and never fails the heartbeat.
func TestBaseSensor_ManifestUnsupportedAndFailing(t *testing.T) {
	ctx := context.Background()
	p := &manifestPusher{unsupported: true}
	s := newManifestSensor(t, p)
	if _, err := s.FirstHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if puts, beat := p.counts(); puts != 0 || beat != "" {
		t.Fatalf("unsupported: %d puts, digest %q", puts, beat)
	}

	p2 := &manifestPusher{fail: errors.New("503")}
	s2 := newManifestSensor(t, p2)
	if _, err := s2.FirstHeartbeat(ctx); err != nil {
		t.Fatalf("a failed registration failed the heartbeat: %v", err)
	}
	p2.mu.Lock()
	p2.fail = nil
	p2.mu.Unlock()
	s2.sendHeartbeat(ctx) // within the retry delay: not retried yet
	if puts, beat := p2.counts(); puts != 0 || beat != "" {
		t.Fatalf("retried within the delay: %d puts, digest %q", puts, beat)
	}
	s2.manifest.mu.Lock()
	s2.manifest.retryAt = time.Time{}
	s2.manifest.mu.Unlock()
	s2.sendHeartbeat(ctx)
	if puts, beat := p2.counts(); puts != 1 || beat == "" {
		t.Fatalf("after the delay: %d puts, digest %q", puts, beat)
	}
}

// manifestDigestPinned is the digest the api computes for the same document
// (api pkg/domain/sensor TestManifestDigestMatchesSDK).
const manifestDigestPinned = "sha256:053d2bb0ced8606d7b0278818bb6dc30e49116b36d6e6380d228de3e82fe4d51"

// O3: once the platform acknowledged with omit_inventory, heartbeats leave
// the inventory out and carry each tool's content freshness.
func TestBaseSensor_SlimHeartbeat(t *testing.T) {
	ctx := context.Background()
	p := &manifestPusher{omit: true}
	s := newManifestSensor(t, p)
	s.Tools().SetMaxConcurrentJobs(3)
	if err := s.Tools().Register(ToolSpec{Name: "trivy", Version: "0.75.0"}); err != nil {
		t.Fatal(err)
	}
	s.SetCapabilityReporter(CapabilityReporterFunc(func(ctx context.Context) CapabilityReport {
		rep := s.Tools().CapabilityReport(ctx)
		rep.Tools[1].Content = []ContentInfo{{Name: "trivy-db", Version: "2026-10-02", Managed: true, Error: "rate limited"}}
		return rep
	}))
	if _, err := s.FirstHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	s.sendHeartbeat(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.puts) != 1 || len(p.puts[0].Tools) != 2 {
		t.Fatalf("manifest %+v", p.puts)
	}
	for i, st := range p.statuses {
		if st.Tools != nil || st.Capabilities != nil || st.MaxConcurrentJobs != 0 || st.ManifestDigest == "" {
			t.Fatalf("heartbeat %d not slim: %+v", i, st)
		}
		if len(st.Content) != 1 || st.Content[0].Tool != "trivy" || st.Content[0].Error != "rate limited" {
			t.Fatalf("heartbeat %d content %+v", i, st.Content)
		}
	}
}

// Without omit_inventory (a platform before Phase 2, or the kill switch)
// heartbeats stay full.
func TestBaseSensor_FullHeartbeatWithoutOmit(t *testing.T) {
	p := &manifestPusher{}
	s := newManifestSensor(t, p)
	if _, err := s.FirstHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if st := p.statuses[0]; st.Tools == nil || st.Content != nil || st.ManifestDigest == "" {
		t.Fatalf("heartbeat %+v", st)
	}
}

// O2: the policy comes with the acknowledgement and is read again when the
// platform's config_version moves.
func TestBaseSensor_PolicyFollowsConfigVersion(t *testing.T) {
	ctx := context.Background()
	p := &manifestPusher{policy: &ManifestPolicy{AllowedTools: []string{"nuclei"}}, cv: "aaaaaaaaaaaaaaaa"}
	s := newManifestSensor(t, p)
	if got := s.ManifestPolicy(); got != nil {
		t.Fatalf("policy before the first registration: %+v", got)
	}
	if _, err := s.FirstHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.ManifestPolicy(); got == nil || !reflect.DeepEqual(got.AllowedTools, []string{"nuclei"}) {
		t.Fatalf("policy %+v", got)
	}
	s.sendHeartbeat(ctx) // same config_version: no GET
	p.mu.Lock()
	if p.gets != 0 {
		t.Fatalf("%d GETs without a config_version change", p.gets)
	}
	p.cv = "bbbbbbbbbbbbbbbb"
	p.policy = &ManifestPolicy{AllowedTools: []string{"nuclei", "semgrep"}}
	p.mu.Unlock()
	s.sendHeartbeat(ctx) // answered with the new version
	s.sendHeartbeat(ctx) // reads the policy again
	p.mu.Lock()
	gets, puts := p.gets, len(p.puts)
	p.mu.Unlock()
	if gets != 1 || puts != 1 {
		t.Fatalf("after the change: %d GETs, %d PUTs", gets, puts)
	}
	if got := s.ManifestPolicy(); !reflect.DeepEqual(got.AllowedTools, []string{"nuclei", "semgrep"}) {
		t.Fatalf("policy not re-read: %+v", got)
	}
}

func TestCommandToolGate(t *testing.T) {
	p := &manifestPusher{policy: &ManifestPolicy{AllowedTools: []string{"nuclei", "betterleaks"}}}
	s := newManifestSensor(t, p)
	gate := s.CommandToolGate()
	cmd := func(payload string) *Command { return &Command{ID: "c", Type: "scan", Payload: []byte(payload)} }
	if err := gate(cmd(`{"scanner":"semgrep"}`)); err != nil {
		t.Fatalf("no policy yet must pass: %v", err)
	}
	if _, err := s.FirstHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	for payload, allowed := range map[string]bool{
		`{"scanner":"nuclei"}`:         true,
		`{"scanner":"NUCLEI "}`:        true,
		`{"scanner":"gitleaks"}`:       true, // the retired name of betterleaks
		`{"preferred_tool":"nuclei"}`:  true,
		`{"target":"x"}`:               true, // names no tool
		`{"scanner":"semgrep"}`:        false,
		`{"preferred_tool":"semgrep"}`: false,
	} {
		err := gate(cmd(payload))
		if allowed != (err == nil) {
			t.Errorf("%s: err %v, allowed %v", payload, err, allowed)
		}
		if err != nil && (!errors.Is(err, ErrToolNotAllowed) || !strings.Contains(err.Error(), "tool-not-allowed: semgrep")) {
			t.Errorf("%s: error %q", payload, err)
		}
	}
}

// The poller reports a refused command failed and never runs it.
func TestCommandPoller_GateRefuses(t *testing.T) {
	c := newQueueClient(scanCmd("refused", "normal", map[string]any{"scanner": "semgrep"}),
		scanCmd("ok", "normal", map[string]any{"scanner": "nuclei"}))
	e := newCtxExecutor()
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 4})
	p.SetCommandGate(func(cmd *Command) error {
		if commandTool(cmd) == "semgrep" {
			return fmt.Errorf("%w: semgrep", ErrToolNotAllowed)
		}
		return nil
	})
	p.pollAndExecute(context.Background())
	select {
	case id := <-e.started:
		if id != "ok" {
			t.Fatalf("ran %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the allowed command did not run")
	}
	close(e.release)
	p.activeCmds.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.results["refused"] != "failed" {
		t.Fatalf("refused command result %q", c.results["refused"])
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.runs["refused"] != 0 {
		t.Fatal("the refused command ran")
	}
}

// A command for a tool the administrator just allowed is not refused: the
// policy is stale (a newer config_version was announced) and is read again
// before the refusal.
func TestCommandToolGate_RereadsStalePolicy(t *testing.T) {
	ctx := context.Background()
	p := &manifestPusher{policy: &ManifestPolicy{AllowedTools: []string{"nuclei"}}, cv: "aaaaaaaaaaaaaaaa"}
	s := newManifestSensor(t, p)
	if _, err := s.FirstHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.cv = "bbbbbbbbbbbbbbbb"
	p.policy = &ManifestPolicy{AllowedTools: []string{"nuclei", "semgrep"}}
	p.mu.Unlock()
	s.sendHeartbeat(ctx) // announces the new version (and would ring the doorbell)
	if err := s.CommandToolGate()(&Command{ID: "c", Type: "scan", Payload: []byte(`{"scanner":"semgrep"}`)}); err != nil {
		t.Fatalf("refused under a stale policy: %v", err)
	}
	if err := s.CommandToolGate()(&Command{ID: "c", Type: "scan", Payload: []byte(`{"scanner":"trivy"}`)}); !errors.Is(err, ErrToolNotAllowed) {
		t.Fatalf("trivy: %v", err)
	}
}
