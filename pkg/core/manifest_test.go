package core

import (
	"context"
	"errors"
	"reflect"
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
	return &ManifestAck{Digest: "platform:" + d, Changed: true}, nil
}

func (p *manifestPusher) SendHeartbeatWithHints(_ context.Context, s *SensorStatus) (*HeartbeatHints, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beats = append(p.beats, s.ManifestDigest)
	h := &HeartbeatHints{Present: true}
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
