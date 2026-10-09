package core

// The sensor manifest (api RFC-033, docs/rfcs/RFC-033-sensor-manifest.md):
// what a sensor is, registered once and again when it changes. Build,
// platform, resources, the operator's concurrency ceiling, the sensor-wide
// capabilities and every tool with its kind, version, installed state,
// capabilities and content versions. Its load is not in it: that stays on
// every heartbeat.
//
// A BaseSensor builds the manifest from its capability report (a sensor only
// registers tools) and, when the platform serves it (protocol v2 feature
// "manifest"), registers it before its first heartbeat, again when its own
// digest changes and when a heartbeat answer asks (HeartbeatActionSendManifest).
// Every heartbeat then echoes the digest the platform returned.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/sdk-go/pkg/resource"
)

// ManifestSchema is the manifest document version this SDK writes.
const ManifestSchema = 1

// Concurrency models of a manifest.
const (
	// ConcurrencyModelDynamic: the SDK sizes the slots from CPU, memory and
	// the tools' learned cost (a resource manager), at most the ceiling.
	ConcurrencyModelDynamic = "dynamic"
	// ConcurrencyModelFixed: the ceiling is the slot count.
	ConcurrencyModelFixed = "fixed"
)

// HeartbeatActionSendManifest: the platform does not have the manifest this
// sensor's heartbeat names (api RFC-033); register it again.
const HeartbeatActionSendManifest HeartbeatAction = "send_manifest"

// ErrManifestUnsupported is returned by ManifestPusher.PutManifest when the
// platform does not serve manifests (no "manifest" on hello). The sensor
// then keeps reporting only on its heartbeat, as before.
var ErrManifestUnsupported = errors.New("the platform does not accept sensor manifests")

// Manifest is a sensor's self-description (api RFC-033 §6.2).
type Manifest struct {
	Schema       int                  `json:"schema"`
	Sensor       *SensorBuild         `json:"sensor,omitempty"`
	SDK          *SDKInfo             `json:"sdk,omitempty"`
	Platform     *ManifestPlatform    `json:"platform,omitempty"`
	Resources    *ManifestResources   `json:"resources,omitempty"`
	Concurrency  *ManifestConcurrency `json:"concurrency,omitempty"`
	Capabilities []string             `json:"capabilities,omitempty"`
	Tools        []ManifestTool       `json:"tools"`
	// LocalPolicy is the sensor-local policy's state, digest and summary
	// (api RFC-040 §5.7), without the live kill switch (the heartbeat
	// carries that). The API client sends it only to a platform that lists
	// the "local_policy" feature.
	LocalPolicy *LocalPolicyReport `json:"local_policy,omitempty"`
	// Posture is the sensor's platform TLS pin and tool sandbox
	// (SensorPosture; BaseSensor.SetPosture). The API client sends it only
	// to a platform that lists the "posture" feature.
	Posture *SensorPosture `json:"posture,omitempty"`
}

// ManifestPlatform is the operating system and architecture.
type ManifestPlatform struct {
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
}

// ManifestResources is what the sensor may use (container limits when it
// runs in one).
type ManifestResources struct {
	CPUCores      float64 `json:"cpu_cores,omitempty"`
	MemTotalBytes int64   `json:"mem_total_bytes,omitempty"`
}

// ManifestConcurrency is the operator's ceiling (0: none) and the model.
type ManifestConcurrency struct {
	Ceiling int    `json:"ceiling"`
	Model   string `json:"model,omitempty"`
}

// ManifestTool is one registered tool.
type ManifestTool struct {
	Name         string            `json:"name"`
	Kind         ToolKind          `json:"kind,omitempty"`
	Version      string            `json:"version,omitempty"`
	Installed    bool              `json:"installed"`
	Capabilities []string          `json:"capabilities,omitempty"`
	TargetTypes  []string          `json:"target_types,omitempty"`
	Content      []ManifestContent `json:"content,omitempty"`
	// Settings identifies the tool's settings schema (api RFC-038): its
	// version and digest only; the platform fetches a schema it does not
	// have by digest. Absent for a tool without settings.
	Settings *ManifestToolSettings `json:"settings,omitempty"`
	// Contract names the tool's tool.yaml manifest by digest, with the
	// fields the platform plans with (class, tier, network, consumes,
	// produces). Absent for a tool not ported to the tool contract.
	Contract *ToolContract `json:"contract,omitempty"`
}

// ManifestToolSettings is a tool's settings schema as the manifest names
// it.
type ManifestToolSettings struct {
	SchemaVersion int    `json:"schema_version"`
	Digest        string `json:"digest"`
}

// ManifestContent is a tool's content version, without the timestamps
// (they change on every refresh and stay on the heartbeat).
type ManifestContent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Source  string `json:"source,omitempty"`
	Managed bool   `json:"managed"`
}

// ManifestAck is the platform's answer to a registered manifest.
type ManifestAck struct {
	// Digest is what the platform stored; heartbeats echo it.
	Digest string
	// Changed is false when the platform already had it.
	Changed bool
	// AcceptedTools and AcceptedCapabilities are what the platform kept.
	AcceptedTools        []string
	AcceptedCapabilities []string
	// Ignored lists what it dropped and why.
	Ignored []ManifestIgnored
	// Policy is what the platform lets the sensor run (api RFC-033 §6.12);
	// nil from a platform that does not say. The BaseSensor refuses
	// commands for tools outside it (CommandToolGate).
	Policy *ManifestPolicy
	// OmitInventory: heartbeats that echo Digest may leave the tool
	// inventory out and carry only each tool's content freshness.
	OmitInventory bool
}

// ManifestPolicy is the sensor's effective tools, capabilities and
// capacity as the platform computes them (the sensor's report narrowed by
// the administrator's settings).
type ManifestPolicy struct {
	AllowedTools        []string
	AllowedCapabilities []string
	MaxJobs             int
}

// ManifestStateReader is implemented by a Pusher that can re-read the
// platform's view of the registered manifest (GET /manifest): the digest,
// the policy as it stands now and the heartbeat form. The BaseSensor calls
// it when the heartbeat's config_version changes. ErrManifestNotRegistered
// means the platform has no manifest for the sensor.
type ManifestStateReader interface {
	GetManifestState(ctx context.Context) (*ManifestAck, error)
}

// ErrManifestNotRegistered: the platform has no manifest for this sensor.
var ErrManifestNotRegistered = errors.New("the platform has no manifest for this sensor")

// ErrToolNotAllowed is the error of a command refused because its tool is
// outside the platform's policy (api RFC-033 §6.12). The command is reported
// failed with it, never run.
var ErrToolNotAllowed = errors.New("tool-not-allowed")

// ToolContent is one piece of a tool's content on a slim heartbeat's
// "content" (api RFC-033 §6.12): ContentInfo with the tool it belongs to.
type ToolContent struct {
	Tool string `json:"tool"`
	ContentInfo
}

// ManifestIgnored is one manifest item the platform dropped.
type ManifestIgnored struct {
	Path   string `json:"path"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason"`
}

// ManifestPusher is implemented by a Pusher that can register a manifest
// (client.Client on protocol v2).
type ManifestPusher interface {
	PutManifest(ctx context.Context, m *Manifest) (*ManifestAck, error)
}

// BuildManifest builds the manifest of a heartbeat status that already
// carries the capability report (BaseSensor.withCapabilities): its tools,
// the capabilities no installed tool provides (sensor-wide), the operator's
// ceiling, the build and the platform. res, when known, gives the
// resources; model is ConcurrencyModelDynamic when a resource manager sizes
// the slots.
func BuildManifest(status *SensorStatus, res *resource.HostResources, model string) Manifest {
	m := Manifest{Schema: ManifestSchema, Tools: []ManifestTool{}}
	if status == nil {
		return m
	}
	m.Sensor, m.SDK = status.Sensor, status.SDK
	if status.OS != "" || status.Arch != "" {
		m.Platform = &ManifestPlatform{OS: status.OS, Arch: status.Arch}
	}
	if res != nil && (res.CPUCores > 0 || res.MemTotalBytes > 0) {
		m.Resources = &ManifestResources{CPUCores: res.CPUCores, MemTotalBytes: res.MemTotalBytes}
	}
	if status.MaxConcurrentJobs > 0 || model != "" {
		m.Concurrency = &ManifestConcurrency{Ceiling: max(status.MaxConcurrentJobs, 0), Model: model}
	}
	provided := map[string]bool{}
	for _, t := range status.Tools {
		mt := ManifestTool{Name: t.Name, Kind: t.Kind, Version: t.Version, Installed: t.Installed,
			Capabilities: slices.Clone(t.Capabilities)}
		if t.Settings != nil {
			ts := *t.Settings
			mt.Settings = &ts
		}
		mt.Contract = t.Contract.clone()
		for _, c := range t.Content {
			mt.Content = append(mt.Content, ManifestContent{Name: c.Name, Version: c.Version, Digest: c.Digest,
				Source: c.Source, Managed: c.Managed})
		}
		m.Tools = append(m.Tools, mt)
		if t.Installed {
			provided[t.Name] = true
			for _, c := range t.Capabilities {
				provided[c] = true
			}
		}
	}
	budgetDescriptors(m.Tools)
	for _, c := range status.Capabilities {
		if !provided[c] && !slices.Contains(m.Capabilities, c) {
			m.Capabilities = append(m.Capabilities, c)
		}
	}
	if lp := status.LocalPolicy; lp != nil {
		r := *lp
		r.KillSwitch = false // live state: on the heartbeat, not in the manifest
		r.Warnings = slices.Clone(lp.Warnings)
		if lp.Summary != nil {
			s := *lp.Summary
			s.Tools, s.Checks = slices.Clone(s.Tools), slices.Clone(s.Checks)
			r.Summary = &s
		}
		m.LocalPolicy = &r
	}
	return m
}

// Digest is "sha256:" + the hex SHA-256 of the manifest's canonical JSON
// (object members sorted, no whitespace, no HTML escaping), the form the
// platform digests. The sensor uses it to notice its own changes; the
// heartbeat echoes the digest the platform returned.
func (m Manifest) Digest() (string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("decode manifest: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// MaxManifestDescriptorBytes bounds the tool descriptors one manifest
// carries in all. The platform caps a manifest document (256 KiB in
// OpenCTEM); descriptors past the budget are left out, largest first, and
// the platform keeps planning with those tools by their digest and
// contract fields.
const MaxManifestDescriptorBytes = 128 << 10

// budgetDescriptors leaves out the largest descriptors until the rest fit
// MaxManifestDescriptorBytes. The choice is deterministic (size, then name),
// so the manifest digest stays stable.
func budgetDescriptors(tools []ManifestTool) {
	total := 0
	var idx []int
	for i, t := range tools {
		if t.Contract != nil && len(t.Contract.Descriptor) > 0 {
			total += len(t.Contract.Descriptor)
			idx = append(idx, i)
		}
	}
	if total <= MaxManifestDescriptorBytes {
		return
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		if d := len(tools[b].Contract.Descriptor) - len(tools[a].Contract.Descriptor); d != 0 {
			return d
		}
		return strings.Compare(tools[a].Name, tools[b].Name)
	})
	for _, i := range idx {
		if total <= MaxManifestDescriptorBytes {
			return
		}
		total -= len(tools[i].Contract.Descriptor)
		tools[i].Contract.Descriptor = nil
	}
}
