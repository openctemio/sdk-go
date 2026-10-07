package tool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"gopkg.in/yaml.v3"
)

// MaxManifestBytes bounds a tool.yaml file.
const MaxManifestBytes = 256 << 10

// ManifestError is one problem in a manifest. Path is a JSON pointer.
type ManifestError struct {
	Path    string
	Message string
}

func (e ManifestError) Error() string {
	if e.Path == "" {
		return e.Message
	}
	return e.Path + ": " + e.Message
}

// ManifestErrors are every problem found in a manifest.
type ManifestErrors []ManifestError

func (e ManifestErrors) Error() string {
	parts := make([]string, len(e))
	for i, m := range e {
		parts[i] = m.Error()
	}
	return "invalid tool manifest: " + strings.Join(parts, "; ")
}

// LoadManifestFile reads and validates a tool.yaml file.
func LoadManifestFile(path string) (Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, err
	}
	return LoadManifest(data)
}

// LoadManifest reads a manifest (YAML or JSON) strictly: unknown keys,
// duplicate keys and more than one document are errors. The result is
// validated (Validate) and has its defaults filled.
func LoadManifest(data []byte) (Manifest, error) {
	if len(data) > MaxManifestBytes {
		return Manifest{}, ManifestErrors{{Message: fmt.Sprintf("larger than %d bytes", MaxManifestBytes)}}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return Manifest{}, ManifestErrors{{Message: "not YAML: " + err.Error()}}
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return Manifest{}, ManifestErrors{{Message: "more than one YAML document"}}
	}
	if _, ok := doc.(map[string]any); !ok {
		return Manifest{}, ManifestErrors{{Message: "not a mapping"}}
	}
	js, err := json.Marshal(doc)
	if err != nil {
		return Manifest{}, ManifestErrors{{Message: "not representable as JSON: " + err.Error()}}
	}
	var m Manifest
	jd := json.NewDecoder(bytes.NewReader(js))
	jd.DisallowUnknownFields()
	if err := jd.Decode(&m); err != nil {
		return Manifest{}, ManifestErrors{{Message: err.Error()}}
	}
	if m.APIVersion != APIVersion {
		return Manifest{}, ManifestErrors{{Path: "/apiVersion", Message: fmt.Sprintf("must be %q", APIVersion)}}
	}
	m = m.withDefaults()
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// withDefaults fills the defaults: apiVersion, protocol, network and
// filesystem by class, run profile, and the config schema's version.
func (m Manifest) withDefaults() Manifest {
	if m.APIVersion == "" {
		m.APIVersion = APIVersion
	}
	if m.Protocol.Min == 0 {
		m.Protocol.Min = ProtocolVersion
	}
	if m.Permissions.Network == "" {
		switch m.Class {
		case TargetScan:
			m.Permissions.Network = NetTargets
		case Connector:
			m.Permissions.Network = NetVendor
		default:
			m.Permissions.Network = NetNone
		}
	}
	if m.Permissions.Filesystem == "" {
		m.Permissions.Filesystem = FSWorkdir
	}
	if m.Run != nil && m.Run.Profile == "" {
		run := *m.Run
		run.Profile = ProfileAdapter
		m.Run = &run
	}
	if len(m.Config) > 0 {
		m.Config = withSchemaVersion(m.Config)
	}
	return m
}

// withSchemaVersion adds "x-octm-schema-version": 1 to a schema object that
// has none (the settings schema language requires it).
func withSchemaVersion(raw json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return raw
	}
	if _, ok := obj["x-octm-schema-version"]; ok {
		return raw
	}
	obj["x-octm-schema-version"] = json.RawMessage("1")
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

// Normalized returns the manifest with its defaults filled, as the runtime
// sees it.
func (m Manifest) Normalized() Manifest { return m.withDefaults() }

// Digest is "sha256:" + the hex SHA-256 of the manifest's canonical JSON
// (defaults filled, object members sorted, no insignificant whitespace).
// The runtime compares a tool's self-description with its file by digest,
// and the sensor registers manifests with the platform by digest.
func (m Manifest) Digest() string {
	b, err := m.Canonical()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Canonical is the manifest's canonical JSON.
func (m Manifest) Canonical() ([]byte, error) {
	m = m.withDefaults()
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil { // maps are encoded with sorted keys
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Contract names the manifest in the sensor manifest (core.ToolContract):
// its digest and the fields the platform plans with.
func (m Manifest) Contract() *core.ToolContract {
	m = m.withDefaults()
	var implements []string
	for _, im := range m.Implements {
		implements = append(implements, im.Capability)
	}
	return &core.ToolContract{
		APIVersion: m.APIVersion, Digest: m.Digest(), Version: m.Version, Class: string(m.Class), Tier: string(m.Tier),
		Network: string(m.Permissions.Network), Consumes: slices.Clone(m.Consumes), Produces: slices.Clone(m.Produces),
		Implements: implements, Batch: m.Batches(),
	}
}

// Produce kinds.
const (
	KindAsset      = "asset"
	KindFinding    = "finding"
	KindDependency = "dependency"
)

// Declares reports whether the manifest produces records of kind ("asset",
// "finding", "dependency") and CTIS type typ ("" for dependencies).
func (m Manifest) Declares(kind, typ string) bool {
	want := kind
	if kind != KindDependency {
		want = kind + ":" + typ
	}
	return slices.Contains(m.Produces, want)
}
