package tool

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// APIVersion is the manifest format this package reads and writes.
const APIVersion = "openctem.io/tool/v1"

// ProtocolVersion is the adapter protocol version this SDK speaks.
const ProtocolVersion = 1

// Class is a tool's execution class: what it touches and how the runtime
// dispatches it.
type Class string

// Execution classes.
const (
	// TargetScan touches customer targets (hosts, URLs, repositories).
	TargetScan Class = "target-scan"
	// Connector reads a vendor API with credentials.
	Connector Class = "connector"
	// Parser reads a file and produces records; no network.
	Parser Class = "parser"
	// Enricher annotates findings; it never creates assets.
	Enricher Class = "enricher"
)

// Mode is a sensor mode a tool can run in.
type Mode string

// Modes.
const (
	// Daemon is the long-lived sensor that receives jobs.
	Daemon Mode = "daemon"
	// Runner is the ephemeral CI mode.
	Runner Mode = "runner"
)

// Tier is a tool's intrusiveness.
type Tier string

// Tiers.
const (
	// T0 is passive: the tool reads, it does not probe.
	T0 Tier = "T0"
	// T1 is active and non-intrusive.
	T1 Tier = "T1"
	// T2 is intrusive (allowed for target-scan tools only).
	T2 Tier = "T2"
)

// Network is the network a tool needs.
type Network string

// Network permissions.
const (
	// NetNone: no network at all.
	NetNone Network = "none"
	// NetTargets: the task's targets only, through the zone's egress.
	NetTargets Network = "targets"
	// NetEgressProxy: through the sensor's egress proxy only.
	NetEgressProxy Network = "egress-proxy"
	// NetVendor: the declared vendor hosts only.
	NetVendor Network = "vendor"
)

// Filesystem is what a tool may read besides its private directory.
type Filesystem string

// Filesystem permissions.
const (
	// FSWorkdir: the task's private directory only (the default).
	FSWorkdir Filesystem = "workdir"
	// FSScanRootsReadOnly: also the sensor's scan roots, read-only.
	FSScanRootsReadOnly Filesystem = "scan-roots-read-only"
)

// Run profiles.
const (
	// ProfileAdapter: the program speaks adapter protocol v1.
	ProfileAdapter = "adapter"
	// ProfileExec: a CLI that writes CTIS or SARIF, with no adapter code.
	ProfileExec = "exec"
)

// Output formats of the exec profile.
const (
	OutputCTIS      = "ctis"
	OutputSARIF     = "sarif"
	OutputJSONLCTIS = "jsonl-ctis"
)

// Manifest describes a tool. Its file form is tool.yaml; LoadManifest reads
// it, strictly (an unknown key is an error: the manifest is a security
// document). The runtime trusts the manifest file or the one compiled into
// the sensor, never a tool's description of itself.
type Manifest struct {
	// APIVersion is APIVersion ("" in Go code means APIVersion).
	APIVersion string `json:"apiVersion"`
	// Name is unique per sensor: ^[a-z][a-z0-9-]{1,62}$.
	Name string `json:"name"`
	// Version is the semantic version of the tool adapter (not of the
	// engine it runs).
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	// Publisher is who publishes the tool: the signer of a certified
	// tool, or free text (shown as text, never trusted).
	Publisher string `json:"publisher,omitempty"`
	// License is the SPDX license expression of the adapter (the wrapped
	// engine's is engine.license).
	License string `json:"license,omitempty"`
	// Engine is the program the tool wraps; its version is probed.
	Engine *Engine `json:"engine,omitempty"`
	// Presentation is how the platform shows the tool.
	Presentation *Presentation `json:"presentation,omitempty"`
	Class        Class         `json:"class"`
	// Modes the tool runs in; empty means both.
	Modes []Mode `json:"modes,omitempty"`
	// Tier is the tier the tool asks for. It cannot be below the tier
	// floor of a capability it implements; the platform assigns the
	// effective tier and may raise it (MinimumTier).
	Tier Tier `json:"tier"`
	// Implements are the capabilities of the OpenCTEM capability taxonomy
	// the tool implements ("scan.ports@1"), with its param mapping.
	Implements []Implementation `json:"implements,omitempty"`
	// Capabilities is the older free-form capability list. Deprecated:
	// use Implements. With Implements set it may only repeat its ids.
	Capabilities []string `json:"capabilities,omitempty"`
	// Consumes are CTIS asset types, "file:<media type>" for parsers, or
	// "finding:<type>" for enrichers.
	Consumes []string `json:"consumes,omitempty"`
	// Produces are "asset:<type>", "finding:<type>" or "dependency". A
	// record of any other kind is refused (ErrUndeclaredOutput).
	Produces []string `json:"produces"`
	// Input is how the tool takes its targets (default: one per task).
	Input *InputSpec `json:"input,omitempty"`
	// Config is the tool's configuration schema: the closed JSON Schema
	// subset of api RFC-038 (pkg/core settings schemas), with no secret
	// fields (secrets are credentials, never configuration). nil: no
	// configuration (New derives one from the config type when it has
	// fields).
	Config      json.RawMessage `json:"config,omitempty"`
	Permissions Permissions     `json:"permissions"`
	Resources   Resources       `json:"resources"`
	// Safety is what the tool does to its targets beyond reading them.
	Safety *Safety `json:"safety,omitempty"`
	// Features are the optional protocol features the tool supports.
	Features *Features `json:"features,omitempty"`
	// HTTP is how the tool's requests to its targets look (user agent,
	// headers, timeout, TLS): applied by ctx.HTTP(), named in exec argv
	// ({{http.user_agent}}) and readable by an adapter from its manifest.
	HTTP *HTTPSpec `json:"http,omitempty"`
	// Selftest are fixtures: a task and the CTIS it must produce.
	Selftest []Fixture `json:"selftest,omitempty"`
	// Retest says the tool can check again what it reported (a retest
	// task, see Retester). Target-scan tools only. Deprecated spelling of
	// features.retest.
	Retest bool `json:"retest,omitempty"`
	// Protocol is the range of adapter protocol versions the tool speaks.
	Protocol Range `json:"protocol"`
	// Run says how to start a tool that is not compiled into the sensor.
	Run *RunSpec `json:"run,omitempty"`
	// SDK is the oldest SDK that understands every key this manifest uses.
	SDK *SDKRequirement `json:"sdk,omitempty"`
	// Deprecated marks a tool being replaced.
	Deprecated *Deprecation `json:"deprecated,omitempty"`
}

// Permissions are what a tool needs. The effective permission is the
// manifest's intersected with the sensor's policy and the job.
type Permissions struct {
	// Network defaults by class: none for parsers and enrichers, targets
	// for target scans, vendor for connectors.
	Network Network `json:"network,omitempty"`
	// VendorHosts are the hosts a vendor-network tool may reach
	// ("api.example.com", "api.example.com:8443", or "${config.<key>}" for
	// a string configuration key holding a URL or host).
	VendorHosts []string   `json:"vendor_hosts,omitempty"`
	Filesystem  Filesystem `json:"filesystem,omitempty"`
	// Credentials the tool may receive. Only these are ever delivered,
	// and only when the sensor's operator stored them.
	Credentials []CredentialReq `json:"credentials,omitempty"`
	// LinuxCaps the tool needs (NET_RAW for SYN scans); granted only when
	// the local policy allows.
	LinuxCaps []string `json:"linux_caps,omitempty"`
	// Proxy is ProxyHonours or ProxyIgnores; unset is unknown, which the
	// platform treats as ignores where a zone requires a proxy.
	Proxy string `json:"proxy,omitempty"`
}

// CredentialReq is a credential a tool declares.
type CredentialReq struct {
	// Name is how the tool asks for it (Context.Secret).
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}

// Credential kinds.
var credentialKinds = []string{"api_key", "token", "password", "basic", "private_key", "certificate", "other"}

// Resources bound one task of the tool. Zero fields take the runtime's
// defaults.
type Resources struct {
	CPU            float64  `json:"cpu,omitempty"`
	Memory         ByteSize `json:"memory,omitempty"`
	Timeout        Duration `json:"timeout,omitempty"`
	IdleTimeout    Duration `json:"idle_timeout,omitempty"`
	MaxOutputBytes ByteSize `json:"max_output_bytes,omitempty"`
	MaxRecords     int      `json:"max_records,omitempty"`
	// Cost is the slot cost for the sensor's capacity model.
	Cost int `json:"cost,omitempty"`
}

// Defaults of Resources.
const (
	DefaultTimeout        = 60 * time.Minute
	DefaultIdleTimeout    = 10 * time.Minute
	DefaultMaxOutputBytes = 64 << 20
	DefaultMaxRecords     = 200000
)

// Limits are the effective bounds of one task.
func (r Resources) Limits() (timeout, idle time.Duration, maxBytes int64, maxRecords int) {
	timeout, idle = time.Duration(r.Timeout), time.Duration(r.IdleTimeout)
	maxBytes, maxRecords = int64(r.MaxOutputBytes), r.MaxRecords
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxOutputBytes
	}
	if maxRecords <= 0 {
		maxRecords = DefaultMaxRecords
	}
	return timeout, idle, maxBytes, maxRecords
}

// Fixture is one self-test: a task file and the CTIS it must produce, both
// relative to the manifest's directory.
type Fixture struct {
	Name   string `json:"name"`
	Task   string `json:"task"`
	Expect string `json:"expect"`
}

// Range is a range of protocol versions (Max 0: no upper bound).
type Range struct {
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
}

// RunSpec says how the runtime starts a tool that is its own program.
type RunSpec struct {
	// Profile is ProfileAdapter (default) or ProfileExec.
	Profile string `json:"profile,omitempty"`
	// Argv is the program and its arguments. Never a shell. Placeholders
	// are a closed set: {{config.<key>}} (a scalar key of the config
	// schema), {{target.value}}, {{target.host}}, {{target.port}},
	// {{target.url}}, {{task.targets_file}}, {{task.targets_json}},
	// {{task.config_file}}, {{task.web_scope_file}}, {{task.output}},
	// {{task.workdir}}.
	Argv []string `json:"argv"`
	// Output is where an exec-profile tool writes its results.
	Output *OutputSpec `json:"output,omitempty"`
	// ExitCodes maps an exec-profile tool's exit codes to outcomes
	// ("ok", "partial") or error classes; default: 0 ok, else tool_error.
	ExitCodes map[string]string `json:"exit_codes,omitempty"`
}

// OutputSpec is an exec-profile tool's output.
type OutputSpec struct {
	// Format is OutputCTIS, OutputSARIF, OutputJSONLCTIS, OutputJSON or
	// OutputJSONL (with Mapping), or a named format of ctis/importer
	// (ImporterFormats: "nuclei", "trivy", "cyclonedx", ...).
	Format string `json:"format"`
	// From is "stdout" or "file" (the {{task.output}} path).
	From string `json:"from"`
	// Mapping is the mapping file (relative to the manifest's directory)
	// that turns json or jsonl output into CTIS: the declarative mapping
	// language of ctis/importer/mapping, in JSON or YAML.
	Mapping string `json:"mapping,omitempty"`
	// MappingDigest is the mapping's digest, set when the manifest file is
	// loaded (LoadManifestFile); the manifest digest covers it, and the
	// runtime refuses a mapping file that no longer matches it.
	MappingDigest string `json:"mapping_digest,omitempty"`
}

// ByteSize is a size in bytes; in a manifest a number or a string with a
// binary or decimal suffix ("512Mi", "1Gi", "64MB").
type ByteSize int64

// UnmarshalJSON reads a number or a size string.
func (b *ByteSize) UnmarshalJSON(data []byte) error {
	var n int64
	if err := json.Unmarshal(data, &n); err == nil {
		*b = ByteSize(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("size must be a number or a string such as \"512Mi\"")
	}
	v, err := ParseByteSize(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// ParseByteSize reads "1024", "512Ki", "512Mi", "1Gi", "64MB", "1G".
func ParseByteSize(s string) (ByteSize, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{
		{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
		{"K", 1000}, {"M", 1000 * 1000}, {"G", 1000 * 1000 * 1000}, {"B", 1},
	}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			mult, s = u.mult, strings.TrimSuffix(s, u.suffix)
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return ByteSize(n * mult), nil
}

// Duration is a time.Duration; in a manifest a string such as "20m" or a
// number of seconds.
type Duration time.Duration

// UnmarshalJSON reads "20m", "1h30m" or a number of seconds.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var n float64
	if err := json.Unmarshal(data, &n); err == nil {
		*d = Duration(time.Duration(n * float64(time.Second)))
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"20m\" or a number of seconds")
	}
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON writes the duration as a string ("20m0s").
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}
