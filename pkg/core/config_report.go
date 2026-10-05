package core

// The sensor config report (OpenCTEM research/26, documented in api
// docs/rfcs/RFC-033-sensor-manifest.md, "Config report"): the results of
// the sensor's preflight checks, each with a stable id, a status, a typed
// reason and typed parameters, and the presence (never the value) of every
// declared setting. A BaseSensor sends it to a platform that lists the
// "config_report" feature (PUT /api/v2/sensor/config-report) when it
// changes or the platform asks, and every heartbeat carries its digest.
//
// The platform explains each check from its own catalog; the free text here
// (summary, excerpt) is only data. Everything is bounded and scrubbed of
// secrets before it leaves the host (ConfigReport.Finalize).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ConfigReportSchema is the config report document version this SDK writes.
const ConfigReportSchema = 1

// MaxConfigReportBytes is the most a config report may weigh on the wire
// (the platform answers 413 above it).
const MaxConfigReportBytes = 64 << 10

// Limits of a config report.
const (
	MaxConfigChecks      = 200
	MaxConfigSettings    = 300
	MaxConfigParams      = 16
	MaxConfigKeys        = 8
	MaxConfigBlocks      = 8
	MaxConfigNames       = 8
	MaxConfigSummaryLen  = 300
	MaxConfigExcerptLen  = 512
	maxConfigPathLen     = 256
	maxConfigHostLen     = 253
	maxConfigCheckIDLen  = 96
	maxConfigParamInt    = 1_000_000_000_000
	configRedactedMarker = "****"
)

// Check statuses.
const (
	CheckPass  = "pass"
	CheckWarn  = "warn"
	CheckFail  = "fail"
	CheckSkip  = "skip"
	CheckError = "error"
)

// Check severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Config health rollups.
const (
	ConfigHealthOK        = "ok"
	ConfigHealthAttention = "attention"
	ConfigHealthImpaired  = "impaired"
	ConfigHealthBlocked   = "blocked"
)

// Report triggers.
const (
	ConfigTriggerStart     = "start"
	ConfigTriggerChange    = "change"
	ConfigTriggerRequested = "requested"
)

// Runtime kinds.
const (
	RuntimeDocker     = "docker"
	RuntimeKubernetes = "kubernetes"
	RuntimeSystemd    = "systemd"
	RuntimeBinary     = "binary"
	RuntimeUnknown    = "unknown"
)

// Blocks: what a failed check keeps the sensor from doing.
const (
	BlockAll             = "role:*"
	BlockScan            = "role:scan"
	BlockPrivateTargets  = "target:private"
	BlockCustomTemplates = "feature:custom_templates"
)

// BlockTool is the block of one tool.
func BlockTool(name string) string { return "tool:" + name }

// HeartbeatActionSendConfigReport: the platform does not have the config
// report this sensor's heartbeat names; send it again.
const HeartbeatActionSendConfigReport HeartbeatAction = "send_config_report"

// ErrConfigReportUnsupported is returned by ConfigReportPusher.PutConfigReport
// when the platform does not take config reports (no "config_report" on
// hello). The sensor then sends none.
var ErrConfigReportUnsupported = errors.New("the platform does not accept sensor config reports")

// ConfigReport is the document (schema 1).
type ConfigReport struct {
	Schema       int             `json:"schema"`
	ObservedAt   string          `json:"observed_at"`
	Trigger      string          `json:"trigger"`
	Runtime      ConfigRuntime   `json:"runtime"`
	ConfigHealth string          `json:"config_health"`
	Checks       []ConfigCheck   `json:"checks"`
	Settings     []ConfigSetting `json:"settings"`
	Truncated    bool            `json:"truncated"`
}

// ConfigRuntime is how the sensor runs (docker, kubernetes, systemd,
// binary): the platform preselects the matching fix snippet.
type ConfigRuntime struct {
	Kind string `json:"kind"`
}

// ConfigCheck is one check result.
type ConfigCheck struct {
	ID       string                 `json:"id"`
	Status   string                 `json:"status"`
	Severity string                 `json:"severity"`
	Code     string                 `json:"code"`
	Params   map[string]ConfigParam `json:"params,omitempty"`
	Keys     []string               `json:"keys,omitempty"`
	Summary  string                 `json:"summary,omitempty"`
	Excerpt  string                 `json:"excerpt,omitempty"`
	Blocks   []string               `json:"blocks,omitempty"`
}

// ConfigParam is a typed parameter: exactly one member is set.
type ConfigParam struct {
	Int     *int64   `json:"int,omitempty"`
	Bool    *bool    `json:"bool,omitempty"`
	Enum    string   `json:"enum,omitempty"`
	Path    string   `json:"path,omitempty"`
	Host    string   `json:"host,omitempty"`
	Version string   `json:"version,omitempty"`
	Name    string   `json:"name,omitempty"`
	Names   []string `json:"names,omitempty"`
}

// ParamInt and the functions below build typed parameters.
func ParamInt(n int64) ConfigParam      { return ConfigParam{Int: &n} }
func ParamBool(b bool) ConfigParam      { return ConfigParam{Bool: &b} }
func ParamEnum(s string) ConfigParam    { return ConfigParam{Enum: s} }
func ParamPath(s string) ConfigParam    { return ConfigParam{Path: s} }
func ParamHost(s string) ConfigParam    { return ConfigParam{Host: s} }
func ParamVersion(s string) ConfigParam { return ConfigParam{Version: s} }
func ParamName(s string) ConfigParam    { return ConfigParam{Name: s} }
func ParamNames(s ...string) ConfigParam {
	return ConfigParam{Names: slices.Clone(s)}
}

// ConfigSetting is a declared setting's presence: set or not, where it came
// from, whether it is a secret and whether its value is valid. It has no
// value member: values never leave the host.
type ConfigSetting struct {
	Name   string `json:"name"`
	Set    bool   `json:"set"`
	Source string `json:"source"`
	Secret bool   `json:"secret"`
	Valid  bool   `json:"valid"`
}

// ConfigReportSummary is what every heartbeat says about the report: the
// digest the platform returned for it, the rollup and the counts.
type ConfigReportSummary struct {
	Digest     string `json:"digest"`
	Health     string `json:"health"`
	Fail       int    `json:"fail"`
	Warn       int    `json:"warn"`
	ObservedAt string `json:"observed_at"`
}

// ConfigReportAck is the platform's answer to a config report.
type ConfigReportAck struct {
	Digest  string
	Changed bool
	Ignored []ManifestIgnored
}

// ConfigReportPusher is implemented by a Pusher that can send a config
// report (client.Client on protocol v2).
type ConfigReportPusher interface {
	PutConfigReport(ctx context.Context, r *ConfigReport) (*ConfigReportAck, error)
}

var (
	configCheckIDRE   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_-]+){1,3}$`)
	configCodeRE      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	configParamKeyRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	configEnumRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
	configNameRE      = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	configVersionRE   = regexp.MustCompile(`^v?[0-9A-Za-z.+-]{1,64}$`)
	configBlockToolRE = regexp.MustCompile(`^tool:[a-z0-9][a-z0-9._-]{0,63}$`)
	configHostnameRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)
	// userinfoRE finds credentials in a URL ("scheme://user:pass@host").
	userinfoRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)
)

// Finalize makes r safe to send: it drops what does not fit the schema,
// scrubs every secret value and every URL's credentials from all text,
// bounds each field, recomputes the health rollup and, when the document
// is still larger than maxBytes (MaxConfigReportBytes when <= 0), drops the
// settings, then passing checks, then the least severe checks, marking it
// truncated. secrets are the values to scrub (the registry's secret
// settings, the API key in use).
func (r *ConfigReport) Finalize(secrets []string, maxBytes int) {
	if maxBytes <= 0 {
		maxBytes = MaxConfigReportBytes
	}
	r.Schema = ConfigReportSchema
	if r.Runtime.Kind == "" {
		r.Runtime.Kind = RuntimeUnknown
	}
	scrub := newScrubber(secrets)
	checks := make([]ConfigCheck, 0, len(r.Checks))
	for _, c := range r.Checks {
		if cc, ok := cleanCheck(c, scrub); ok {
			checks = append(checks, cc)
		}
	}
	sortChecks(checks)
	if len(checks) > MaxConfigChecks {
		checks, r.Truncated = checks[:MaxConfigChecks], true
	}
	r.Checks = checks
	settings := make([]ConfigSetting, 0, len(r.Settings))
	for _, s := range r.Settings {
		if !configNameRE.MatchString(s.Name) {
			continue
		}
		switch s.Source {
		case "env", "option", "default", "unset":
		default:
			s.Source = "unset"
		}
		settings = append(settings, s)
	}
	if len(settings) > MaxConfigSettings {
		settings, r.Truncated = settings[:MaxConfigSettings], true
	}
	r.Settings = settings
	r.ConfigHealth = ConfigHealthOf(r.Checks)
	r.fit(maxBytes)
}

// fit drops settings, then passing and skipped checks, then the least
// severe remaining checks until the document fits.
func (r *ConfigReport) fit(maxBytes int) {
	size := func() int { b, _ := json.Marshal(r); return len(b) }
	if size() <= maxBytes {
		return
	}
	r.Truncated = true
	r.Settings = []ConfigSetting{}
	for size() > maxBytes && len(r.Checks) > 0 {
		// Checks are sorted most important first: drop from the end.
		r.Checks = r.Checks[:len(r.Checks)-1]
	}
}

// statusRank orders statuses most important first.
func statusRank(s string) int {
	switch s {
	case CheckFail:
		return 0
	case CheckError:
		return 1
	case CheckWarn:
		return 2
	case CheckSkip:
		return 3
	default:
		return 4
	}
}

func sortChecks(cs []ConfigCheck) {
	sort.SliceStable(cs, func(i, j int) bool {
		if a, b := statusRank(cs[i].Status), statusRank(cs[j].Status); a != b {
			return a < b
		}
		return cs[i].ID < cs[j].ID
	})
}

// ConfigHealthOf is the rollup: blocked (a failure that blocks everything),
// impaired (any other failure or a check that could not run), attention (a
// warning of severity warning or critical), else ok.
func ConfigHealthOf(checks []ConfigCheck) string {
	health := ConfigHealthOK
	for _, c := range checks {
		switch c.Status {
		case CheckFail:
			if slices.Contains(c.Blocks, BlockAll) {
				return ConfigHealthBlocked
			}
			health = ConfigHealthImpaired
		case CheckError:
			health = ConfigHealthImpaired
		case CheckWarn:
			if health == ConfigHealthOK && c.Severity != SeverityInfo {
				health = ConfigHealthAttention
			}
		}
	}
	return health
}

// Counts returns the failed and warning checks.
func (r *ConfigReport) Counts() (fail, warn int) {
	for _, c := range r.Checks {
		switch c.Status {
		case CheckFail, CheckError:
			fail++
		case CheckWarn:
			warn++
		}
	}
	return fail, warn
}

// Digest is "sha256:" + the hex SHA-256 of the report's canonical JSON
// (object members sorted, no whitespace, no HTML escaping) with observed_at
// and trigger emptied: the same state rebuilt later has the same digest.
func (r *ConfigReport) Digest() (string, error) {
	cp := *r
	cp.ObservedAt, cp.Trigger = "", ""
	raw, err := json.Marshal(cp)
	if err != nil {
		return "", fmt.Errorf("encode config report: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("decode config report: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("encode config report: %w", err)
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Summary is the heartbeat form of r under the platform's digest.
func (r *ConfigReport) Summary(platformDigest string) *ConfigReportSummary {
	fail, warn := r.Counts()
	return &ConfigReportSummary{Digest: platformDigest, Health: r.ConfigHealth, Fail: fail, Warn: warn, ObservedAt: r.ObservedAt}
}

// scrubber removes secret values and URL credentials from text.
type scrubber struct{ secrets []string }

func newScrubber(secrets []string) scrubber {
	var s []string
	for _, v := range secrets {
		if v = strings.TrimSpace(v); v != "" {
			s = append(s, v)
		}
	}
	// Longest first, so a secret that contains another is removed whole.
	sort.Slice(s, func(i, j int) bool { return len(s[i]) > len(s[j]) })
	return scrubber{secrets: s}
}

func (s scrubber) text(v string) string {
	for _, sec := range s.secrets {
		if strings.Contains(v, sec) {
			v = strings.ReplaceAll(v, sec, configRedactedMarker)
		}
	}
	return userinfoRE.ReplaceAllString(v, "${1}"+configRedactedMarker+"@")
}

// contains reports whether v holds any secret (a parameter that does is
// dropped whole rather than shown redacted).
func (s scrubber) contains(v string) bool {
	for _, sec := range s.secrets {
		if strings.Contains(v, sec) {
			return true
		}
	}
	return false
}

func cleanCheck(c ConfigCheck, scrub scrubber) (ConfigCheck, bool) {
	if len(c.ID) > maxConfigCheckIDLen || !configCheckIDRE.MatchString(c.ID) {
		return ConfigCheck{}, false
	}
	switch c.Status {
	case CheckPass, CheckWarn, CheckFail, CheckSkip, CheckError:
	default:
		return ConfigCheck{}, false
	}
	switch c.Severity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	case "":
		c.Severity = defaultSeverity(c.Status)
	default:
		return ConfigCheck{}, false
	}
	if !configCodeRE.MatchString(c.Code) {
		return ConfigCheck{}, false
	}
	out := ConfigCheck{ID: c.ID, Status: c.Status, Severity: c.Severity, Code: c.Code}
	if len(c.Params) > 0 {
		keys := make([]string, 0, len(c.Params))
		for k := range c.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if len(out.Params) == MaxConfigParams {
				break
			}
			if !configParamKeyRE.MatchString(k) {
				continue
			}
			if p, ok := cleanParam(c.Params[k], scrub); ok {
				if out.Params == nil {
					out.Params = map[string]ConfigParam{}
				}
				out.Params[k] = p
			}
		}
	}
	for _, k := range c.Keys {
		if len(out.Keys) < MaxConfigKeys && configNameRE.MatchString(k) && !slices.Contains(out.Keys, k) {
			out.Keys = append(out.Keys, k)
		}
	}
	for _, b := range c.Blocks {
		if len(out.Blocks) < MaxConfigBlocks && validBlock(b) && !slices.Contains(out.Blocks, b) {
			out.Blocks = append(out.Blocks, b)
		}
	}
	out.Summary = boundText(scrub.text(c.Summary), MaxConfigSummaryLen)
	out.Excerpt = boundText(scrub.text(c.Excerpt), MaxConfigExcerptLen)
	return out, true
}

func defaultSeverity(status string) string {
	switch status {
	case CheckFail, CheckError:
		return SeverityCritical
	case CheckWarn:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

func validBlock(b string) bool {
	switch b {
	case BlockAll, BlockScan, BlockPrivateTargets, BlockCustomTemplates:
		return true
	}
	return configBlockToolRE.MatchString(b)
}

// cleanParam keeps a parameter with exactly one valid member.
func cleanParam(p ConfigParam, scrub scrubber) (ConfigParam, bool) {
	n := 0
	for _, set := range []bool{p.Int != nil, p.Bool != nil, p.Enum != "", p.Path != "", p.Host != "",
		p.Version != "", p.Name != "", p.Names != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return ConfigParam{}, false
	}
	switch {
	case p.Int != nil:
		if *p.Int > maxConfigParamInt || *p.Int < -maxConfigParamInt {
			return ConfigParam{}, false
		}
		return ParamInt(*p.Int), true
	case p.Bool != nil:
		return ParamBool(*p.Bool), true
	case p.Enum != "":
		return p, configEnumRE.MatchString(p.Enum)
	case p.Path != "":
		return p, validConfigPath(p.Path) && !scrub.contains(p.Path)
	case p.Host != "":
		return p, validConfigHost(p.Host) && !scrub.contains(p.Host)
	case p.Version != "":
		return p, configVersionRE.MatchString(p.Version)
	case p.Name != "":
		return p, configNameRE.MatchString(p.Name) && !scrub.contains(p.Name)
	default:
		var names []string
		for _, v := range p.Names {
			if len(names) < MaxConfigNames && configNameRE.MatchString(v) && !scrub.contains(v) {
				names = append(names, v)
			}
		}
		if len(names) == 0 {
			return ConfigParam{}, false
		}
		return ConfigParam{Names: names}, true
	}
}

func validConfigPath(p string) bool {
	if len(p) > maxConfigPathLen || !strings.HasPrefix(p, "/") || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) || isBidi(r) {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return path.Clean(p) != ""
}

func validConfigHost(h string) bool {
	if len(h) > maxConfigHostLen {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	return configHostnameRE.MatchString(h)
}

// isBidi reports the Unicode bidirectional controls that can reorder text
// (Trojan Source).
func isBidi(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C:
		return true
	}
	return false
}

// boundText strips control characters (keeping newlines and tabs) and bidi
// controls, and caps the text at max bytes on a rune boundary.
func boundText(s string, maxLen int) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "") {
		if isBidi(r) || (unicode.IsControl(r) && r != '\n' && r != '\t') {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxLen {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// DetectRuntime says how this process runs: kubernetes, docker (any
// container engine), systemd, else binary.
func DetectRuntime() string {
	switch {
	case os.Getenv("KUBERNETES_SERVICE_HOST") != "":
		return RuntimeKubernetes
	case fileExists("/.dockerenv"), fileExists("/run/.containerenv"):
		return RuntimeDocker
	case os.Getenv("INVOCATION_ID") != "":
		return RuntimeSystemd
	default:
		return RuntimeBinary
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// NowRFC3339 is the report timestamp format.
func NowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
