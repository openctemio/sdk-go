package tool

import (
	"fmt"
	"net"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

var (
	nameRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	versionRE    = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]{1,64})?(\+[0-9A-Za-z.-]{1,64})?$`)
	capabilityRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	mediaTypeRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$`)
	credNameRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	hostRE       = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)
	configRefRE  = regexp.MustCompile(`^\$\{config\.([a-z][a-z0-9_]{0,63})\}$`)
	placeholder  = regexp.MustCompile(`\{\{\s*([^{}]*?)\s*\}\}`)
	secretNameRE = regexp.MustCompile(`(^|_)(password|passwd|secret|api_?key|token|private_key|credentials?)($|_)`)
)

// Limits of a manifest.
const (
	maxListItems   = 64
	maxDescription = 1024
	maxArgv        = 64
	maxArgLen      = 4096
	maxCredentials = 16
	maxMemory      = 64 << 30
	maxTimeout     = 24 * time.Hour
	maxOutputBytes = 1 << 30
	maxRecords     = 10000000
	maxCost        = 64
)

// Placeholders an argv may use besides {{config.<key>}}.
var argvPlaceholders = []string{
	"target.value", "target.host", "target.port", "target.url",
	"task.targets_file", "task.targets_json", "task.config_file", "task.output", "task.workdir",
}

// Programs an argv may not start: a shell or an interpreter given code on
// the command line would turn placeholders into code.
var refusedPrograms = []string{"sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "csh", "tcsh", "fish",
	"busybox", "env", "eval", "xargs", "sudo", "su", "doas", "cmd", "cmd.exe", "powershell", "pwsh"}

// Linux capabilities a manifest may request.
var allowedCaps = []string{"NET_RAW", "NET_BIND_SERVICE"}

// Exit-code outcomes of the exec profile.
var exitOutcomes = []string{"ok", "partial", string(ToolError), string(InvalidInput), string(TargetUnreachable), string(Transient)}

// Validate checks the manifest: identity, class against permissions and
// tier, consumes/produces from the CTIS vocabulary, a configuration
// schema in the settings subset with no secret fields, resources within
// bounds, and a run specification with a closed set of placeholders and
// no shell. The error is ManifestErrors with every problem.
func (m Manifest) Validate() error {
	m = m.withDefaults()
	var errs ManifestErrors
	add := func(p, format string, args ...any) {
		errs = append(errs, ManifestError{Path: p, Message: fmt.Sprintf(format, args...)})
	}
	if m.APIVersion != APIVersion {
		add("/apiVersion", "must be %q", APIVersion)
	}
	if !nameRE.MatchString(m.Name) {
		add("/name", "must match ^[a-z][a-z0-9-]{1,62}$")
	}
	if !versionRE.MatchString(m.Version) {
		add("/version", "must be a semantic version (1.2.3)")
	}
	if len(m.Description) > maxDescription {
		add("/description", "longer than %d bytes", maxDescription)
	}
	validClass := slices.Contains([]Class{TargetScan, Connector, Parser, Enricher}, m.Class)
	if !validClass {
		add("/class", "must be target-scan, connector, parser or enricher")
	}
	for i, md := range m.Modes {
		if md != Daemon && md != Runner {
			add(fmt.Sprintf("/modes/%d", i), "must be daemon or runner")
		}
		if slices.Index(m.Modes, md) != i {
			add(fmt.Sprintf("/modes/%d", i), "duplicate")
		}
	}
	switch m.Tier {
	case T0, T1:
	case T2:
		if m.Class != TargetScan {
			add("/tier", "T2 (intrusive) is allowed for target-scan tools only")
		}
	default:
		add("/tier", "must be T0, T1 or T2")
	}
	checkList(add, "/capabilities", m.Capabilities, func(s string) string {
		if !capabilityRE.MatchString(s) {
			return "must match ^[a-z0-9][a-z0-9._:-]{0,63}$"
		}
		return ""
	})
	checkList(add, "/consumes", m.Consumes, func(s string) string { return checkConsumes(m.Class, s) })
	if len(m.Produces) == 0 {
		add("/produces", "must declare at least one output type")
	}
	checkList(add, "/produces", m.Produces, func(s string) string { return checkProduces(m.Class, s) })
	if m.Retest && m.Class != TargetScan {
		add("/retest", "only target-scan tools retest")
	}
	if m.Retest && m.Run != nil && m.Run.Profile == ProfileExec {
		add("/retest", "an exec-profile tool cannot retest (it has no verdict channel)")
	}
	schema := m.validateConfig(add)
	m.validatePermissions(add, schema)
	m.validateContract(add, schema)
	m.validateResources(add)
	if m.Protocol.Min > ProtocolVersion {
		add("/protocol/min", "this SDK speaks adapter protocol %d", ProtocolVersion)
	}
	if m.Protocol.Max != 0 && m.Protocol.Max < m.Protocol.Min {
		add("/protocol/max", "below min")
	}
	if len(m.Selftest) > maxListItems {
		add("/selftest", "more than %d fixtures", maxListItems)
	}
	for i, f := range m.Selftest {
		p := fmt.Sprintf("/selftest/%d", i)
		if f.Name == "" {
			add(p+"/name", "required")
		}
		for k, v := range map[string]string{"task": f.Task, "expect": f.Expect} {
			if msg := checkRelPath(v); msg != "" {
				add(p+"/"+k, "%s", msg)
			}
		}
	}
	if m.Run != nil {
		m.validateRun(add, schema)
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

func checkList(add func(p, format string, args ...any), p string, list []string, check func(string) string) {
	if len(list) > maxListItems {
		add(p, "more than %d entries", maxListItems)
		return
	}
	for i, s := range list {
		if msg := check(s); msg != "" {
			add(fmt.Sprintf("%s/%d", p, i), "%s", msg)
		}
		if slices.Index(list, s) != i {
			add(fmt.Sprintf("%s/%d", p, i), "duplicate")
		}
	}
}

func checkConsumes(c Class, s string) string {
	switch {
	case strings.HasPrefix(s, "file:"):
		if c != Parser {
			return "file inputs are for parsers only"
		}
		if !mediaTypeRE.MatchString(strings.TrimPrefix(s, "file:")) {
			return "file: must name a media type (file:application/sarif+json)"
		}
	case strings.HasPrefix(s, KindFinding+":"):
		if c != Enricher {
			return "findings are consumed by enrichers only"
		}
		if !ctis.FindingType(strings.TrimPrefix(s, KindFinding+":")).IsValid() {
			return "unknown CTIS finding type"
		}
	default:
		if c == Parser || c == Enricher {
			return "a " + string(c) + " consumes " + map[Class]string{Parser: "file:<media type>", Enricher: "finding:<type>"}[c]
		}
		if !ctis.AssetType(s).IsValid() {
			return "unknown CTIS asset type"
		}
	}
	return ""
}

func checkProduces(c Class, s string) string {
	kind, typ, _ := strings.Cut(s, ":")
	switch kind {
	case KindAsset:
		if c == Enricher {
			return "an enricher never creates assets"
		}
		if !ctis.AssetType(typ).IsValid() {
			return "unknown CTIS asset type"
		}
	case KindFinding:
		if !ctis.FindingType(typ).IsValid() {
			return "unknown CTIS finding type"
		}
	case KindDependency:
		if typ != "" || s != KindDependency {
			return `must be exactly "dependency"`
		}
		if c == Enricher {
			return "an enricher produces findings only"
		}
	default:
		return `must be "asset:<type>", "finding:<type>" or "dependency"`
	}
	return ""
}

// ConfigSchema parses the configuration schema (nil when there is none).
func (m Manifest) ConfigSchema() (*core.SettingsSchema, error) {
	m = m.withDefaults()
	if len(m.Config) == 0 {
		return nil, nil
	}
	return core.ParseSettingsSchema(m.Config)
}

func (m Manifest) validateConfig(add func(p, format string, args ...any)) *core.SettingsSchema {
	schema, err := m.ConfigSchema()
	if err != nil {
		add("/config", "%v", err)
		return nil
	}
	if schema == nil {
		return nil
	}
	var walk func(prefix string, props []*core.SettingProperty)
	walk = func(prefix string, props []*core.SettingProperty) {
		for _, p := range props {
			ptr := prefix + "/properties/" + p.Name
			if p.Sensitive || p.WriteOnly {
				add(ptr, "secrets are credentials (permissions.credentials), never configuration")
			}
			if secretNameRE.MatchString(p.Name) {
				add(ptr, "a key named like a secret; declare a credential instead")
			}
			walk(ptr, p.Properties)
		}
	}
	walk("/config", schema.Properties)
	return schema
}

func (m Manifest) validatePermissions(add func(p, format string, args ...any), schema *core.SettingsSchema) {
	p := m.Permissions
	switch p.Network {
	case NetNone:
	case NetTargets, NetEgressProxy:
		if m.Class != TargetScan {
			add("/permissions/network", "%s is for target-scan tools only", p.Network)
		}
	case NetVendor:
		if m.Class == TargetScan || m.Class == Parser {
			add("/permissions/network", "vendor is for connectors and enrichers")
		}
		if len(p.VendorHosts) == 0 {
			add("/permissions/vendor_hosts", "a vendor-network tool must name its hosts")
		}
	default:
		add("/permissions/network", "must be none, targets, egress-proxy or vendor")
	}
	if m.Class == Connector && p.Network != NetVendor {
		add("/permissions/network", "a connector must use vendor with its hosts")
	}
	if p.Network != NetVendor && len(p.VendorHosts) > 0 {
		add("/permissions/vendor_hosts", "only for network: vendor")
	}
	checkList(add, "/permissions/vendor_hosts", p.VendorHosts, func(h string) string { return checkVendorHost(h, schema) })
	switch p.Filesystem {
	case FSWorkdir:
	case FSScanRootsReadOnly:
		if m.Class != TargetScan && m.Class != Parser {
			add("/permissions/filesystem", "scan roots are for target-scan tools and parsers")
		}
	default:
		add("/permissions/filesystem", "must be workdir or scan-roots-read-only")
	}
	if len(p.Credentials) > maxCredentials {
		add("/permissions/credentials", "more than %d credentials", maxCredentials)
	}
	for i, c := range p.Credentials {
		ptr := fmt.Sprintf("/permissions/credentials/%d", i)
		if !credNameRE.MatchString(c.Name) {
			add(ptr+"/name", "must match ^[a-z][a-z0-9_]{0,63}$")
		}
		if slices.IndexFunc(p.Credentials, func(o CredentialReq) bool { return o.Name == c.Name }) != i {
			add(ptr+"/name", "duplicate")
		}
		if !slices.Contains(credentialKinds, c.Kind) {
			add(ptr+"/kind", "must be one of %s", strings.Join(credentialKinds, ", "))
		}
		if len(c.Description) > maxDescription {
			add(ptr+"/description", "longer than %d bytes", maxDescription)
		}
	}
	for i, c := range p.LinuxCaps {
		if !slices.Contains(allowedCaps, c) {
			add(fmt.Sprintf("/permissions/linux_caps/%d", i), "must be one of %s", strings.Join(allowedCaps, ", "))
		}
	}
}

func checkVendorHost(h string, schema *core.SettingsSchema) string {
	if mm := configRefRE.FindStringSubmatch(h); mm != nil {
		if schema == nil {
			return "names a config key but the tool has no config"
		}
		prop := schema.Property(mm[1])
		if prop == nil || prop.Type != "string" {
			return "must name a string config key"
		}
		return ""
	}
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		host, port = h, ""
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "invalid port"
		}
	}
	if net.ParseIP(host) == nil && !hostRE.MatchString(host) {
		return "must be a host name, host:port or ${config.<key>}"
	}
	return ""
}

func (m Manifest) validateResources(add func(p, format string, args ...any)) {
	r := m.Resources
	if r.CPU < 0 || r.CPU > 256 {
		add("/resources/cpu", "must be between 0 and 256")
	}
	if r.Memory < 0 || r.Memory > maxMemory {
		add("/resources/memory", "must be between 0 and 64Gi")
	}
	if r.Timeout < 0 || time.Duration(r.Timeout) > maxTimeout {
		add("/resources/timeout", "must be between 0 and 24h")
	}
	if r.IdleTimeout < 0 || (r.Timeout > 0 && r.IdleTimeout > r.Timeout) {
		add("/resources/idle_timeout", "must be between 0 and the timeout")
	}
	if r.MaxOutputBytes < 0 || r.MaxOutputBytes > maxOutputBytes {
		add("/resources/max_output_bytes", "must be between 0 and 1Gi")
	}
	if r.MaxRecords < 0 || r.MaxRecords > maxRecords {
		add("/resources/max_records", "must be between 0 and %d", maxRecords)
	}
	if r.Cost < 0 || r.Cost > maxCost {
		add("/resources/cost", "must be between 0 and %d", maxCost)
	}
}

func (m Manifest) validateRun(add func(p, format string, args ...any), schema *core.SettingsSchema) {
	r := m.Run
	switch r.Profile {
	case ProfileAdapter:
		if r.Output != nil {
			add("/run/output", "only for the exec profile (an adapter emits records)")
		}
		if len(r.ExitCodes) > 0 {
			add("/run/exit_codes", "only for the exec profile")
		}
	case ProfileExec:
		if len(m.Permissions.Credentials) > 0 {
			add("/permissions/credentials", "the exec profile cannot receive credentials; write an adapter")
		}
		if r.Output == nil {
			add("/run/output", "required for the exec profile")
		} else {
			if !slices.Contains([]string{OutputCTIS, OutputSARIF, OutputJSONLCTIS}, r.Output.Format) {
				add("/run/output/format", "must be ctis, sarif or jsonl-ctis")
			}
			switch r.Output.From {
			case "stdout":
			case "file":
				if !slices.ContainsFunc(r.Argv, func(a string) bool { return strings.Contains(a, "{{task.output}}") }) {
					add("/run/output/from", "file output needs {{task.output}} in argv")
				}
			default:
				add("/run/output/from", "must be stdout or file")
			}
		}
		for code, outcome := range r.ExitCodes {
			if n, err := strconv.Atoi(code); err != nil || n < 0 || n > 255 {
				add("/run/exit_codes/"+code, "must be an exit code 0-255")
			}
			if !slices.Contains(exitOutcomes, outcome) {
				add("/run/exit_codes/"+code, "must be one of %s", strings.Join(exitOutcomes, ", "))
			}
		}
	default:
		add("/run/profile", "must be adapter or exec")
	}
	if len(r.Argv) == 0 || len(r.Argv) > maxArgv {
		add("/run/argv", "must have 1 to %d entries", maxArgv)
		return
	}
	prog := path.Base(strings.ReplaceAll(r.Argv[0], `\`, "/"))
	if slices.Contains(refusedPrograms, strings.ToLower(prog)) {
		add("/run/argv/0", "%s is a shell or launcher; run the tool directly (no shell)", prog)
	}
	if placeholder.MatchString(r.Argv[0]) {
		add("/run/argv/0", "the program cannot be a placeholder")
	}
	for i, a := range r.Argv {
		ptr := fmt.Sprintf("/run/argv/%d", i)
		if len(a) > maxArgLen {
			add(ptr, "longer than %d bytes", maxArgLen)
		}
		if strings.ContainsAny(a, "\x00\n\r") {
			add(ptr, "contains a NUL or a line break")
		}
		for _, mm := range placeholder.FindAllStringSubmatch(a, -1) {
			if msg := checkPlaceholder(mm[1], schema); msg != "" {
				add(ptr, "%s: %s", mm[0], msg)
			}
		}
		if rest := placeholder.ReplaceAllString(a, ""); strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
			add(ptr, "unbalanced placeholder braces")
		}
	}
}

func checkPlaceholder(name string, schema *core.SettingsSchema) string {
	if slices.Contains(argvPlaceholders, name) {
		return ""
	}
	key, ok := strings.CutPrefix(name, "config.")
	if !ok {
		return "unknown placeholder (allowed: {{config.<key>}}, " + strings.Join(argvPlaceholders, ", ") + ")"
	}
	if schema == nil {
		return "the tool has no config schema"
	}
	p := schema.Property(key)
	if p == nil || strings.Contains(key, ".") {
		return "not a top-level config key"
	}
	switch p.Type {
	case "string", "integer", "number", "boolean":
		return ""
	}
	return "only scalar config keys can be placeholders"
}

func checkRelPath(p string) string {
	if p == "" {
		return "required"
	}
	if path.IsAbs(p) || strings.HasPrefix(p, `\`) || strings.Contains(p, ":") {
		return "must be a relative path"
	}
	if c := path.Clean(p); c == ".." || strings.HasPrefix(c, "../") {
		return "must stay inside the manifest's directory"
	}
	return ""
}
