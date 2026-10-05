package sensorkit

// Preflight checks and the config report (OpenCTEM research/26, documented
// in api docs/rfcs/RFC-033-sensor-manifest.md, "Config report"). What the
// kit used to print to stderr only (a skipped tool and why, a state
// directory that does not persist, scanners inheriting a proxy, a failed OOM
// protection, legacy names, an unreadable CA file, ...) is also a check
// result with a stable id, and the kit delivers them, with the presence of
// every declared setting, to a platform that takes config reports. New
// checks never stop the sensor; the existing fail-closed exits stay.
//
// Security: setting values never leave the host (presence only); every free
// text is scrubbed of the secret settings' values and URL credentials and
// bounded (core.ConfigReport.Finalize). The checks only read the sensor's
// own settings and files; they open no connection.

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/platform"
	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// Check ids the kit reports (stable API: the platform explains them).
const (
	CheckToolsAvailable       = "tools.available"
	CheckStatePersistent      = "identity.state_persistent"
	CheckKeyRenewal           = "identity.key_renewal"
	CheckScanProxyInherit     = "network.scan_proxy_inherit"
	CheckOOMProtect           = "runtime.oom_protect"
	CheckAliasDeprecated      = "config.alias_deprecated"
	CheckEnvUnknown           = "config.env_unknown"
	CheckPlatformTLS          = "platform.tls"
	CheckLocalPolicy          = "policy.local"
	CheckTemplateKeys         = "policy.template_keys"
	CheckCommandPoller        = "runtime.command_poller"
	EnvSSLCertFile            = "SSL_CERT_FILE"
	EnvSSLCertDir             = "SSL_CERT_DIR"
	unknownEnvPrefixSensor    = "SENSOR_"
	unknownEnvPrefixSDK       = "OPENCTEM_SDK_"
	maxToolCheckSegment       = 40
	maxUnavailableExcerptSize = core.MaxConfigExcerptLen
)

// ToolCheckID is the id of a per-tool check ("binary", "selection",
// "registration") for tool name.
func ToolCheckID(name, kind string) string {
	return "tool." + toolSegment(name) + "." + kind
}

// toolSegment is a tool name as a check id segment: lower case, [a-z0-9_-].
func toolSegment(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
		if b.Len() == maxToolCheckSegment {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// doctor holds the check results and builds the report.
type doctor struct {
	mu      sync.Mutex
	checks  map[string]core.ConfigCheck
	version int
	cached  *core.ConfigReport
	builtAt int
	reg     *settingsreg.Registry
	secrets func() []string
	runtime string
}

func newDoctor(reg *settingsreg.Registry, secrets func() []string) *doctor {
	return &doctor{checks: map[string]core.ConfigCheck{}, reg: reg, secrets: secrets, runtime: core.DetectRuntime()}
}

// checkKey identifies a result: its id and its parameters (one id may
// report several results, one per legacy name for instance).
func checkKey(c core.ConfigCheck) string {
	raw, _ := json.Marshal(c.Params) // map keys are sorted
	return c.ID + "\x00" + string(raw)
}

func (d *doctor) put(c core.ConfigCheck) {
	if c.Severity == "" {
		switch c.Status {
		case core.CheckFail, core.CheckError:
			c.Severity = core.SeverityCritical
		case core.CheckWarn:
			c.Severity = core.SeverityWarning
		default:
			c.Severity = core.SeverityInfo
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	k := checkKey(c)
	if old, ok := d.checks[k]; ok && sameCheck(old, c) {
		return
	}
	d.checks[k] = c
	d.version++
}

func sameCheck(a, b core.ConfigCheck) bool {
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return string(ra) == string(rb)
}

// report builds (or returns the cached) finalized report.
func (d *doctor) report() *core.ConfigReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cached != nil && d.builtAt == d.version {
		cp := *d.cached
		return &cp
	}
	r := &core.ConfigReport{
		ObservedAt: core.NowRFC3339(),
		Trigger:    core.ConfigTriggerStart,
		Runtime:    core.ConfigRuntime{Kind: d.runtime},
		Checks:     make([]core.ConfigCheck, 0, len(d.checks)),
	}
	keys := make([]string, 0, len(d.checks))
	for k := range d.checks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r.Checks = append(r.Checks, d.checks[k])
	}
	for _, st := range d.reg.States(nil) {
		r.Settings = append(r.Settings, core.ConfigSetting{Name: st.Name, Set: st.Set, Source: string(st.Source),
			Secret: st.Secret, Valid: st.Valid})
	}
	var secrets []string
	if d.secrets != nil {
		secrets = d.secrets()
	}
	r.Finalize(secrets, core.MaxConfigReportBytes)
	d.cached, d.builtAt = r, d.version
	cp := *r
	return &cp
}

// counts returns the passed, warning and failed results.
func (d *doctor) counts() (pass, warn, fail int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.checks {
		switch c.Status {
		case core.CheckPass:
			pass++
		case core.CheckWarn:
			warn++
		case core.CheckFail, core.CheckError:
			fail++
		}
	}
	return pass, warn, fail
}

// ReportCheck records a check result for the config report: a sensor adds
// its own checks (its configuration file, its tools) before or during Run.
// A result with the same id and parameters replaces the earlier one. The
// id, code and parameters must follow the report's schema
// (core.ConfigCheck); results that do not are dropped when the report is
// built. Never put a setting's value in a parameter or the summary.
func (k *Kit) ReportCheck(c core.ConfigCheck) {
	k.doc.put(c)
}

// ConfigReport is the current config report, finalized: what the platform
// receives (and what a local doctor command may print).
func (k *Kit) ConfigReport() *core.ConfigReport { return k.doc.report() }

// Settings is the settings registry: the SDK's settings are registered; a
// sensor registers its own (and MarkOption for those it set from a flag or
// its configuration file) before Run.
func (k *Kit) Settings() *settingsreg.Registry { return k.reg }

// secretValues are the values the report must never contain: every secret
// setting that is set, the configured and the in-use API key.
func (k *Kit) secretValues() []string {
	out := k.reg.SecretValues(nil)
	for _, v := range []string{k.opts.APIKey, k.s.apiKey, k.s.key.configuredKey, k.s.key.key,
		k.opts.ControlProxy, k.opts.ContentProxy, k.opts.ScanProxy} {
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// RegisterSDKSettings registers the settings the SDK and the kit read.
func RegisterSDKSettings(r *settingsreg.Registry) {
	r.Register(
		settingsreg.Setting{Name: EnvAPIURL, Type: settingsreg.URL, Required: true, Group: "platform",
			Description: "The platform's API URL (not the web UI origin)."},
		settingsreg.Setting{Name: EnvAPIKey, Type: settingsreg.String, Required: true, Secret: true, Group: "platform",
			Description: "The sensor's API key."},
		settingsreg.Setting{Name: EnvSensorID, Type: settingsreg.String, Group: "platform",
			Description: "The sensor's id, when the key is not bound to one."},
		settingsreg.Setting{Name: EnvSensorName, Type: settingsreg.String, Default: "sensor-<hostname>", Group: "platform",
			Description: "The sensor's name on the platform."},
		settingsreg.Setting{Name: EnvProtocol, Type: settingsreg.Enum, Enum: []string{"auto", "v1", "v2"}, Default: "auto",
			Group: "platform", Description: "Sensor protocol."},
		settingsreg.Setting{Name: EnvCACertFile, Type: settingsreg.Path, Group: "platform", Validate: readableFile,
			Description: "PEM file with the platform's private CA (or a TLS-inspecting proxy's CA)."},
		settingsreg.Setting{Name: EnvSSLCertFile, Type: settingsreg.Path, Group: "platform", Validate: readableFile,
			Description: "System trust store file override (read by the Go runtime and the scanners)."},
		settingsreg.Setting{Name: EnvSSLCertDir, Type: settingsreg.Path, Group: "platform", Validate: readableDir,
			Description: "System trust store directory override."},
		settingsreg.Setting{Name: EnvStateDir, Type: settingsreg.Path, Default: platform.DefaultStateDir, Group: "identity",
			Description: "Local state: the renewed API key and the tool cost history. Mount a persistent volume."},
		settingsreg.Setting{Name: EnvKeyAutoRenew, Type: settingsreg.Bool, Default: "auto", Group: "identity",
			Description: "API key auto-renewal: true, false, or unset (on when the state directory persists)."},
		settingsreg.Setting{Name: EnvMaxJobs, Type: settingsreg.Int, Group: "runtime",
			Description: "Cap on concurrent jobs, 1-100. Unset: the slots follow CPU, memory and tool costs."},
		settingsreg.Setting{Name: EnvDrainGrace, Type: settingsreg.Duration, Default: "30s", Group: "runtime",
			Description: "How long running jobs may finish on shutdown."},
		settingsreg.Setting{Name: EnvScannerPriority, Type: settingsreg.Enum, Enum: []string{"low", "normal"}, Default: "low",
			Group: "runtime", Description: "Priority of scanner processes."},
		settingsreg.Setting{Name: EnvProtectFromOOM, Type: settingsreg.Bool, Default: "false", Group: "runtime",
			Description: "Protect the sensor itself from the OOM killer (needs CAP_SYS_RESOURCE)."},
		settingsreg.Setting{Name: EnvTools, Type: settingsreg.List, Group: "tools",
			Description: "Allowlist of tools the sensor runs (comma-separated). Unset: every installed tool."},
		settingsreg.Setting{Name: EnvTemplateSigningKeys, Type: settingsreg.List, Group: "policy",
			Description: "The platform's template-signing public keys (base64 Ed25519); needed for custom templates."},
		settingsreg.Setting{Name: core.EnvLocalPolicy, Type: settingsreg.Path, Default: core.DefaultLocalPolicyPath, Group: "policy",
			Description: "The sensor-local policy file the network owner installs."},
		settingsreg.Setting{Name: core.EnvAllowedRanges, Type: settingsreg.List, Group: "policy",
			Description: "Shorthand local policy: allowed target ranges."},
		settingsreg.Setting{Name: core.EnvAllowedPorts, Type: settingsreg.List, Group: "policy",
			Description: "Shorthand local policy: allowed ports."},
		settingsreg.Setting{Name: core.EnvKillSwitchFile, Type: settingsreg.Path, Group: "policy",
			Description: "A file whose presence stops every job."},
		settingsreg.Setting{Name: core.EnvSensorAllowPrivateTargets, Type: settingsreg.Enum, Enum: []string{"", "0", "1"}, Group: "policy",
			Description: "1 allows private (RFC 1918 / ULA) targets; the local policy must allow them too."},
		settingsreg.Setting{Name: core.EnvAllowPrivateTargets, Type: settingsreg.Enum, Enum: []string{"", "0", "1"}, Group: "policy",
			Description: "SDK name of the private-target switch."},
		settingsreg.Setting{Name: core.EnvScanRoots, Type: settingsreg.List, Group: "policy",
			Description: "Directories code scans may read."},
		settingsreg.Setting{Name: EnvControlProxy, Type: settingsreg.URL, Secret: true, Group: "network",
			Description: "Proxy for platform requests (may carry credentials: presence only)."},
		settingsreg.Setting{Name: EnvContentProxy, Type: settingsreg.URL, Secret: true, Group: "network",
			Description: "Proxy for content downloads (may carry credentials: presence only)."},
		settingsreg.Setting{Name: EnvScanProxy, Type: settingsreg.URL, Secret: true, Group: "network",
			Description: "Scanner proxy: direct, inherit, or a proxy URL (may carry credentials: presence only)."},
		settingsreg.Setting{Name: core.EnvScannerProxy, Type: settingsreg.URL, Secret: true, Group: "network",
			Description: "SDK name of the scanner proxy setting."},
		settingsreg.Setting{Name: "HTTPS_PROXY", Type: settingsreg.URL, Secret: true, Group: "network",
			Description: "Environment proxy (may carry credentials: presence only)."},
		settingsreg.Setting{Name: "HTTP_PROXY", Type: settingsreg.URL, Secret: true, Group: "network",
			Description: "Environment proxy (may carry credentials: presence only)."},
		settingsreg.Setting{Name: "NO_PROXY", Type: settingsreg.List, Group: "network",
			Description: "Hosts the environment proxy is not used for."},
		settingsreg.Setting{Name: "OPENCTEM_SDK_SCANNER_ENV_ALLOW", Type: settingsreg.List, Group: "network",
			Description: "Extra environment variables scanners inherit."},
		settingsreg.Setting{Name: "OPENCTEM_SDK_SCANNER_INHERIT_ENV", Type: settingsreg.Bool, Group: "network",
			Description: "1 lets scanners inherit the whole environment (not recommended)."},
		settingsreg.Setting{Name: "OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE", Type: settingsreg.Bool, Group: "network",
			Description: "Lets SDK HTTP clients reach private addresses."},
		settingsreg.Setting{Name: "OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK", Type: settingsreg.Bool, Group: "network",
			Description: "Lets SDK HTTP clients reach loopback addresses."},
		settingsreg.Setting{Name: EnvSandbox, Type: settingsreg.Enum, Enum: []string{"off", "auto", "required"}, Default: "auto", Group: "runtime",
			Description: "How every tool run is confined: auto (what the host supports), required (refuse to start without every control), off."},
		settingsreg.Setting{Name: EnvOutbox, Type: settingsreg.Enum, Enum: []string{"on", "off", "true", "false"}, Group: "storage",
			Description: "The durable results outbox (on for a daemon)."},
		settingsreg.Setting{Name: EnvOutboxDir, Type: settingsreg.Path, Group: "storage",
			Description: "Outbox directory. Mount a persistent volume."},
		settingsreg.Setting{Name: EnvOutboxMaxBytes, Type: settingsreg.Bytes, Default: "1GiB", Group: "storage",
			Description: "Outbox size limit."},
		settingsreg.Setting{Name: EnvOutboxMaxAge, Type: settingsreg.Duration, Default: "168h", Group: "storage",
			Description: "Outbox age limit."},
		settingsreg.Setting{Name: EnvOutboxKeyFile, Type: settingsreg.Path, Group: "storage",
			Description: "Outbox encryption key file (default <outbox dir>/outbox.key)."},
	)
}

func readableFile(v string) error {
	f, err := os.Open(v) // #nosec G304 -- the operator's own setting, read to validate it
	if err != nil {
		return fmt.Errorf("unreadable")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return fmt.Errorf("not a file")
	}
	return nil
}

func readableDir(v string) error {
	entries, err := os.ReadDir(v)
	if err != nil {
		return fmt.Errorf("unreadable")
	}
	_ = entries
	return nil
}

// preflightNew records the checks New can decide: the trust store files,
// legacy names, unknown names, the scanner proxy, the state directory and
// the local policy.
func (k *Kit) preflightNew(proxies Proxies, proxyOpts ProxyOptions) {
	k.checkTrustFiles()
	for _, rv := range legacyv1.SensorRenamedEnv {
		r := [2]string{rv.Old, rv.New}
		if _, ok := os.LookupEnv(r[0]); ok {
			k.ReportCheck(core.ConfigCheck{ID: CheckAliasDeprecated, Status: core.CheckWarn, Code: "legacy_name",
				Params:  map[string]core.ConfigParam{"name": core.ParamName(r[0]), "replacement": core.ParamName(r[1])},
				Summary: fmt.Sprintf("%s is a deprecated name; use %s", r[0], r[1])})
		}
	}
	if k.opts.ReportUnknownEnv {
		for _, u := range k.reg.Unknown(nil, unknownEnvPrefixSensor, unknownEnvPrefixSDK) {
			params := map[string]core.ConfigParam{"name": core.ParamName(u.Name)}
			summary := u.Name + " is not a setting this sensor reads"
			if u.DidYouMean != "" {
				params["suggestion"] = core.ParamName(u.DidYouMean)
				summary += "; did you mean " + u.DidYouMean + "?"
			}
			k.ReportCheck(core.ConfigCheck{ID: CheckEnvUnknown, Status: core.CheckWarn, Code: "unknown",
				Params: params, Summary: summary})
			_, _ = fmt.Fprintf(k.errw, "Warning: %s\n", summary)
		}
	}
	// Scanners and the environment proxy (api RFC-034 G1).
	explicit := firstNonEmpty(proxyOpts.Scan, os.Getenv(EnvScanProxy), os.Getenv(core.EnvScannerProxy))
	switch {
	case proxies.Scan == core.ScannerProxyDirect:
		k.ReportCheck(core.ConfigCheck{ID: CheckScanProxyInherit, Status: core.CheckPass, Code: "direct"})
	case proxies.ScanWarning() == "":
		k.ReportCheck(core.ConfigCheck{ID: CheckScanProxyInherit, Status: core.CheckPass, Code: "direct"})
	case explicit != "":
		k.ReportCheck(core.ConfigCheck{ID: CheckScanProxyInherit, Status: core.CheckPass, Code: "inherit_explicit"})
	default:
		k.ReportCheck(core.ConfigCheck{ID: CheckScanProxyInherit, Status: core.CheckWarn, Code: "inherits_proxy",
			Params:  map[string]core.ConfigParam{"vars": core.ParamNames(environmentProxyVars()...)},
			Keys:    []string{EnvScanProxy},
			Summary: "scanner processes inherit this sensor's proxy variables"})
	}
	k.reportLocalPolicyChecks(k.s.local)
}

// reportLocalPolicyChecks records the local policy checks for lp (at start
// and after each reload).
func (k *Kit) reportLocalPolicyChecks(lp *core.LocalPolicy) {
	if lp != nil {
		rep := lp.Report()
		if rep.State == core.LocalPolicyStateEnforced {
			k.ReportCheck(core.ConfigCheck{ID: CheckLocalPolicy, Status: core.CheckPass, Code: "enforced"})
		} else {
			k.ReportCheck(core.ConfigCheck{ID: CheckLocalPolicy, Status: core.CheckWarn, Code: "absent",
				Keys: []string{core.EnvLocalPolicy}, Summary: "no sensor-local policy is installed"})
		}
		switch {
		case rep.Summary == nil || !rep.Summary.AllowCustomTemplates:
			k.ReportCheck(core.ConfigCheck{ID: CheckTemplateKeys, Status: core.CheckSkip, Code: "not_needed"})
		case k.s.templates == nil:
			k.ReportCheck(core.ConfigCheck{ID: CheckTemplateKeys, Status: core.CheckWarn, Code: "missing",
				Keys: []string{EnvTemplateSigningKeys}, Blocks: []string{core.BlockCustomTemplates},
				Summary: "the local policy allows custom templates but no template-signing key is set"})
		default:
			k.ReportCheck(core.ConfigCheck{ID: CheckTemplateKeys, Status: core.CheckPass, Code: "ok"})
		}
	}
}

// checkTrustFiles reports an unreadable SSL_CERT_FILE / SSL_CERT_DIR: the Go
// runtime ignores them silently and the operator only sees "x509: unknown
// authority". SENSOR_CA_CERT_FILE is loaded by New (an unreadable one stops
// the sensor), so it passes here.
func (k *Kit) checkTrustFiles() {
	bad := false
	if f := os.Getenv(EnvSSLCertFile); f != "" && readableFile(f) != nil {
		bad = true
		k.ReportCheck(core.ConfigCheck{ID: CheckPlatformTLS, Status: core.CheckFail, Code: "ca_file_unreadable",
			Params: map[string]core.ConfigParam{"name": core.ParamName(EnvSSLCertFile), "path": core.ParamPath(f)},
			Keys:   []string{EnvSSLCertFile}, Blocks: []string{core.BlockAll},
			Summary: EnvSSLCertFile + " is set but the file cannot be read; TLS to the platform will fail with " +
				"\"unknown authority\" if it uses a private CA"})
		_, _ = fmt.Fprintf(k.errw, "Warning: %s=%s cannot be read: the system trust store is used instead, so a private CA is not trusted\n", EnvSSLCertFile, f)
	}
	if d := os.Getenv(EnvSSLCertDir); d != "" {
		for _, dir := range strings.Split(d, string(os.PathListSeparator)) {
			if dir == "" || readableDir(dir) == nil {
				continue
			}
			bad = true
			k.ReportCheck(core.ConfigCheck{ID: CheckPlatformTLS, Status: core.CheckFail, Code: "ca_dir_unreadable",
				Params: map[string]core.ConfigParam{"name": core.ParamName(EnvSSLCertDir), "path": core.ParamPath(dir)},
				Keys:   []string{EnvSSLCertDir}, Blocks: []string{core.BlockAll},
				Summary: EnvSSLCertDir + " names a directory that cannot be read"})
			_, _ = fmt.Fprintf(k.errw, "Warning: %s entry %s cannot be read: certificates in it are not trusted\n", EnvSSLCertDir, dir)
		}
	}
	if !bad {
		k.ReportCheck(core.ConfigCheck{ID: CheckPlatformTLS, Status: core.CheckPass, Code: "ok"})
	}
}

// checkState reports whether the state directory survives a recreate.
func (k *Kit) checkState() {
	if k.opts.Standalone || k.s.stateDir == "" {
		return
	}
	p := statePersistence(k.s.stateDir)
	params := map[string]core.ConfigParam{"path": core.ParamPath(k.s.stateDir)}
	switch {
	case p.Persistent:
		k.ReportCheck(core.ConfigCheck{ID: CheckStatePersistent, Status: core.CheckPass, Code: "persistent", Params: params})
	case strings.Contains(p.Reason, "unreadable"):
		k.ReportCheck(core.ConfigCheck{ID: CheckStatePersistent, Status: core.CheckWarn, Code: "unknown", Params: params,
			Keys: []string{EnvStateDir}, Summary: p.Reason})
	default:
		k.ReportCheck(core.ConfigCheck{ID: CheckStatePersistent, Status: core.CheckWarn, Code: "not_persistent", Params: params,
			Keys: []string{EnvStateDir}, Summary: p.Reason})
	}
}

// keyRenewalCheck reports the key renewal decision (after it started or
// failed to).
func (k *Kit) keyRenewalCheck(startErr error) {
	if k.client == nil {
		return
	}
	switch {
	case startErr != nil:
		k.ReportCheck(core.ConfigCheck{ID: CheckKeyRenewal, Status: core.CheckFail, Code: "start_failed",
			Severity: core.SeverityWarning, Summary: "key auto-renew failed to start: " + startErr.Error()})
	case k.s.key.autoRenew:
		k.ReportCheck(core.ConfigCheck{ID: CheckKeyRenewal, Status: core.CheckPass, Code: "enabled"})
	case strings.HasPrefix(k.s.key.why, "disabled"):
		k.ReportCheck(core.ConfigCheck{ID: CheckKeyRenewal, Status: core.CheckSkip, Code: "disabled", Keys: []string{EnvKeyAutoRenew}})
	default:
		k.ReportCheck(core.ConfigCheck{ID: CheckKeyRenewal, Status: core.CheckWarn, Code: "off_not_persistent",
			Keys: []string{EnvStateDir, EnvKeyAutoRenew}, Summary: k.s.key.why})
	}
}

// oomCheck reports the OOM protection outcome (err from the write; nil and
// requested false when not asked for).
func (k *Kit) oomCheck(requested bool, code, summary string) {
	if !requested {
		k.ReportCheck(core.ConfigCheck{ID: CheckOOMProtect, Status: core.CheckSkip, Code: "not_requested"})
		return
	}
	if code == "protected" {
		k.ReportCheck(core.ConfigCheck{ID: CheckOOMProtect, Status: core.CheckPass, Code: code})
		return
	}
	k.ReportCheck(core.ConfigCheck{ID: CheckOOMProtect, Status: core.CheckWarn, Code: code,
		Keys: []string{EnvProtectFromOOM}, Summary: summary})
}

// toolBinaryCheck records whether an allowed scanner can run here.
func (k *Kit) toolBinaryCheck(e scannerEntry, installed bool, checkErr error, reason string) {
	name := e.label()
	params := map[string]core.ConfigParam{"tool": core.ParamName(name)}
	id := ToolCheckID(name, "binary")
	if installed && checkErr == nil {
		k.ReportCheck(core.ConfigCheck{ID: id, Status: core.CheckPass, Code: "ok", Params: params})
		return
	}
	code := unavailableCode(reason, checkErr)
	k.ReportCheck(core.ConfigCheck{ID: id, Status: core.CheckFail, Code: code, Params: params,
		Keys: []string{EnvTools}, Blocks: []string{core.BlockTool(toolSegment(name))},
		Summary: name + " cannot run here", Excerpt: truncateBytes(reason, maxUnavailableExcerptSize)})
}

// unavailableCode classifies why a tool cannot run from its reason
// (Options.UnavailableReason): a reason starting "not installed" is
// not_installed, one saying the tool "fails to run" (or is "broken") is
// broken, any other with a check error is check_error.
func unavailableCode(reason string, checkErr error) string {
	r := strings.ToLower(strings.TrimSpace(reason))
	switch {
	case strings.HasPrefix(r, "not installed"):
		return "not_installed"
	case strings.Contains(r, "fails to run"), strings.Contains(r, "broken"):
		return "broken"
	case checkErr != nil:
		return "check_error"
	default:
		return "not_installed"
	}
}

func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// environmentProxyVars names the proxy variables set in the environment.
func environmentProxyVars() []string {
	var out []string
	for _, n := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if os.Getenv(n) != "" {
			out = append(out, n)
		}
	}
	return out
}

// printPreflight prints one line with the counts.
func (k *Kit) printPreflight() {
	pass, warn, fail := k.doc.counts()
	where := ""
	if k.client != nil {
		where = " (the platform shows them under the sensor's Setup & health)"
	}
	_, _ = fmt.Fprintf(k.out, "  Preflight: %d passed, %d warning(s), %d failed%s\n", pass, warn, fail, where)
}
