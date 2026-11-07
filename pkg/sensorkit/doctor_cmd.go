package sensorkit

// The doctor subcommand (research/468 D2): a read-only, local check of the
// host a sensor runs on, before or after it starts. It reuses the config
// report's probes and checks (sandbox, user namespaces, storage) and adds
// what an install needs to get right first: cgroup delegation, free disk,
// the platform's name, TLS and clock, the kill switch path and the local
// policy.
//
// Security: the doctor changes nothing on the host (the sandbox probe runs
// the launcher once, as the sensor's start does). It contacts only the
// configured platform URL, with no credential: the request carries no API
// key, no signature and no token. Its output goes through the config
// report's scrubber (core.ConfigReport.Finalize), so no secret setting's
// value, URL credential or key byte appears in it; the TLS evidence is the
// CA certificate's SHA-256 fingerprint only.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/resource"
	"github.com/openctemio/sdk-go/pkg/sdk"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// DoctorSchema identifies the `doctor --json` document
// (docs/schemas/sensor-doctor.v1.schema.json).
const DoctorSchema = "openctem.io/sensor-doctor/v1"

// Doctor exit codes: the most severe result decides. A flag error exits
// ExitUsage.
const (
	DoctorExitOK      = 0 // every check passed (or was skipped)
	DoctorExitWarning = 3 // a warning, no failure
	DoctorExitFailure = 4 // a failure: something blocks the sensor or its jobs
)

// Doctor check ids (stable: scripts and the console read them).
const (
	CheckDoctorVersion   = "doctor.version"
	CheckCgroupEnvelope  = "runtime.cgroup_envelope"
	CheckDiskFree        = "storage.disk_free"
	CheckStateDir        = "identity.state_dir"
	CheckPlatformDNS     = "platform.dns"
	CheckPlatformReach   = "platform.reachable"
	CheckPlatformClock   = "platform.clock_skew"
	CheckKillSwitchPath  = "policy.kill_switch_path"
	CheckLocalPolicyLoad = "policy.local_parse"
)

// Free disk thresholds of the data directories.
const (
	doctorDiskFail = 1 << 30 // 1 GiB
	doctorDiskWarn = 5 << 30 // 5 GiB
	// doctorClockWarn: a skew this large is not refused yet but drifts.
	doctorClockWarn = 30 * time.Second
)

// RecommendedKillSwitchFile is the kill switch path every install uses
// (research/468 D4): /etc/openctem/STOP on the host, mounted read-only at
// the same path.
const RecommendedKillSwitchFile = "/etc/openctem/STOP"

// DoctorOptions configure DoctorCommand. Empty fields fall back to the
// settings (environment) the sensor reads at start.
type DoctorOptions struct {
	// ProductName and Version are the sensor's ("openctemio-sensor").
	ProductName, Version string
	// APIURL is the platform URL (SENSOR_API_URL).
	APIURL string
	// StateDir and OutboxDir are the data directories (SENSOR_STATE_DIR,
	// SENSOR_OUTBOX_DIR).
	StateDir, OutboxDir string
	// LocalPolicyPath is the local policy (SENSOR_LOCAL_POLICY).
	LocalPolicyPath string
	// Sandbox is the tool sandbox mode (SENSOR_SANDBOX).
	Sandbox string
	// Settings is the sensor's settings registry, for the secret values
	// the output must never contain (nil: the SDK's settings).
	Settings *settingsreg.Registry
	// HTTPClient sends the platform request (default
	// httpsec.NewAPIClient). Timeout bounds every network check
	// (default 10 seconds).
	HTTPClient *http.Client
	Timeout    time.Duration
}

// DoctorReport is the `doctor --json` document.
type DoctorReport struct {
	Schema     string `json:"schema"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	SDKVersion string `json:"sdk_version"`
	// Runtime is where the doctor ran (core.DetectRuntime).
	Runtime string `json:"runtime"`
	// Checks are the results, scrubbed and bounded like a config report's.
	Checks []core.ConfigCheck `json:"checks"`
	// Summary counts the results; ExitCode is the process exit code.
	Summary  DoctorSummary `json:"summary"`
	ExitCode int           `json:"exit_code"`
}

// DoctorSummary counts the results by status.
type DoctorSummary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// Test seams.
var (
	doctorLookupHost = net.DefaultResolver.LookupHost
	doctorDiskFree   = resource.DiskFree
	doctorEnvelopes  = executor.CheckEnvelopes
	doctorBackend    = executor.NewProcessBackend
)

// DoctorCommand runs `<sensor> doctor [--json]`: every check, a table (or
// the JSON document) on stdout, and an exit code by the most severe
// result. The program's main must call executor.RunLauncherIfRequested
// first, as for the sensor itself, or the sandbox check fails.
func DoctorCommand(args []string, o DoctorOptions, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the results as JSON ("+DoctorSchema+")")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: doctor [--json]\n\nChecks this host for the sensor without changing it: the tool sandbox and user namespaces, cgroup delegation, free disk, the platform's name, TLS and clock (no credential is sent), the kill switch path and the local policy.\nExit codes: %d all passed, %d a warning, %d a failure, %d a usage error.\n",
			DoctorExitOK, DoctorExitWarning, DoctorExitFailure, ExitUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return DoctorExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "doctor: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*timeout)
	defer cancel()
	r := RunDoctor(ctx, o)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		writeDoctorTable(stdout, r)
	}
	return r.ExitCode
}

// RunDoctor runs every check and returns the scrubbed report.
func RunDoctor(ctx context.Context, o DoctorOptions) *DoctorReport {
	reg := o.Settings
	if reg == nil {
		reg = settingsreg.New()
		RegisterSDKSettings(reg)
	}
	d := newDoctor(reg, nil)
	k := &Kit{doc: d, out: io.Discard, errw: io.Discard}
	put := d.put

	put(core.ConfigCheck{ID: CheckDoctorVersion, Status: core.CheckPass, Code: "version",
		Params:  map[string]core.ConfigParam{"sdk": core.ParamVersion(sdk.Version)},
		Summary: strings.TrimSpace(firstNonEmpty(o.ProductName, "sensor") + " " + o.Version + " (sdk-go " + sdk.Version + ")")})
	doctorSandbox(k, o)
	put(doctorCgroupCheck())
	stateDir := ResolveStateDir(o.StateDir)
	put(doctorStateDirCheck(stateDir))
	put(doctorDiskCheck(stateDir, firstNonEmpty(o.OutboxDir, os.Getenv(EnvOutboxDir), DefaultOutboxDir)))
	for _, c := range doctorPlatformChecks(ctx, o) {
		put(c)
	}
	for _, c := range doctorPolicyChecks(o) {
		put(c)
	}

	secrets := reg.SecretValues(nil)
	rep := &core.ConfigReport{Checks: d.report().Checks}
	rep.Finalize(secrets, 0)
	out := &DoctorReport{Schema: DoctorSchema, Product: o.ProductName, Version: o.Version, SDKVersion: sdk.Version,
		Runtime: core.DetectRuntime(), Checks: rep.Checks}
	if out.Checks == nil {
		out.Checks = []core.ConfigCheck{}
	}
	for _, c := range out.Checks {
		switch c.Status {
		case core.CheckPass:
			out.Summary.Pass++
		case core.CheckWarn:
			out.Summary.Warn++
		case core.CheckFail, core.CheckError:
			out.Summary.Fail++
		default:
			out.Summary.Skip++
		}
	}
	switch {
	case out.Summary.Fail > 0:
		out.ExitCode = DoctorExitFailure
	case out.Summary.Warn > 0:
		out.ExitCode = DoctorExitWarning
	}
	return out
}

// doctorSandbox probes the tool sandbox as the sensor's start would and
// reports the config report's sandbox checks. A required control the host
// cannot give is a failure here (the sensor would refuse to start, or
// refuse every tool that contacts its targets).
func doctorSandbox(k *Kit, o DoctorOptions) {
	shared, err := SharedModeFromEnv()
	if err != nil {
		k.ReportCheck(core.ConfigCheck{ID: CheckSandboxUnconfined, Status: core.CheckFail, Code: "settings_invalid", Keys: []string{EnvSharedMode}, Summary: err.Error()})
		return
	}
	mode, netMode, err := sandboxModes(o.Sandbox, shared)
	if err != nil {
		k.ReportCheck(core.ConfigCheck{ID: CheckSandboxUnconfined, Status: core.CheckFail, Code: "settings_invalid",
			Keys: []string{EnvSandbox, EnvSandboxNetwork}, Summary: err.Error()})
		return
	}
	// Probe what the host gives, without the requirement (which would
	// only return an error): the checks below judge it.
	probe := mode
	if probe == executor.ModeRequired {
		probe = executor.ModeAuto
	}
	b, err := doctorBackend(executor.Config{Mode: probe, ConfineNetwork: netMode != executor.ModeOff})
	if err != nil {
		k.ReportCheck(core.ConfigCheck{ID: CheckSandboxUnconfined, Status: core.CheckFail, Code: "probe_failed", Keys: []string{EnvSandbox}, Summary: err.Error()})
		return
	}
	st := b.Status()
	st.Mode = mode
	c := unconfinedCheck(st)
	if mode == executor.ModeRequired && !st.Complete() {
		c.Status, c.Code = core.CheckFail, "required_unmet"
		c.Summary = EnvSandbox + "=required and this host does not enforce every sandbox control: " + strings.Join(st.Missing, "; ")
	}
	k.ReportCheck(c)
	k.sandboxNetworkCheck(mode, netMode, st)
	if netMode == executor.ModeRequired && !st.NetworkEnforced {
		n, ok := findReported(k, CheckSandboxNetwork)
		if ok {
			n.Status = core.CheckFail
			k.ReportCheck(n)
		}
	}
}

func findReported(k *Kit, id string) (core.ConfigCheck, bool) {
	for _, c := range k.doc.report().Checks {
		if c.ID == id {
			return c, true
		}
	}
	return core.ConfigCheck{}, false
}

// doctorCgroupCheck: per-task envelopes need a cgroup v2 that delegates
// memory and pids and is writable. Without it tasks get rlimits only.
func doctorCgroupCheck() core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckCgroupEnvelope, Keys: []string{EnvToolCgroups}}
	if strings.EqualFold(strings.TrimSpace(os.Getenv(EnvToolCgroups)), "off") {
		c.Status, c.Code, c.Summary = core.CheckSkip, "off", "per-task cgroups are off ("+EnvToolCgroups+"=off): tasks get rlimits only"
		return c
	}
	why := doctorEnvelopes()
	if why == "" {
		c.Status, c.Code, c.Keys = core.CheckPass, "delegated", nil
		c.Summary = "the sensor's cgroup v2 delegates memory and pids: each task gets its own CPU, memory and process limits"
		return c
	}
	c.Status, c.Code = core.CheckWarn, "not_delegated"
	c.Summary = "tasks get rlimits only, not a cgroup each: give the sensor a delegated cgroup v2 (systemd: Delegate=yes and MemoryMax=; a container: the default private cgroup namespace with a writable cgroup)"
	c.Excerpt = truncateBytes(why, maxUnavailableExcerptSize)
	return c
}

func doctorStateDirCheck(dir string) core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckStateDir, Keys: []string{EnvStateDir}, Params: map[string]core.ConfigParam{"dir": core.ParamPath(dir)}}
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.Status, c.Code = core.CheckWarn, "missing"
		c.Summary = "the state directory " + dir + " does not exist yet: the sensor creates it at start; mount a persistent volume there so its identity survives a restart"
	case err != nil:
		c.Status, c.Code, c.Summary = core.CheckFail, "unreadable", "the state directory "+dir+" cannot be read: "+err.Error()
	case !fi.IsDir():
		c.Status, c.Code, c.Summary = core.CheckFail, "not_a_directory", dir+" is not a directory"
	case !dirWritable(dir):
		c.Status, c.Code, c.Summary = core.CheckFail, "not_writable", "the state directory "+dir+" is not writable by this user: the sensor cannot keep its identity"
	default:
		c.Status, c.Code, c.Keys = core.CheckPass, "ok", nil
		c.Summary = "the state directory " + dir + " exists and is writable"
	}
	return c
}

// doctorDiskCheck reports the least free space of the data directories
// (the first existing parent of each).
func doctorDiskCheck(dirs ...string) core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckDiskFree}
	least, at := int64(-1), ""
	for _, d := range dirs {
		p := existingParent(d)
		if p == "" {
			continue
		}
		if free := doctorDiskFree(p); free > 0 && (least < 0 || free < least) {
			least, at = free, p
		}
	}
	if least < 0 {
		c.Status, c.Code, c.Summary = core.CheckSkip, "unknown", "free disk space cannot be read on this system"
		return c
	}
	c.Params = map[string]core.ConfigParam{"free_bytes": core.ParamInt(least), "path": core.ParamPath(at)}
	human := strconv.FormatFloat(float64(least)/(1<<30), 'f', 1, 64) + " GiB free on " + at
	switch {
	case least < doctorDiskFail:
		c.Status, c.Code, c.Summary = core.CheckFail, "low", human+": below 1 GiB the outbox refuses new results and tools fail; free space or mount a larger volume"
	case least < doctorDiskWarn:
		c.Status, c.Code, c.Summary = core.CheckWarn, "low", human+": below 5 GiB content packs and results may not fit"
	default:
		c.Status, c.Code, c.Summary = core.CheckPass, "ok", human
	}
	return c
}

func existingParent(p string) string {
	for p = filepath.Clean(p); p != "" && p != "."; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		if p == string(filepath.Separator) {
			break
		}
	}
	return ""
}

// doctorPlatformChecks resolve the platform's host name, open a TLS
// connection and send one GET to its hello without any credential, and
// compare its clock with this host's.
func doctorPlatformChecks(ctx context.Context, o DoctorOptions) []core.ConfigCheck {
	raw := firstNonEmpty(o.APIURL, os.Getenv(EnvAPIURL))
	dns := core.ConfigCheck{ID: CheckPlatformDNS, Keys: []string{EnvAPIURL}}
	if raw == "" {
		dns.Status, dns.Code, dns.Summary = core.CheckSkip, "not_set", EnvAPIURL+" is not set: the platform checks are skipped"
		return []core.ConfigCheck{dns}
	}
	if _, err := httpsec.CheckAPIBaseURL(raw); err != nil {
		dns.Status, dns.Code, dns.Summary = core.CheckFail, "url_invalid", EnvAPIURL+" is not a usable platform URL: "+err.Error()
		return []core.ConfigCheck{dns}
	}
	u, _ := url.Parse(raw)
	host := u.Hostname()
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if net.ParseIP(host) != nil {
		dns.Status, dns.Code, dns.Keys = core.CheckPass, "ip_literal", nil
		dns.Summary = "the platform URL names an address, no lookup needed"
	} else {
		lctx, cancel := context.WithTimeout(ctx, timeout)
		addrs, err := doctorLookupHost(lctx, host+".")
		cancel()
		if err != nil {
			dns.Status, dns.Code = core.CheckFail, "unresolved"
			dns.Summary = "the platform host " + host + " does not resolve on this host: check its DNS (in a container, the runtime's resolver), or pin the name with an extra hosts entry"
			dns.Excerpt = truncateBytes(err.Error(), maxUnavailableExcerptSize)
			return []core.ConfigCheck{dns}
		}
		dns.Status, dns.Code, dns.Keys = core.CheckPass, "resolved", nil
		dns.Params = map[string]core.ConfigParam{"addresses": core.ParamInt(int64(len(addrs)))}
		dns.Summary = "the platform host " + host + " resolves (" + strconv.Itoa(len(addrs)) + " addresses)"
	}

	reach := core.ConfigCheck{ID: CheckPlatformReach, Keys: []string{EnvAPIURL, EnvCACertFile, EnvCAFingerprint}}
	hc := o.HTTPClient
	if hc == nil {
		hc = httpsec.NewAPIClient(timeout)
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, strings.TrimRight(raw, "/")+protov2.PathPrefix+protov2.HelloPath, nil)
	if err != nil {
		reach.Status, reach.Code, reach.Summary = core.CheckFail, "url_invalid", err.Error()
		return []core.ConfigCheck{dns, reach}
	}
	req.Header.Set("Accept", protov2.MediaTypeJSON)
	req.Header.Set("User-Agent", productToken(firstNonEmpty(o.ProductName, "openctem-sensor"), o.Version)+" doctor")
	sent := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		reach.Status = core.CheckFail
		reach.Code, reach.Summary = classifyReachError(err)
		reach.Excerpt = truncateBytes(err.Error(), maxUnavailableExcerptSize)
		return []core.ConfigCheck{dns, reach}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	received := time.Now()
	reach.Status, reach.Code, reach.Keys = core.CheckPass, "reachable", nil
	reach.Params = map[string]core.ConfigParam{"http_status": core.ParamInt(int64(resp.StatusCode))}
	reach.Summary = "the platform answers (HTTP " + strconv.Itoa(resp.StatusCode) + " without credentials)"
	if u.Scheme == "https" && resp.TLS != nil {
		if fp := caFingerprint(resp); fp != "" {
			reach.Summary += "; TLS verified, CA SHA256:" + fp
		}
	} else {
		reach.Status, reach.Code = core.CheckWarn, "plain_http"
		reach.Summary += " over plain http: use https outside a lab"
	}
	return []core.ConfigCheck{dns, reach, clockCheck(resp.Header.Get("Date"), sent, received)}
}

// classifyReachError names why the platform could not be reached.
func classifyReachError(err error) (code, summary string) {
	var ua x509.UnknownAuthorityError
	switch {
	case errors.As(err, &ua) || strings.Contains(err.Error(), "certificate signed by unknown authority"):
		return "tls_untrusted", "the platform's TLS certificate is not trusted here: give the sensor its CA (" + EnvCACertFile + ") or pin it (" + EnvCAFingerprint + ")"
	case strings.Contains(err.Error(), "x509:") || strings.Contains(err.Error(), "tls:"):
		return "tls_failed", "the TLS handshake with the platform failed (a certificate for another name, an expired one, or a proxy that intercepts TLS)"
	case strings.Contains(err.Error(), "connection refused"):
		return "refused", "the platform host refuses the connection: check the URL's port and that the platform is up"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout", "the platform did not answer in time: check the network path (a firewall, a proxy setting)"
	}
	return "unreachable", "the platform cannot be reached from this host"
}

// caFingerprint is the SHA-256 of the last certificate of the verified
// chain (the CA the platform's certificate leads to), hex.
func caFingerprint(resp *http.Response) string {
	cs := resp.TLS
	if len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0 {
		chain := cs.VerifiedChains[0]
		sum := sha256.Sum256(chain[len(chain)-1].Raw)
		return hex.EncodeToString(sum[:])
	}
	return ""
}

// clockCheck compares the platform's Date with this host's clock (the
// midpoint of the request). Beyond sensorsig.MaxClockSkew the platform
// refuses the sensor's signatures.
func clockCheck(date string, sent, received time.Time) core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckPlatformClock}
	pt, err := http.ParseTime(date)
	if err != nil {
		c.Status, c.Code, c.Summary = core.CheckSkip, "no_date", "the platform's answer carries no Date header"
		return c
	}
	mid := sent.Add(received.Sub(sent) / 2)
	skew := mid.Sub(pt).Round(time.Second)
	abs := skew
	if abs < 0 {
		abs = -abs
	}
	c.Params = map[string]core.ConfigParam{"skew_seconds": core.ParamInt(int64(skew / time.Second))}
	dir := "ahead of"
	if skew < 0 {
		dir = "behind"
	}
	switch {
	case abs > sensorsig.MaxClockSkew+time.Second: // Date has one-second precision
		c.Status, c.Code = core.CheckFail, "skewed"
		c.Summary = "this host's clock is " + abs.String() + " " + dir + " the platform's: signatures allow " + sensorsig.MaxClockSkew.String() + "; fix NTP on the wrong one (timedatectl shows the state)"
	case abs > doctorClockWarn:
		c.Status, c.Code = core.CheckWarn, "drifting"
		c.Summary = "this host's clock is " + abs.String() + " " + dir + " the platform's: check NTP before it reaches " + sensorsig.MaxClockSkew.String()
	default:
		c.Status, c.Code, c.Summary = core.CheckPass, "ok", "this host's clock is within "+doctorClockWarn.String()+" of the platform's"
	}
	return c
}

// doctorPolicyChecks parse the local policy as the sensor would and check
// the kill switch path.
func doctorPolicyChecks(o DoctorOptions) []core.ConfigCheck {
	parse := core.ConfigCheck{ID: CheckLocalPolicyLoad, Keys: []string{core.EnvLocalPolicy, core.EnvAllowedRanges}}
	lp, err := core.LoadLocalPolicy(core.LocalPolicyOptions{Path: o.LocalPolicyPath})
	if err != nil {
		parse.Status, parse.Code = core.CheckFail, "invalid"
		parse.Summary = "the sensor refuses to start with this local policy: " + err.Error()
		return []core.ConfigCheck{parse, killSwitchPathCheck(nil)}
	}
	parse.Status, parse.Code, parse.Keys = core.CheckPass, "ok", nil
	parse.Summary = "local policy " + lp.Describe()
	for _, w := range lp.Warnings() {
		parse.Status, parse.Code = core.CheckWarn, "warnings"
		parse.Summary += "; warning: " + w
	}
	return []core.ConfigCheck{parse, killSwitchPathCheck(lp)}
}

// killSwitchPathCheck: an emergency stop works only when the file the
// sensor watches is on a path the host owner can reach.
func killSwitchPathCheck(lp *core.LocalPolicy) core.ConfigCheck {
	c := core.ConfigCheck{ID: CheckKillSwitchPath, Keys: []string{core.EnvKillSwitchFile}}
	files := lp.KillSwitchFiles()
	if len(files) == 0 {
		c.Status, c.Code = core.CheckWarn, "not_set"
		c.Summary = "no kill switch file: set " + core.EnvKillSwitchFile + "=" + RecommendedKillSwitchFile + " and mount " + filepath.Dir(RecommendedKillSwitchFile) +
			" from the host read-only at the same path, so creating that file on the host stops every job"
		return c
	}
	c.Params = map[string]core.ConfigParam{"path": core.ParamPath(files[0])}
	if lp.KillSwitchEngaged() {
		c.Status, c.Code = core.CheckWarn, "engaged"
		c.Summary = "the kill switch is engaged (" + files[0] + " exists): the sensor refuses every job until it is removed"
		return c
	}
	if _, err := os.Stat(filepath.Dir(files[0])); err != nil {
		c.Status, c.Code = core.CheckWarn, "dir_missing"
		c.Summary = "the kill switch directory " + filepath.Dir(files[0]) + " does not exist here: mount it from the host, or creating the file there stops nothing"
		return c
	}
	c.Status, c.Code, c.Keys = core.CheckPass, "ready", nil
	c.Summary = "creating " + files[0] + " stops every job"
	return c
}

// writeDoctorTable prints the results for a person: one line per check,
// failures first.
func writeDoctorTable(w io.Writer, r *DoctorReport) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STATUS\tCHECK\tCODE\tDETAIL")
	for _, c := range r.Checks {
		detail := c.Summary
		if c.Excerpt != "" {
			detail += " (" + c.Excerpt + ")"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strings.ToUpper(c.Status), c.ID, c.Code, detail)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintf(w, "\n%d passed, %d warnings, %d failures, %d skipped (sdk-go %s)\n",
		r.Summary.Pass, r.Summary.Warn, r.Summary.Fail, r.Summary.Skip, r.SDKVersion)
}
