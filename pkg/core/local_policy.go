package core

// The sensor-local policy (api RFC-040 §5.7, docs/rfcs/RFC-040-platform-
// sensor-mutual-distrust.md in openctemio/openctem): a read-only file the
// network owner writes when the sensor is installed. The sensor refuses every
// job outside it, even a job the platform sent and signed. The platform has
// no route to change it; it only sees the digest and a summary on the
// heartbeat and the manifest (LocalPolicyReport).
//
// Loading fails closed: an unknown key, a malformed entry, a second YAML
// document, an empty or world-writable file, or a path that was configured
// but cannot be read is an error, and a sensor that cannot load its policy
// does not start.
//
// A sensor with no policy at all depends on whether it requires one
// (LocalPolicy.Required: SENSOR_REQUIRE_LOCAL_POLICY, else whether its
// paired identity was created by an SDK that fails closed). A sensor that
// requires one refuses every job with network targets, custom templates and
// out-of-band callbacks until a policy is installed (rule no_local_policy);
// jobs without network targets still run. A legacy sensor works as before
// (owner decision Q3 (a)): it reports local_policy "absent" with required
// false, and warns.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

// Local policy settings and limits.
const (
	// EnvLocalPolicy is the path of the local policy file. Unset, the
	// sensor reads DefaultLocalPolicyPath when it exists.
	EnvLocalPolicy = "SENSOR_LOCAL_POLICY"
	// DefaultLocalPolicyPath is where an install mounts the policy
	// read-only.
	DefaultLocalPolicyPath = "/etc/openctem/sensor-policy.yaml"
	// EnvAllowedRanges is a shorthand policy without a file: a
	// comma-separated targets.allow list (CIDRs, IPs, domains, *.domains;
	// *.x covers x and every name below it).
	EnvAllowedRanges = "SENSOR_ALLOWED_RANGES"
	// EnvAllowedPorts is a shorthand policy without a file: ports.allow
	// ("1-1024,3389").
	EnvAllowedPorts = "SENSOR_ALLOWED_PORTS"
	// EnvKillSwitchFile names a file whose presence stops every job, with
	// or without a policy file.
	EnvKillSwitchFile = "SENSOR_KILL_SWITCH_FILE"
	// EnvRequireLocalPolicy (true/false) decides whether the sensor fails
	// closed without a local policy. Set, it wins; unset, the caller decides
	// (LocalPolicyOptions.Required: the sensor kit requires a policy for an
	// identity paired by an SDK that fails closed).
	EnvRequireLocalPolicy = "SENSOR_REQUIRE_LOCAL_POLICY"

	// LocalPolicyRuleNoPolicy is the rule of a job refused because the
	// sensor requires a local policy and has none.
	LocalPolicyRuleNoPolicy = "no_local_policy"

	// LocalPolicyAPIVersion is the apiVersion of schema v1. v1 is frozen:
	// it never gains a key, because a sensor refuses a file with a key it
	// does not know, so a new v1 key would stop every older sensor (owner
	// decision D13, api research/25 §3.3). New keys go into a new version.
	LocalPolicyAPIVersion = "openctem.io/sensor-policy/v1"
	// LocalPolicyAPIVersionV2 is the apiVersion of schema v2: every v1 key
	// plus managed (see policyFileV2).
	LocalPolicyAPIVersionV2 = "openctem.io/sensor-policy/v2"
	// LocalPolicyAPIVersionV3 is the apiVersion of schema v3: every v2 key
	// plus http (see policyFileV3).
	LocalPolicyAPIVersionV3 = "openctem.io/sensor-policy/v3"
	// MaxLocalPolicyBytes bounds the policy file.
	MaxLocalPolicyBytes = 1 << 20
	// MaxLocalPolicyEntries bounds each list in the policy.
	MaxLocalPolicyEntries = 4096

	// MaxScanTimeout caps a scan command's timeout_seconds whatever the
	// platform sends (api RFC-040 P0); a local policy can lower it.
	MaxScanTimeout = 24 * time.Hour
)

// LocalPolicySchemas are the local policy schema versions this SDK reads,
// as LocalPolicyReport.Schemas reports them: the platform generates a
// recommended policy only in a version the sensor lists, so a downloaded
// file never stops a sensor.
var LocalPolicySchemas = []string{"v1", "v2", "v3"}

// Local policy states, as LocalPolicyReport.State reports them.
const (
	// LocalPolicyStateEnforced: a policy is loaded and every job is
	// checked against it.
	LocalPolicyStateEnforced = "enforced"
	// LocalPolicyStateAbsent: no policy; the sensor works as before
	// (built-in deny list and the private-range switch only).
	LocalPolicyStateAbsent = "absent"
)

// Local policy sources, as LocalPolicyReport.Source reports them.
const (
	LocalPolicySourceFile = "file"
	LocalPolicySourceEnv  = "env"
)

// ErrRefusedByLocalPolicy is the error every refusal by the local policy
// wraps (see LocalPolicyError).
var ErrRefusedByLocalPolicy = errors.New("refused by local policy")

// LocalPolicyError is a job refused by the local policy: Rule names the
// policy key that refused it (targets.allow, ports.allow, kill_switch, …)
// and Detail the offending item. Its text is what the platform shows:
// "refused by local policy: <rule>: <detail>".
type LocalPolicyError struct {
	// Layer is the policy layer that refused (RefusalLayer*); "" is the
	// local policy.
	Layer  string
	Rule   string
	Detail string
}

func (e *LocalPolicyError) Error() string {
	if e.Detail == "" {
		return ErrRefusedByLocalPolicy.Error() + ": " + e.Rule
	}
	return ErrRefusedByLocalPolicy.Error() + ": " + e.Rule + ": " + e.Detail
}

// Unwrap makes errors.Is(err, ErrRefusedByLocalPolicy) true.
func (e *LocalPolicyError) Unwrap() error { return ErrRefusedByLocalPolicy }

func refuse(rule, format string, args ...any) error {
	return &LocalPolicyError{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

// LocalPolicyOptions say where LoadLocalPolicy finds the policy.
type LocalPolicyOptions struct {
	// Path is the policy file (a sensor's flag). "" reads EnvLocalPolicy,
	// then DefaultPath when that file exists. A path given here or in the
	// environment must exist.
	Path string
	// DefaultPath replaces DefaultLocalPolicyPath (tests).
	DefaultPath string
	// LookupEnv reads the environment (nil: os.LookupEnv).
	LookupEnv func(string) (string, bool)
	// LookupIP resolves host names for target checks (nil:
	// net.DefaultResolver).
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
	// Required makes a sensor without a policy fail closed (see
	// LocalPolicy.Required). EnvRequireLocalPolicy, when set, wins.
	Required bool
}

// LocalPolicy is the loaded sensor-local policy. It is immutable once
// loaded; only the kill switch file is read live. A nil *LocalPolicy, like
// an absent one, restricts nothing but the built-in deny list.
type LocalPolicy struct {
	present bool
	// required: without a policy, jobs with network targets, custom
	// templates and callbacks are refused (Required).
	required bool
	source   string
	path     string
	digest   string

	targetsAllowSet bool
	allowNets       []*net.IPNet
	denyNets        []*net.IPNet
	allowDomains    []domainPattern
	denyDomains     []domainPattern
	allowPrivate    bool
	allowLoopback   bool // tests only

	ports     []portRange // nil: any port
	portsText string

	tools  []string // nil: any tool
	checks []string // nil: any check type

	allowCustomTemplates bool
	allowInteractsh      bool
	// httpUserAgent replaces every tool's User-Agent ("": the tools');
	// allowInsecureTLS false refuses tools that skip TLS verification.
	httpUserAgent    string
	allowInsecureTLS bool

	// schema is the file's schema version ("v1", "v2"); "" without a file.
	schema string
	// managedAccept is managed.accept (v2; true when absent): false means
	// the sensor owner refuses every platform-managed policy document
	// (owner decision D11).
	managedAccept bool

	maxRPS        int
	maxJobSeconds int

	killSwitch      bool
	killSwitchFiles []string
	// reloadFailed is why a reload of the policy failed (ReloadLocalPolicy):
	// set, every job is stopped until a reload succeeds.
	reloadFailed string

	warnings []string
	lookupIP func(ctx context.Context, host string) ([]net.IP, error)
}

// policyFile is the policy document. Every key is optional except
// apiVersion; an absent section restricts nothing, an absent switch is off.
type policyFile struct {
	APIVersion string `yaml:"apiVersion"`
	Targets    *struct {
		Allow        []string `yaml:"allow"`
		Deny         []string `yaml:"deny"`
		AllowPrivate *bool    `yaml:"allow_private"`
	} `yaml:"targets"`
	Ports *struct {
		Allow *string `yaml:"allow"`
	} `yaml:"ports"`
	Tools *struct {
		Allow []string `yaml:"allow"`
	} `yaml:"tools"`
	Checks *struct {
		Allow []string `yaml:"allow"`
	} `yaml:"checks"`
	AllowCustomTemplates *bool `yaml:"allow_custom_templates"`
	AllowInteractsh      *bool `yaml:"allow_interactsh"`
	Rate                 *struct {
		MaxRPS        *int `yaml:"max_rps"`
		MaxJobSeconds *int `yaml:"max_job_seconds"`
	} `yaml:"rate"`
	KillSwitch     bool   `yaml:"kill_switch"`
	KillSwitchFile string `yaml:"kill_switch_file"`
}

// policyFileV2 is schema v2: every v1 key, plus managed. Like v1 it is
// frozen once released; later keys go into v3.
type policyFileV2 struct {
	policyFile `yaml:",inline"`
	// Managed decides whether the platform may narrow this policy further
	// with a managed document (api research/25 §3.5). It is read only from
	// this file, never from the network.
	Managed *struct {
		// Accept false: the sensor ignores every platform-managed policy
		// and the platform shows it as locked by its owner. Default true.
		Accept *bool `yaml:"accept"`
	} `yaml:"managed"`
}

// policyFileV3 is schema v3: every v2 key, plus http. Frozen once
// released, like v1 and v2.
type policyFileV3 struct {
	policyFileV2 `yaml:",inline"`
	// HTTP is what the owner of this network decides about the tools'
	// requests, whatever a tool's tool.yaml says (api RFC-060 §4.1).
	HTTP *struct {
		// UserAgent replaces every tool's User-Agent (a scanner the
		// network's owners recognize in their logs).
		UserAgent *string `yaml:"user_agent"`
		// AllowInsecureTLS false refuses tasks of tools that skip
		// certificate verification. Default true.
		AllowInsecureTLS *bool `yaml:"allow_insecure_tls"`
	} `yaml:"http"`
}

// domainPattern is a targets entry naming hosts: an exact name, or
// "*.x" for x itself and every name below it, at any depth. This is the
// platform's reading of a scope pattern (api RFC-054 §4.1), so an allow
// entry and a platform scope entry cover the same names. A deny entry uses
// the same matcher: "*.x" in targets.deny also denies x. Names are compared
// lower-case, without one trailing dot, in their IDNA ASCII form.
type domainPattern struct {
	name     string
	wildcard bool
}

func (d domainPattern) matches(host string) bool {
	host = canonicalHostName(host)
	if d.wildcard {
		return host == d.name || strings.HasSuffix(host, "."+d.name)
	}
	return host == d.name
}

// canonicalHostName lower-cases a host name, trims spaces and one trailing
// dot, and converts an internationalized name to its IDNA ASCII form. A
// name that does not convert is returned lower-cased: it then matches only
// an identical pattern, never a wider one.
func canonicalHostName(s string) string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			if a, err := idna.Lookup.ToASCII(s); err == nil {
				return strings.ToLower(a)
			}
			return s
		}
	}
	return s
}

type portRange struct{ lo, hi int }

// LoadLocalPolicy loads the sensor-local policy: the file at opts.Path, else
// at SENSOR_LOCAL_POLICY, else at DefaultLocalPolicyPath when it exists;
// without a file, the SENSOR_ALLOWED_RANGES / SENSOR_ALLOWED_PORTS
// shorthands; without those, an absent policy (Present false) that still
// honors SENSOR_KILL_SWITCH_FILE. Any error means the sensor must not start.
func LoadLocalPolicy(opts LocalPolicyOptions) (*LocalPolicy, error) {
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	env := func(name string) string {
		v, _ := lookup(name)
		return strings.TrimSpace(v)
	}

	path, explicit := strings.TrimSpace(opts.Path), true
	if path == "" {
		path = env(EnvLocalPolicy)
	}
	if path == "" {
		explicit = false
		path = opts.DefaultPath
		if path == "" {
			path = DefaultLocalPolicyPath
		}
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			path = ""
		} else if err != nil {
			return nil, fmt.Errorf("local policy %s: %w", path, err)
		}
	}

	ranges, ports := env(EnvAllowedRanges), env(EnvAllowedPorts)
	var (
		lp  *LocalPolicy
		err error
	)
	switch {
	case path != "":
		if ranges != "" || ports != "" {
			return nil, fmt.Errorf("local policy %s: %s and %s are shorthands for a policy without a file; with a file, put the ranges and ports in it and unset them", path, EnvAllowedRanges, EnvAllowedPorts)
		}
		lp, err = readPolicyFile(path, explicit, lookup)
	case ranges != "" || ports != "":
		lp, err = policyFromEnv(ranges, ports, lookup)
	default:
		lp = absentPolicy()
	}
	if err != nil {
		return nil, err
	}
	lp.required = opts.Required
	if v, set, err := RequireLocalPolicyFromEnv(lookup); err != nil {
		return nil, err
	} else if set {
		lp.required = v
	}
	if f := env(EnvKillSwitchFile); f != "" {
		if !filepath.IsAbs(f) {
			return nil, fmt.Errorf("%s=%q must be an absolute path", EnvKillSwitchFile, f)
		}
		f = filepath.Clean(f)
		if !slices.Contains(lp.killSwitchFiles, f) {
			lp.killSwitchFiles = append(lp.killSwitchFiles, f)
		}
	}
	lp.lookupIP = opts.LookupIP
	return lp, nil
}

func readPolicyFile(path string, explicit bool, lookup func(string) (string, bool)) (*LocalPolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && explicit {
			return nil, fmt.Errorf("local policy %s does not exist (configured with -local-policy or %s)", path, EnvLocalPolicy)
		}
		return nil, fmt.Errorf("local policy %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("local policy %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("local policy %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("local policy %s is writable by every user (mode %v); make it read-only (0644, owned by root)", path, st.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxLocalPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("local policy %s: %w", path, err)
	}
	if len(data) > MaxLocalPolicyBytes {
		return nil, fmt.Errorf("local policy %s is larger than %d bytes", path, MaxLocalPolicyBytes)
	}
	lp, err := parsePolicy(data, lookup)
	if err != nil {
		return nil, fmt.Errorf("local policy %s: %w", path, err)
	}
	lp.source, lp.path = LocalPolicySourceFile, path
	return lp, nil
}

// ParseLocalPolicy parses and validates a policy document (the content of
// the policy file). The private-range switch (SENSOR_ALLOW_PRIVATE_TARGETS)
// is read from opts.LookupEnv: a private target is allowed only when both
// the switch and targets.allow_private allow it.
func ParseLocalPolicy(data []byte, opts LocalPolicyOptions) (*LocalPolicy, error) {
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	lp, err := parsePolicy(data, lookup)
	if err != nil {
		return nil, err
	}
	lp.source = LocalPolicySourceFile
	lp.lookupIP = opts.LookupIP
	return lp, nil
}

func parsePolicy(data []byte, lookup func(string) (string, bool)) (*LocalPolicy, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("the policy is empty")
	}
	// The version first (a lenient read of apiVersion alone), then the
	// whole document strictly against that version's keys: a v1 file with
	// a v2 key is refused, as every v1-only sensor refuses it.
	var head struct {
		APIVersion string `yaml:"apiVersion"`
	}
	if err := yaml.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	var (
		doc    policyFile
		target any
		v2     policyFileV2
		v3     policyFileV3
		schema string
	)
	switch head.APIVersion {
	case LocalPolicyAPIVersion:
		target, schema = &doc, "v1"
	case LocalPolicyAPIVersionV2:
		target, schema = &v2, "v2"
	case LocalPolicyAPIVersionV3:
		target, schema = &v3, "v3"
	default:
		return nil, fmt.Errorf("apiVersion is %q; it must be %q, %q or %q", head.APIVersion, LocalPolicyAPIVersion, LocalPolicyAPIVersionV2, LocalPolicyAPIVersionV3)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(target); err != nil {
		return nil, fmt.Errorf("invalid policy (schema %s): %w", schema, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid policy: more than one YAML document")
	}
	managedAccept := true
	if schema == "v3" {
		v2 = v3.policyFileV2
	}
	if schema == "v2" || schema == "v3" {
		doc = v2.policyFile
		if m := v2.Managed; m != nil && m.Accept != nil {
			managedAccept = *m.Accept
		}
	}

	sum := sha256.Sum256(data)
	lp := &LocalPolicy{present: true, digest: "sha256:" + hex.EncodeToString(sum[:]), schema: schema, managedAccept: managedAccept}
	envPrivate := privateSwitch(lookup)

	if t := doc.Targets; t != nil {
		if t.AllowPrivate != nil {
			lp.allowPrivate = *t.AllowPrivate && envPrivate
			if *t.AllowPrivate && !envPrivate {
				lp.warnings = append(lp.warnings, fmt.Sprintf("targets.allow_private is true but %s is not 1: private targets stay refused", EnvSensorAllowPrivateTargets))
			}
		}
		if t.Allow != nil {
			lp.targetsAllowSet = true
			if err := lp.addTargets("targets.allow", t.Allow, true, t.AllowPrivate != nil && *t.AllowPrivate); err != nil {
				return nil, err
			}
		}
		if err := lp.addTargets("targets.deny", t.Deny, false, false); err != nil {
			return nil, err
		}
	}
	if p := doc.Ports; p != nil {
		if p.Allow == nil {
			return nil, errors.New("ports: allow is required in a ports section")
		}
		ranges, err := parsePorts(*p.Allow)
		if err != nil {
			return nil, fmt.Errorf("ports.allow: %w", err)
		}
		lp.ports, lp.portsText = ranges, strings.Join(strings.Fields(*p.Allow), "")
	}
	if t := doc.Tools; t != nil {
		names, err := policyNames("tools.allow", t.Allow, true)
		if err != nil {
			return nil, err
		}
		lp.tools = names
	}
	if c := doc.Checks; c != nil {
		names, err := policyNames("checks.allow", c.Allow, false)
		if err != nil {
			return nil, err
		}
		lp.checks = names
	}
	lp.allowCustomTemplates = doc.AllowCustomTemplates != nil && *doc.AllowCustomTemplates
	lp.allowInteractsh = doc.AllowInteractsh != nil && *doc.AllowInteractsh
	lp.allowInsecureTLS = true
	if h := v3.HTTP; h != nil {
		if h.UserAgent != nil {
			ua := *h.UserAgent
			if ua == "" || len(ua) > 256 || strings.IndexFunc(ua, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
				return nil, errors.New("http.user_agent must be 1 to 256 printable ASCII characters")
			}
			lp.httpUserAgent = ua
		}
		if h.AllowInsecureTLS != nil {
			lp.allowInsecureTLS = *h.AllowInsecureTLS
		}
	}
	if r := doc.Rate; r != nil {
		if r.MaxRPS != nil {
			if *r.MaxRPS < 1 || *r.MaxRPS > MaxScanLimit {
				return nil, fmt.Errorf("rate.max_rps must be from 1 to %d", MaxScanLimit)
			}
			lp.maxRPS = *r.MaxRPS
		}
		if r.MaxJobSeconds != nil {
			if *r.MaxJobSeconds < 1 || *r.MaxJobSeconds > int(MaxScanTimeout/time.Second) {
				return nil, fmt.Errorf("rate.max_job_seconds must be from 1 to %d", int(MaxScanTimeout/time.Second))
			}
			lp.maxJobSeconds = *r.MaxJobSeconds
		}
	}
	lp.killSwitch = doc.KillSwitch
	if f := strings.TrimSpace(doc.KillSwitchFile); f != "" {
		if !filepath.IsAbs(f) {
			return nil, fmt.Errorf("kill_switch_file %q must be an absolute path", f)
		}
		lp.killSwitchFiles = []string{filepath.Clean(f)}
	} else if doc.KillSwitchFile != "" {
		return nil, errors.New("kill_switch_file is blank")
	}
	return lp, nil
}

// policyFromEnv builds the shorthand policy (SENSOR_ALLOWED_RANGES,
// SENSOR_ALLOWED_PORTS). Private ranges follow the private-range switch.
func policyFromEnv(ranges, ports string, lookup func(string) (string, bool)) (*LocalPolicy, error) {
	envPrivate := privateSwitch(lookup)
	lp := &LocalPolicy{present: true, source: LocalPolicySourceEnv, allowPrivate: envPrivate, managedAccept: true}
	if ranges != "" {
		lp.targetsAllowSet = true
		if err := lp.addTargets(EnvAllowedRanges, splitList(ranges), true, envPrivate); err != nil {
			return nil, err
		}
	}
	if ports != "" {
		r, err := parsePorts(ports)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvAllowedPorts, err)
		}
		lp.ports, lp.portsText = r, strings.Join(strings.Fields(ports), "")
	}
	// The digest identifies the shorthand settings the way a file digest
	// identifies a file.
	sum := sha256.Sum256([]byte(EnvAllowedRanges + "=" + ranges + "\n" + EnvAllowedPorts + "=" + ports + "\n"))
	lp.digest = "sha256:" + hex.EncodeToString(sum[:])
	lp.warnings = append(lp.warnings, fmt.Sprintf("local policy from %s/%s: custom templates and out-of-band callbacks are refused; write a policy file to allow them", EnvAllowedRanges, EnvAllowedPorts))
	return lp, nil
}

// RequireLocalPolicyFromEnv reads EnvRequireLocalPolicy: set reports
// whether it is set (to anything but blanks), required its value. A value
// that is not a boolean is an error: the sensor must not guess its posture.
func RequireLocalPolicyFromEnv(lookup func(string) (string, bool)) (required, set bool, err error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	v, ok := lookup(EnvRequireLocalPolicy)
	if v = strings.TrimSpace(v); !ok || v == "" {
		return false, false, nil
	}
	b, perr := strconv.ParseBool(v)
	if perr != nil {
		return false, false, fmt.Errorf("%s=%q is not recognized: set it to true (refuse network jobs without a local policy) or false", EnvRequireLocalPolicy, v)
	}
	return b, true, nil
}

// noLocalPolicyHelp is what the operator of a sensor that requires a local
// policy must do.
const noLocalPolicyHelp = "this sensor requires a sensor-local policy and has none: install " + DefaultLocalPolicyPath +
	" (or point " + EnvLocalPolicy + " at one), or set " + EnvAllowedRanges

func absentPolicy() *LocalPolicy {
	return &LocalPolicy{
		// Owner decision Q4 (a): existing installs keep their behavior,
		// with a warning, until they write a policy. A sensor that
		// requires a policy refuses both (failsClosed).
		allowCustomTemplates: true,
		allowInteractsh:      true,
		managedAccept:        true,
	}
}

// absentWarnings are the warnings of a sensor without a policy.
func absentWarnings(required bool) []string {
	if required {
		return []string{
			"no local policy: " + noLocalPolicyHelp + "; until then every job with network targets is refused (" +
				LocalPolicyRuleNoPolicy + "), and so are custom templates and out-of-band callbacks; jobs without network targets still run",
		}
	}
	return []string{
		"no local policy: this sensor runs any target the platform sends outside the built-in deny list (legacy install, api RFC-040 Q3); install " +
			DefaultLocalPolicyPath + ", or set " + EnvRequireLocalPolicy + "=true to refuse network jobs without one",
		// What actually happens (api research/25 §0.5): callbacks run
		// only when a job asks for them, and custom templates only
		// with pinned signing keys.
		"no local policy: jobs may enable out-of-band callbacks (interactsh), and custom templates run when SENSOR_TEMPLATE_SIGNING_KEYS is set; install " + DefaultLocalPolicyPath + " with allow_interactsh and allow_custom_templates to decide",
	}
}

// failsClosed reports whether lp has no policy and requires one: every
// network target, custom template and callback is refused.
func (lp *LocalPolicy) failsClosed() bool { return lp != nil && !lp.present && lp.required }

// Required reports whether the sensor requires a local policy: without
// one it refuses every job with network targets (rule no_local_policy),
// custom templates and out-of-band callbacks. False is a legacy install,
// which without a policy admits any target outside the built-in deny list.
func (lp *LocalPolicy) Required() bool { return lp != nil && lp.required }

// WithRequired returns a copy of lp (of the absent policy when lp is nil)
// that requires a local policy or not. The copy shares lp's lists, which
// are never modified after loading.
func (lp *LocalPolicy) WithRequired(required bool) *LocalPolicy {
	var cp LocalPolicy
	if lp != nil {
		cp = *lp
	} else {
		cp = *absentPolicy()
	}
	cp.required = required
	return &cp
}

// privateSwitch reads the existing private-range switch the way the scan
// target policy does.
func privateSwitch(lookup func(string) (string, bool)) bool {
	for _, name := range []string{EnvSensorAllowPrivateTargets, EnvAllowPrivateTargets} {
		if v, ok := lookup(name); ok && strings.TrimSpace(v) == "1" {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// addTargets parses CIDRs, IPs and domain patterns into the allow or deny
// lists. An allow entry may not name a range that is always blocked, nor a
// private range unless allowPrivate.
func (lp *LocalPolicy) addTargets(key string, entries []string, allow, allowPrivate bool) error {
	if len(entries) > MaxLocalPolicyEntries {
		return fmt.Errorf("%s has %d entries, more than %d", key, len(entries), MaxLocalPolicyEntries)
	}
	for _, raw := range entries {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			return fmt.Errorf("%s has an empty entry", key)
		}
		if n, err := parseNet(e); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		} else if n != nil {
			if allow {
				if blockedAlways(n.IP) {
					return fmt.Errorf("%s: %s is always blocked (loopback, link-local, metadata or reserved addresses)", key, n)
				}
				if n.IP.IsPrivate() && !allowPrivate {
					return fmt.Errorf("%s: %s is a private range; set targets.allow_private: true (and %s=1) to scan it", key, n, EnvSensorAllowPrivateTargets)
				}
				lp.allowNets = append(lp.allowNets, n)
			} else {
				lp.denyNets = append(lp.denyNets, n)
			}
			continue
		}
		d, err := parseDomainPattern(e)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if allow {
			lp.allowDomains = append(lp.allowDomains, d)
		} else {
			lp.denyDomains = append(lp.denyDomains, d)
		}
	}
	return nil
}

// parseNet returns the network of a CIDR or IP entry, nil for an entry that
// is neither (a domain). A CIDR with host bits set is an error: it usually
// means a typo in the prefix.
func parseNet(e string) (*net.IPNet, error) {
	if strings.Contains(e, "/") {
		ip, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid CIDR", e)
		}
		if !ip.Equal(n.IP) {
			return nil, fmt.Errorf("%q has host bits set; the network is %s", e, n)
		}
		return n, nil
	}
	ip := net.ParseIP(e)
	if ip == nil {
		return nil, nil
	}
	bits := 128
	if ip4 := ip.To4(); ip4 != nil {
		ip, bits = ip4, 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

func parseDomainPattern(e string) (domainPattern, error) {
	d := domainPattern{name: canonicalHostName(e)}
	if rest, ok := strings.CutPrefix(d.name, "*."); ok {
		d.name, d.wildcard = canonicalHostName(rest), true
	}
	if !validHostname(d.name) || (d.wildcard && !strings.Contains(d.name, ".")) {
		return domainPattern{}, fmt.Errorf("%q is not a CIDR, an IP address, a host name or *.domain", e)
	}
	return d, nil
}

func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

func parsePorts(s string) ([]portRange, error) {
	var out []portRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("%q has an empty item", s)
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = parsePort(hi); err != nil {
				return nil, err
			}
		}
		if b < a {
			return nil, fmt.Errorf("port range %q is reversed", part)
		}
		out = append(out, portRange{a, b})
		if len(out) > MaxLocalPolicyEntries {
			return nil, fmt.Errorf("more than %d port items", MaxLocalPolicyEntries)
		}
	}
	return out, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q is not a port from 1 to 65535", s)
	}
	return n, nil
}

// policyNames normalizes a tools or checks list: lower case, no blanks or
// duplicates; tools take their canonical scanner name. An empty list is
// valid and allows nothing.
func policyNames(key string, names []string, tools bool) ([]string, error) {
	if len(names) > MaxLocalPolicyEntries {
		return nil, fmt.Errorf("%s has more than %d entries", key, MaxLocalPolicyEntries)
	}
	out := make([]string, 0, len(names))
	for _, raw := range names {
		n := strings.ToLower(strings.TrimSpace(raw))
		if tools {
			n = strings.ToLower(CanonicalScannerName(n))
		}
		if n == "" {
			return nil, fmt.Errorf("%s has an empty entry", key)
		}
		for _, r := range n {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
				return nil, fmt.Errorf("%s: %q is not a valid name", key, raw)
			}
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Present reports whether a policy is loaded (from a file or the
// shorthands). An absent policy restricts nothing but the kill switch.
func (lp *LocalPolicy) Present() bool { return lp != nil && lp.present }

// Digest is the policy's digest ("sha256:…" of the file bytes), "" when
// absent.
func (lp *LocalPolicy) Digest() string {
	if lp == nil {
		return ""
	}
	return lp.digest
}

// Path is the policy file, "" without one.
func (lp *LocalPolicy) Path() string {
	if lp == nil {
		return ""
	}
	return lp.path
}

// Warnings are what an operator should know about the policy (absent, a
// switch that cannot take effect). The sensor logs them at start and
// reports them on the heartbeat.
func (lp *LocalPolicy) Warnings() []string {
	if lp == nil {
		return absentWarnings(false)
	}
	var out []string
	if !lp.present {
		out = absentWarnings(lp.required)
	}
	return append(out, lp.warnings...)
}

// AllowsCustomTemplates reports whether jobs may carry platform-supplied
// custom templates (still only signed ones). Without a policy: true on a
// legacy install (owner decision Q4 (a)), false when a policy is required;
// a policy allows them only with allow_custom_templates.
func (lp *LocalPolicy) AllowsCustomTemplates() bool {
	return lp == nil || (lp.allowCustomTemplates && !lp.failsClosed())
}

// AllowsInteractsh reports whether a job may turn on out-of-band callbacks.
// Without a policy: true on a legacy install (Q4 (a)), false when a policy
// is required; a policy allows them only with allow_interactsh.
func (lp *LocalPolicy) AllowsInteractsh() bool {
	return lp == nil || (lp.allowInteractsh && !lp.failsClosed())
}

// HTTPPolicy is what the policy decides about the tools' requests: a
// User-Agent that replaces every tool's ("" none), and whether a tool may
// skip TLS verification toward its targets. Without a policy: none, yes.
func (lp *LocalPolicy) HTTPPolicy() (userAgent string, allowInsecureTLS bool) {
	if !lp.Present() {
		return "", true
	}
	return lp.httpUserAgent, lp.allowInsecureTLS
}

// Schema is the policy file's schema version ("v1", "v2"), "" without a
// file.
func (lp *LocalPolicy) Schema() string {
	if lp == nil {
		return ""
	}
	return lp.schema
}

// AcceptsManagedPolicy reports whether the sensor owner lets the platform
// narrow this policy with a managed document (v2 managed.accept; true
// without a policy or the key). A managed policy never widens the local
// one; this only decides whether it is read at all (owner decision D11).
func (lp *LocalPolicy) AcceptsManagedPolicy() bool {
	return lp == nil || !lp.present || lp.managedAccept
}

// AllowsTool reports whether tools.allow lets tool run (always without a
// policy or a tools section).
func (lp *LocalPolicy) AllowsTool(tool string) bool {
	if !lp.Present() || lp.tools == nil {
		return true
	}
	return slices.Contains(lp.tools, strings.ToLower(CanonicalScannerName(strings.TrimSpace(tool))))
}

// AllowsCheck reports whether checks.allow lets a command type run.
// health_check touches no target and is always allowed.
func (lp *LocalPolicy) AllowsCheck(commandType string) bool {
	if !lp.Present() || lp.checks == nil || commandType == "health_check" {
		return true
	}
	return slices.Contains(lp.checks, strings.ToLower(commandType))
}

// CapRate returns the requests-per-second a scan runs with under the
// policy's rate.max_rps: requested when set and lower, else the maximum.
// Without a maximum it returns requested.
func (lp *LocalPolicy) CapRate(requested int) int {
	if !lp.Present() || lp.maxRPS == 0 {
		return requested
	}
	return CapScanLimit(requested, 0, lp.maxRPS)
}

// CapTimeout returns how long a job may run: requested (0: no limit asked)
// capped at MaxScanTimeout and at the policy's rate.max_job_seconds.
func (lp *LocalPolicy) CapTimeout(requested time.Duration) time.Duration {
	limit := MaxScanTimeout
	if lp.Present() && lp.maxJobSeconds > 0 {
		limit = time.Duration(lp.maxJobSeconds) * time.Second
	}
	if requested <= 0 {
		if lp.Present() && lp.maxJobSeconds > 0 {
			return limit
		}
		return 0
	}
	return min(requested, limit)
}

// KillSwitchEngaged reports whether the sensor owner stopped every job: the
// policy's kill_switch, or a kill switch file that exists. A file that
// cannot be checked (permission denied) counts as present.
func (lp *LocalPolicy) KillSwitchEngaged() bool {
	return lp.killSwitchReason() != ""
}

func (lp *LocalPolicy) killSwitchReason() string {
	if lp == nil {
		return ""
	}
	if lp.reloadFailed != "" {
		return "the local policy could not be reloaded: " + lp.reloadFailed
	}
	if lp.killSwitch {
		return "kill_switch is set in the local policy"
	}
	for _, f := range lp.killSwitchFiles {
		if _, err := os.Lstat(f); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return "kill switch file " + f + " is present"
		}
	}
	return ""
}

// LocalPolicyReport is what the sensor tells the platform about its local
// policy: the state, the digest and a summary, never the ranges themselves.
// The platform shows it; enforcement stays on the sensor.
type LocalPolicyReport struct {
	// State is LocalPolicyStateEnforced or LocalPolicyStateAbsent.
	State string `json:"state"`
	// Required is true when the sensor requires a local policy (new
	// installs): absent, it refuses every job with network targets. State
	// absent with Required false is a legacy install that admits any
	// target outside the built-in deny list. Always sent; an SDK that
	// predates it sends none, which reads as false.
	Required bool `json:"required"`
	// Source is LocalPolicySourceFile or LocalPolicySourceEnv ("" when
	// absent).
	Source string `json:"source,omitempty"`
	// Digest is the policy's sha256 digest ("" when absent).
	Digest string `json:"digest,omitempty"`
	// KillSwitch is true while the sensor owner has stopped every job.
	KillSwitch bool `json:"kill_switch,omitempty"`
	// Summary is set when a policy is enforced.
	Summary *LocalPolicySummary `json:"summary,omitempty"`
	// Warnings are the operator warnings (see LocalPolicy.Warnings).
	Warnings []string `json:"warnings,omitempty"`
	// Schema is the policy file's schema version ("v1", "v2"); "" without
	// a file.
	Schema string `json:"schema,omitempty"`
	// Schemas are the schema versions this sensor reads
	// (LocalPolicySchemas): the platform generates a recommended policy
	// only in one of them.
	Schemas []string `json:"schemas,omitempty"`
}

// LocalPolicySummary is the shape of an enforced policy: counts for the
// target lists, the lists that routing needs (tools, check types), and the
// switches.
type LocalPolicySummary struct {
	// TargetsAllow is the number of targets.allow entries; -1 when the
	// policy sets no allow list (any target outside the deny lists).
	TargetsAllow int `json:"targets_allow"`
	// TargetsDeny is the number of targets.deny entries.
	TargetsDeny int `json:"targets_deny"`
	// AllowPrivate: private ranges may be scanned (the policy and the
	// private-range switch agree).
	AllowPrivate bool `json:"allow_private"`
	// Ports is ports.allow ("" = any port).
	Ports string `json:"ports,omitempty"`
	// Tools and Checks are tools.allow and checks.allow (absent = any).
	Tools  []string `json:"tools,omitempty"`
	Checks []string `json:"checks,omitempty"`
	// AllowCustomTemplates and AllowInteractsh are the policy's switches.
	AllowCustomTemplates bool `json:"allow_custom_templates"`
	AllowInteractsh      bool `json:"allow_interactsh"`
	// MaxRPS and MaxJobSeconds are rate.max_rps and rate.max_job_seconds
	// (0 = not set).
	MaxRPS        int `json:"max_rps,omitempty"`
	MaxJobSeconds int `json:"max_job_seconds,omitempty"`
	// ManagedAccept is managed.accept (v2): false when the sensor owner
	// refuses platform-managed policy documents.
	ManagedAccept bool `json:"managed_accept"`
	// HTTPUserAgent is http.user_agent (v3): the User-Agent forced on
	// every tool ("" none). AllowInsecureTLS is http.allow_insecure_tls.
	HTTPUserAgent    string `json:"http_user_agent,omitempty"`
	AllowInsecureTLS bool   `json:"allow_insecure_tls"`
}

// Report is the policy's state now (the kill switch is read live).
func (lp *LocalPolicy) Report() *LocalPolicyReport {
	r := &LocalPolicyReport{State: LocalPolicyStateAbsent, Required: lp.Required(), KillSwitch: lp.KillSwitchEngaged(),
		Warnings: lp.Warnings(), Schemas: slices.Clone(LocalPolicySchemas)}
	if !lp.Present() {
		return r
	}
	r.State, r.Source, r.Digest, r.Schema = LocalPolicyStateEnforced, lp.source, lp.digest, lp.schema
	s := &LocalPolicySummary{
		TargetsAllow:         -1,
		TargetsDeny:          len(lp.denyNets) + len(lp.denyDomains),
		AllowPrivate:         lp.allowPrivate,
		Ports:                lp.portsText,
		Tools:                slices.Clone(lp.tools),
		Checks:               slices.Clone(lp.checks),
		AllowCustomTemplates: lp.allowCustomTemplates,
		AllowInteractsh:      lp.allowInteractsh,
		MaxRPS:               lp.maxRPS,
		MaxJobSeconds:        lp.maxJobSeconds,
		ManagedAccept:        lp.managedAccept,
		HTTPUserAgent:        lp.httpUserAgent,
		AllowInsecureTLS:     lp.allowInsecureTLS,
	}
	if lp.targetsAllowSet {
		s.TargetsAllow = len(lp.allowNets) + len(lp.allowDomains)
	}
	r.Summary = s
	return r
}

// Describe is a one-line description of the policy for the startup log.
func (lp *LocalPolicy) Describe() string {
	if lp.failsClosed() {
		return "absent and required: fail closed (jobs with network targets, custom templates and callbacks are refused)"
	}
	if !lp.Present() {
		return "absent (legacy install: built-in deny list only)"
	}
	r := lp.Report()
	s := r.Summary
	from := "file " + lp.path
	if lp.source == LocalPolicySourceEnv {
		from = EnvAllowedRanges + "/" + EnvAllowedPorts
	}
	allow := "any"
	if s.TargetsAllow >= 0 {
		allow = strconv.Itoa(s.TargetsAllow)
	}
	ports := cmp.Or(s.Ports, "any")
	tools := "any"
	if s.Tools != nil {
		tools = cmp.Or(strings.Join(s.Tools, ","), "none")
	}
	return fmt.Sprintf("enforced from %s (%s): targets allow %s, deny %d, private %t, ports %s, tools %s, custom templates %t, interactsh %t",
		from, shortDigest(lp.digest), allow, s.TargetsDeny, s.AllowPrivate, ports, tools, s.AllowCustomTemplates, s.AllowInteractsh)
}

// ReloadLocalPolicy re-reads the local policy (on SIGHUP; owner decision
// D10, api research/25 §4.2). A policy that loads replaces prev. One that
// does not load (a typo, a world-writable file, a missing file that was
// configured) does not leave the previous policy running: that may be the
// looser one the owner just tried to tighten. The result is prev with the
// kill switch engaged and a warning naming the error, so every job stops
// and the platform sees why, until a reload succeeds. The error is
// returned for the log.
func ReloadLocalPolicy(prev *LocalPolicy, opts LocalPolicyOptions) (*LocalPolicy, error) {
	lp, err := LoadLocalPolicy(opts)
	if err == nil {
		return lp, nil
	}
	return prev.withReloadFailure(err), err
}

// withReloadFailure is a copy of lp (or of the absent policy) with the kill
// switch engaged because a reload failed. The copy shares lp's lists, which
// are never modified after loading.
func (lp *LocalPolicy) withReloadFailure(err error) *LocalPolicy {
	var cp LocalPolicy
	if lp != nil {
		cp = *lp
	} else {
		cp = *absentPolicy()
	}
	reason := strings.Join(strings.Fields(err.Error()), " ")
	if len(reason) > 512 {
		reason = reason[:512]
	}
	cp.reloadFailed = reason
	cp.warnings = append(slices.Clone(cp.warnings), "local policy reload failed ("+reason+"): every job is stopped until the file is fixed and the sensor reloads it (SIGHUP) or restarts")
	return &cp
}
