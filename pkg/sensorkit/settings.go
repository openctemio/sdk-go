package sensorkit

// Standard sensor settings: the environment variables every sensor built on
// the kit reads, how they are validated, and the exit codes of a sensor that
// refuses to start. Each resolver is exported so a sensor with its own
// command line or configuration file layers them the same way (a flag beats
// the environment, the environment beats a configuration file).

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/platform"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// Environment variables the kit reads (besides the SDK's own, such as
// SENSOR_ALLOW_PRIVATE_TARGETS, SENSOR_SCAN_ROOTS and REGION).
const (
	EnvAPIURL     = "API_URL"
	EnvAPIKey     = "API_KEY"
	EnvSensorID   = "SENSOR_ID"
	EnvSensorName = "SENSOR_NAME"
	EnvProtocol   = "SENSOR_PROTOCOL"    // auto (default) | v1 | v2
	EnvMaxJobs    = "SENSOR_MAX_JOBS"    // 1-100; unset: the slots follow the resources
	EnvDrainGrace = "SENSOR_DRAIN_GRACE" // e.g. 45s, 2m (1s-1h; default 30s)
	EnvTools      = "SENSOR_TOOLS"       // comma-separated allowlist
	EnvStateDir   = "SENSOR_STATE_DIR"   // local state: the renewed API key, the tool cost history
	EnvCACertFile = "SENSOR_CA_CERT_FILE"
	// EnvCAFingerprint pins the platform CA by its SHA-256 fingerprint
	// (install snippet; api RFC-052).
	EnvCAFingerprint = "SENSOR_CA_FINGERPRINT"
	// EnvPlatformKey pins the platform's pairing key (its thumbprint).
	EnvPlatformKey  = "SENSOR_PLATFORM_KEY"
	EnvKeyAutoRenew = "PLATFORM_KEY_AUTORENEW" // true | false; unset: on when the state directory persists
	// EnvScannerPriority is the priority of scanner processes: low (the
	// default: nice +10, lowest best-effort I/O, OOM-killed before the
	// sensor) or normal (the sensor's own).
	EnvScannerPriority = "SENSOR_SCANNER_PRIORITY"
	// EnvProtectFromOOM protects the sensor itself from the OOM killer:
	// true writes SensorOOMScoreAdj to its oom_score_adj at start (Linux;
	// needs CAP_SYS_RESOURCE). false, the default, leaves it.
	EnvProtectFromOOM = "SENSOR_PROTECT_FROM_OOM"
	// EnvTemplateSigningKeys are the platform's template-signing public
	// keys (base64 Ed25519, comma-separated) custom templates must be
	// signed with; unset, commands carrying custom templates are refused.
	EnvTemplateSigningKeys = "SENSOR_TEMPLATE_SIGNING_KEYS"

	EnvOutbox         = "SENSOR_OUTBOX"           // on | off (default: on for a daemon)
	EnvOutboxDir      = "SENSOR_OUTBOX_DIR"       // default DefaultOutboxDir
	EnvOutboxMaxBytes = "SENSOR_OUTBOX_MAX_BYTES" // e.g. 512MiB, 2GiB (default 1GiB)
	EnvOutboxMaxAge   = "SENSOR_OUTBOX_MAX_AGE"   // e.g. 72h (default 168h)
	EnvOutboxKeyFile  = "SENSOR_OUTBOX_KEY_FILE"  // default <dir>/outbox.key
)

// Exit codes of a sensor that stops on an error (see ExitCode).
const (
	// ExitError is any other error.
	ExitError = 1
	// ExitUsage is a setting out of range or missing (the sensor would run
	// differently from what the operator asked for).
	ExitUsage = 2
	// ExitAuthRejected is a one-shot run whose API key the platform rejects
	// (EX_CONFIG from sysexits.h): running again will not help until the
	// configuration is fixed. A daemon never exits for it: it backs off and
	// waits for the key to be accepted.
	ExitAuthRejected = 78
)

// Error is an error with the exit code a sensor stops with.
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func usageError(err error) error { return &Error{Code: ExitUsage, Err: err} }

// ExitCode is the process exit code for err: 0 for nil, the code of an
// *Error, else ExitError.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var e *Error
	if errors.As(err, &e) && e.Code != 0 {
		return e.Code
	}
	return ExitError
}

// Exit prints err as "Error: <err>" to standard error and exits with its
// ExitCode; it returns when err is nil.
func Exit(err error) {
	if err == nil {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(ExitCode(err))
}

var (
	migrateOnce sync.Once
	migrateErr  error
)

// MigrateLegacyEnv applies the pre-rename environment variables (AGENT_ID,
// AGENT_NAME, AGENT_ALLOW_PRIVATE_TARGETS) to their new names with a
// deprecation warning, so everything after reads only new names. Both names
// set to different values is an error naming both (exit code ExitUsage).
// It runs once per process; New calls it too.
func MigrateLegacyEnv() error {
	migrateOnce.Do(func() {
		if err := legacyv1.ApplyRenamedEnv(legacyv1.SensorRenamedEnv, os.LookupEnv, os.Setenv); err != nil {
			migrateErr = usageError(err)
		}
	})
	return migrateErr
}

// MigrateSettings is MigrateLegacyEnv plus the renamed command-line flags of
// fs (-agent-id is applied to -sensor-id, with a warning). Call it right
// after fs.Parse.
func MigrateSettings(fs *flag.FlagSet) error {
	err := MigrateLegacyEnv()
	if fs != nil {
		if ferr := legacyv1.ApplyRenamedFlags(fs, legacyv1.SensorRenamedFlags); ferr != nil {
			err = errors.Join(err, usageError(ferr))
		}
	}
	return err
}

// MaxMaxJobs is the most jobs a sensor may run at once (the platform's limit
// on a sensor's concurrency).
const MaxMaxJobs = 100

// MaxJobsSetting is one place an operator can set the concurrency cap.
type MaxJobsSetting struct {
	// Source names it in errors ("-max-concurrent", "sensor.max_jobs").
	Source string
	Value  int
	Set    bool
}

// ResolveMaxJobs returns the cap on concurrent jobs: explicit (a flag) when
// set, else SENSOR_MAX_JOBS, else configured (a configuration file) when set,
// else 0 (no cap: the slots follow the CPU, memory and tool costs). A value
// outside 1..100 is an error (ExitUsage): the sensor refuses to start rather
// than run a different number of jobs than the operator asked for.
func ResolveMaxJobs(explicit, configured MaxJobsSetting) (int, error) {
	env := os.Getenv(EnvMaxJobs)
	switch {
	case explicit.Set:
		return checkMaxJobs(explicit.Source, explicit.Value)
	case strings.TrimSpace(env) != "":
		n, err := strconv.Atoi(strings.TrimSpace(env))
		if err != nil {
			return 0, usageError(fmt.Errorf("%s=%q is not a number", EnvMaxJobs, env))
		}
		return checkMaxJobs(EnvMaxJobs, n)
	case configured.Set:
		return checkMaxJobs(configured.Source, configured.Value)
	default:
		return 0, nil
	}
}

func checkMaxJobs(source string, n int) (int, error) {
	if n < 1 || n > MaxMaxJobs {
		return 0, usageError(fmt.Errorf("%s=%d: the sensor runs between 1 and %d jobs at once", source, n, MaxMaxJobs))
	}
	return n, nil
}

// ResolveDrainGrace parses SENSOR_DRAIN_GRACE ("45s", "2m"): how long a
// stopping daemon lets running scans finish before it stops them and hands
// them back to the platform. Unset is core.DefaultDrainGrace; an invalid or
// out-of-range (1s-1h) value is an error (ExitUsage).
func ResolveDrainGrace() (time.Duration, error) {
	env := strings.TrimSpace(os.Getenv(EnvDrainGrace))
	if env == "" {
		return core.DefaultDrainGrace, nil
	}
	d, err := time.ParseDuration(env)
	if err != nil {
		return 0, usageError(fmt.Errorf("%s=%q is not a duration (e.g. 45s, 2m)", EnvDrainGrace, env))
	}
	if d < time.Second || d > time.Hour {
		return 0, usageError(fmt.Errorf("%s=%s: between 1s and 1h", EnvDrainGrace, d))
	}
	return d, nil
}

// Scanner priorities (SENSOR_SCANNER_PRIORITY).
const (
	ScannerPriorityLow    = "low"
	ScannerPriorityNormal = "normal"
)

// ResolveScannerPriority returns the priority scanner processes run at:
// explicit when set, else SENSOR_SCANNER_PRIORITY, else low. low is
// core.DefaultScannerPriority (a scanner yields the CPU and the disk to the
// sensor and is OOM-killed before it, api RFC-035 §5.3); normal is nil
// (scanners run at the sensor's own priority). Anything else is an error
// (ExitUsage).
func ResolveScannerPriority(explicit string) (*core.ScannerPriority, error) {
	v := strings.ToLower(strings.TrimSpace(firstNonEmpty(explicit, os.Getenv(EnvScannerPriority))))
	switch v {
	case "", ScannerPriorityLow:
		p := core.DefaultScannerPriority
		return &p, nil
	case ScannerPriorityNormal:
		return nil, nil
	default:
		return nil, usageError(fmt.Errorf("%s=%q: low or normal", EnvScannerPriority, v))
	}
}

// SensorOOMScoreAdj is the oom_score_adj a sensor protected from the OOM
// killer (SENSOR_PROTECT_FROM_OOM) gives itself: low enough that the kernel
// kills almost any other process first, but not -1000, which would exempt the
// sensor entirely. Scanners never inherit it (core.ApplyScannerPriority).
const SensorOOMScoreAdj = -500

// ResolveProtectFromOOM reports whether the sensor protects itself from the
// OOM killer: true when explicit is, else SENSOR_PROTECT_FROM_OOM (true or
// false; unset is false). Any other value is an error (ExitUsage).
func ResolveProtectFromOOM(explicit bool) (bool, error) {
	if explicit {
		return true, nil
	}
	v := strings.TrimSpace(os.Getenv(EnvProtectFromOOM))
	if v == "" {
		return false, nil
	}
	on, err := parseOnOff(v)
	if err != nil {
		return false, usageError(fmt.Errorf("%s=%q: true or false", EnvProtectFromOOM, v))
	}
	return on, nil
}

// ResolveProtocol returns the sensor protocol: explicit (a flag), else
// SENSOR_PROTOCOL, else configured, else auto. auto and v2 both mean
// protocol v2; v1 is retired and refused (client.ErrProtocolV1Retired).
func ResolveProtocol(explicit, configured string) (string, error) {
	v := firstNonEmpty(explicit, os.Getenv(EnvProtocol), configured)
	p, err := client.ParseProtocol(v)
	if err != nil {
		return "", fmt.Errorf("%s: %w", EnvProtocol, err)
	}
	return p, nil
}

// ErrNeedsPlatform is returned (wrapped in an *Error with ExitUsage) when a
// sensor that runs the platform's commands has no platform URL or API key.
var ErrNeedsPlatform = errors.New("needs the platform URL and a sensor API key")

// CredentialsHelp words the error of CheckCredentials for a sensor's own
// command line. The zero value is generic.
type CredentialsHelp struct {
	// Subject names what needs the platform (default "a sensor that runs
	// the platform's commands").
	Subject string
	// Hint follows the list of missing settings: how to set them (default:
	// the environment variables and where to create a key).
	Hint string
}

const (
	defaultCredentialsSubject = "a sensor that runs the platform's commands"
	defaultCredentialsHint    = "  Set them as environment variables (docker run -e API_URL=https://<platform>/ -e API_KEY=<key> ...).\n" +
		"  Create the key in the platform: Settings > Sensors (it is shown once)."
)

// credentialsError is the error of CheckCredentials.
type credentialsError struct {
	subject, hint string
	missing       []string
}

func (e *credentialsError) Error() string {
	return fmt.Sprintf("%s %v; missing: %v.\n%s", e.subject, ErrNeedsPlatform, e.missing, e.hint)
}

func (e *credentialsError) Is(target error) bool { return target == ErrNeedsPlatform }

// CheckCredentials refuses to start a sensor that runs the platform's
// commands without the platform URL or API key: it would start, never poll
// and never say why. The error (errors.Is ErrNeedsPlatform, exit code
// ExitUsage) lists what is missing and how to set it.
func CheckCredentials(apiURL, apiKey string, help CredentialsHelp) error {
	var missing []string
	if apiURL == "" {
		missing = append(missing, EnvAPIURL)
	}
	if apiKey == "" {
		missing = append(missing, EnvAPIKey)
	}
	if len(missing) == 0 {
		return nil
	}
	e := &credentialsError{subject: help.Subject, hint: help.Hint, missing: missing}
	if e.subject == "" {
		e.subject = defaultCredentialsSubject
	}
	if e.hint == "" {
		e.hint = defaultCredentialsHint
	}
	return usageError(e)
}

// CheckDaemonCredentials is CheckCredentials for a sensor that may be
// key-bound (api RFC-052): only the platform URL is required, since a
// sensor without an API key uses its paired identity or pairs on first
// start.
func CheckDaemonCredentials(apiURL string, help CredentialsHelp) error {
	return CheckCredentials(apiURL, "key-bound", help)
}

// ResolveStateDir is where the sensor keeps local state (the API key it
// renews, the tool cost history): explicit, else SENSOR_STATE_DIR, else
// /var/lib/openctem/state when writable (the images create it; mount a
// volume there), else ~/.openctem (platform.ResolveStateDir).
func ResolveStateDir(explicit string) string {
	return platform.ResolveStateDir(explicit)
}

// ParseToolList splits a comma-separated tool list ("semgrep, trivy,,nuclei")
// into trimmed, non-empty names.
func ParseToolList(list string) []string {
	var out []string
	for t := range strings.SplitSeq(list, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func envOr(v, name string) string {
	if v != "" {
		return v
	}
	return os.Getenv(name)
}
