package sensorkit

import (
	"errors"
	"flag"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// clearEnv unsets every variable the kit reads, for the test.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		EnvAPIURL, EnvAPIKey, EnvSensorID, EnvSensorName, EnvProtocol, EnvMaxJobs, EnvDrainGrace, EnvTools,
		EnvStateDir, EnvCACertFile, EnvKeyAutoRenew, EnvScannerPriority, EnvProtectFromOOM, EnvOutbox, EnvOutboxDir, EnvOutboxMaxBytes, EnvOutboxMaxAge,
		EnvOutboxKeyFile, "RETRY_QUEUE", "RETRY_DIR", "SENSOR_ALLOW_PRIVATE_TARGETS", "AGENT_ID", "AGENT_NAME",
		"AGENT_ALLOW_PRIVATE_TARGETS", core.EnvLocalPolicy, core.EnvAllowedRanges, core.EnvAllowedPorts, core.EnvKillSwitchFile,
		core.EnvRequireLocalPolicy,
	} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
}

func TestResolveMaxJobs(t *testing.T) {
	flagSet := func(v int) MaxJobsSetting { return MaxJobsSetting{Source: "-max-concurrent", Value: v, Set: true} }
	config := func(v int) MaxJobsSetting { return MaxJobsSetting{Source: "sensor.max_jobs", Value: v, Set: v != 0} }
	cases := []struct {
		name     string
		explicit MaxJobsSetting
		env      string
		cfg      MaxJobsSetting
		want     int
		wantErr  string
	}{
		{name: "default: no cap", want: 0},
		{name: "config", cfg: config(8), want: 8},
		{name: "env over config", env: "3", cfg: config(8), want: 3},
		{name: "flag over env", explicit: flagSet(12), env: "3", cfg: config(8), want: 12},
		{name: "flag not set: env wins", explicit: MaxJobsSetting{Source: "-max-concurrent", Value: 5}, env: "2", want: 2},
		{name: "env not a number", env: "lots", wantErr: `SENSOR_MAX_JOBS="lots" is not a number`},
		{name: "env zero", env: "0", wantErr: "SENSOR_MAX_JOBS=0: the sensor runs between 1 and 100 jobs at once"},
		{name: "flag above limit", explicit: flagSet(101), wantErr: "-max-concurrent=101"},
		{name: "config negative", cfg: config(-1), wantErr: "sensor.max_jobs=-1"},
		{name: "upper bound", env: "100", want: 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(EnvMaxJobs, c.env)
			got, err := ResolveMaxJobs(c.explicit, c.cfg)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) || ExitCode(err) != ExitUsage {
					t.Fatalf("err = %v (exit %d), want %q (exit 2)", err, ExitCode(err), c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("ResolveMaxJobs = %d, %v; want %d", got, err, c.want)
			}
		})
	}
}

func TestResolveDrainGrace(t *testing.T) {
	cases := map[string]struct {
		want    time.Duration
		wantErr bool
	}{
		"":      {want: 30 * time.Second},
		"45s":   {want: 45 * time.Second},
		" 2m ":  {want: 2 * time.Minute},
		"500ms": {wantErr: true},
		"2h":    {wantErr: true},
		"lots":  {wantErr: true},
		"-5s":   {wantErr: true},
	}
	for in, c := range cases {
		t.Setenv(EnvDrainGrace, in)
		got, err := ResolveDrainGrace()
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("ResolveDrainGrace(%q) = %v, %v; want %v (error %v)", in, got, err, c.want, c.wantErr)
		}
		if err != nil && ExitCode(err) != ExitUsage {
			t.Errorf("ResolveDrainGrace(%q): exit %d, want %d", in, ExitCode(err), ExitUsage)
		}
	}
}

func TestResolveProtocol(t *testing.T) {
	clearEnv(t)
	if p, err := ResolveProtocol("", ""); err != nil || p != "auto" {
		t.Fatalf("default = %q, %v", p, err)
	}
	t.Setenv(EnvProtocol, "V2")
	if p, _ := ResolveProtocol("", "auto"); p != "v2" {
		t.Fatalf("env over config = %q", p)
	}
	if p, _ := ResolveProtocol("auto", ""); p != "auto" {
		t.Fatalf("explicit over env = %q", p)
	}
	// Protocol v1 is retired: the setting is refused with a usable message.
	t.Setenv(EnvProtocol, "v1")
	if _, err := ResolveProtocol("", ""); !errors.Is(err, client.ErrProtocolV1Retired) || !strings.Contains(err.Error(), EnvProtocol) {
		t.Fatalf("v1 accepted: %v", err)
	}
	t.Setenv(EnvProtocol, "v3")
	if _, err := ResolveProtocol("", ""); err == nil || !strings.Contains(err.Error(), EnvProtocol) {
		t.Fatalf("v3 accepted: %v", err)
	}
}

func TestCheckCredentials(t *testing.T) {
	if err := CheckCredentials("https://api", "k", CredentialsHelp{}); err != nil {
		t.Fatal(err)
	}
	err := CheckCredentials("", "", CredentialsHelp{})
	if !errors.Is(err, ErrNeedsPlatform) || ExitCode(err) != ExitUsage {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
	for _, want := range []string{"API_URL", "API_KEY", "Settings > Sensors"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
	// A sensor's own wording, exactly.
	err = CheckCredentials("https://api", "", CredentialsHelp{Subject: "a server-controlled daemon (-daemon -enable-commands)", Hint: "  hint"})
	want := "a server-controlled daemon (-daemon -enable-commands) needs the platform URL and a sensor API key; missing: [API_KEY].\n  hint"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %q\nwant  %q", err, want)
	}
}

func TestResolveStateDir(t *testing.T) {
	t.Setenv(EnvStateDir, "")
	if got := ResolveStateDir("/explicit/state"); got != "/explicit/state" {
		t.Fatalf("explicit: %q", got)
	}
	t.Setenv(EnvStateDir, "/data/state")
	if got := ResolveStateDir(""); got != "/data/state" {
		t.Fatalf("from env: %q", got)
	}
}

func TestExitCode(t *testing.T) {
	if ExitCode(nil) != 0 || ExitCode(errors.New("x")) != ExitError {
		t.Fatal("nil / plain error")
	}
	wrapped := errors.Join(errors.New("a"), &Error{Code: ExitUsage, Err: errors.New("b")})
	if ExitCode(wrapped) != ExitUsage {
		t.Fatalf("wrapped: %d", ExitCode(wrapped))
	}
	if ExitAuthRejected != 78 {
		t.Fatalf("ExitAuthRejected = %d, want 78 (EX_CONFIG)", ExitAuthRejected)
	}
}

func TestParseToolList(t *testing.T) {
	got := ParseToolList(" semgrep, trivy-fs,,nuclei ,")
	if strings.Join(got, "|") != "semgrep|trivy-fs|nuclei" {
		t.Fatalf("%q", got)
	}
	if ParseToolList(" , ") != nil {
		t.Fatal("empty list must be nil")
	}
}

// resetMigration lets a test run the once-per-process migration again.
func resetMigration(t *testing.T) {
	t.Helper()
	migrateOnce, migrateErr = sync.Once{}, nil
	t.Cleanup(func() { migrateOnce, migrateErr = sync.Once{}, nil })
}

func TestMigrateSettings_LegacyEnvAndFlags(t *testing.T) {
	clearEnv(t)
	resetMigration(t)
	var warns []string
	prev := legacyv1.Warn
	legacyv1.Warn = func(old, replacement, kind string) { warns = append(warns, kind+":"+old+"->"+replacement) }
	t.Cleanup(func() { legacyv1.Warn = prev })

	t.Setenv("AGENT_NAME", "edge-1")
	fs := flag.NewFlagSet("sensor", flag.ContinueOnError)
	id := fs.String("sensor-id", "", "")
	_ = fs.String("agent-id", "", "")
	if err := fs.Parse([]string{"-agent-id", "s-1"}); err != nil {
		t.Fatal(err)
	}
	if err := MigrateSettings(fs); err != nil {
		t.Fatal(err)
	}
	if os.Getenv(EnvSensorName) != "edge-1" || *id != "s-1" {
		t.Fatalf("SENSOR_NAME %q, -sensor-id %q", os.Getenv(EnvSensorName), *id)
	}
	if len(warns) != 2 {
		t.Fatalf("warnings %v, want one per deprecated name", warns)
	}
}

func TestMigrateLegacyEnv_ConflictIsUsageError(t *testing.T) {
	clearEnv(t)
	resetMigration(t)
	t.Setenv("AGENT_ID", "a")
	t.Setenv(EnvSensorID, "b")
	err := MigrateLegacyEnv()
	if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "AGENT_ID") || !strings.Contains(err.Error(), "SENSOR_ID") {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
	// New refuses to start with it.
	if _, err := New(Options{DisableCommands: true, Standalone: true}); ExitCode(err) != ExitUsage {
		t.Fatalf("New: %v", err)
	}
}
