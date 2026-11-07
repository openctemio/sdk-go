package sensorkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
)

func doctorFind(t *testing.T, r *DoctorReport, id string) core.ConfigCheck {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no %s check in %+v", id, r.Checks)
	return core.ConfigCheck{}
}

func TestDoctorCgroupCheck(t *testing.T) {
	old := doctorEnvelopes
	t.Cleanup(func() { doctorEnvelopes = old })
	for _, tc := range []struct {
		why, env, status, code string
	}{
		{"", "", core.CheckPass, "delegated"},
		{"the sensor's cgroup is not writable", "", core.CheckWarn, "not_delegated"},
		{"", "off", core.CheckSkip, "off"},
	} {
		doctorEnvelopes = func() string { return tc.why }
		t.Setenv(EnvToolCgroups, tc.env)
		if c := doctorCgroupCheck(); c.Status != tc.status || c.Code != tc.code || (tc.why != "" && c.Excerpt != tc.why) {
			t.Fatalf("%q/%q: %+v", tc.why, tc.env, c)
		}
	}
}

func TestDoctorDiskCheck(t *testing.T) {
	old := doctorDiskFree
	t.Cleanup(func() { doctorDiskFree = old })
	dir := t.TempDir()
	for _, tc := range []struct {
		free   int64
		status string
	}{
		{512 << 20, core.CheckFail},
		{3 << 30, core.CheckWarn},
		{20 << 30, core.CheckPass},
		{0, core.CheckSkip},
	} {
		doctorDiskFree = func(string) int64 { return tc.free }
		if c := doctorDiskCheck(filepath.Join(dir, "not", "yet"), dir); c.Status != tc.status {
			t.Fatalf("free %d: %+v", tc.free, c)
		}
	}
}

func TestDoctorStateDirCheck(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dir, status, code string
	}{
		{dir, core.CheckPass, "ok"},
		{filepath.Join(dir, "missing"), core.CheckWarn, "missing"},
		{file, core.CheckFail, "not_a_directory"},
	} {
		if c := doctorStateDirCheck(tc.dir); c.Status != tc.status || c.Code != tc.code {
			t.Fatalf("%s: %+v", tc.dir, c)
		}
	}
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		if c := doctorStateDirCheck(ro); c.Status != core.CheckFail || c.Code != "not_writable" {
			t.Fatalf("read-only: %+v", c)
		}
	}
}

// platformStub is a TLS platform that records what the doctor sent and
// answers its hello like a platform that serves it only to paired sensors.
type platformStub struct {
	mu   sync.Mutex
	reqs []*http.Request
	date time.Time
}

func (p *platformStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.reqs = append(p.reqs, r.Clone(context.Background()))
	date := p.date
	p.mu.Unlock()
	if !date.IsZero() {
		w.Header().Set("Date", date.UTC().Format(http.TimeFormat))
	}
	http.Error(w, "unauthenticated", http.StatusUnauthorized)
}

func TestDoctorPlatformChecks(t *testing.T) {
	stub := &platformStub{}
	srv := httptest.NewTLSServer(stub)
	t.Cleanup(srv.Close)
	t.Setenv("OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK", "1")
	o := DoctorOptions{APIURL: srv.URL, HTTPClient: srv.Client(), Timeout: 5 * time.Second}

	for _, tc := range []struct {
		name   string
		offset time.Duration
		status string
	}{
		{"in sync", 0, core.CheckPass},
		{"drifting", 45 * time.Second, core.CheckWarn},
		{"skewed", -5 * time.Minute, core.CheckFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub.mu.Lock()
			stub.date = time.Now().Add(tc.offset)
			stub.mu.Unlock()
			cs := doctorPlatformChecks(context.Background(), o)
			if len(cs) != 3 || cs[0].Code != "ip_literal" || cs[1].Status != core.CheckPass || !strings.Contains(cs[1].Summary, "CA SHA256:") {
				t.Fatalf("checks %+v", cs)
			}
			if cs[2].ID != CheckPlatformClock || cs[2].Status != tc.status {
				t.Fatalf("clock %+v, want %s", cs[2], tc.status)
			}
		})
	}
	// The request carries no credential of any kind.
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, r := range stub.reqs {
		for _, h := range []string{"Authorization", "Signature", "Signature-Input", "X-API-Key", "Cookie"} {
			if r.Header.Get(h) != "" {
				t.Fatalf("the doctor sent %s", h)
			}
		}
		if r.URL.RawQuery != "" || r.URL.Path != "/api/v2/sensor/hello" {
			t.Fatalf("request %s", r.URL)
		}
	}
}

func TestDoctorPlatformFailures(t *testing.T) {
	t.Setenv("OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK", "1")
	srv := httptest.NewTLSServer(&platformStub{})
	t.Cleanup(srv.Close)
	// A certificate this host does not trust.
	cs := doctorPlatformChecks(context.Background(), DoctorOptions{APIURL: srv.URL, HTTPClient: &http.Client{Timeout: 5 * time.Second}})
	if len(cs) != 2 || cs[1].Status != core.CheckFail || cs[1].Code != "tls_untrusted" {
		t.Fatalf("untrusted: %+v", cs)
	}
	// Nothing listens.
	closed := httptest.NewTLSServer(&platformStub{})
	url := closed.URL
	closed.Close()
	cs = doctorPlatformChecks(context.Background(), DoctorOptions{APIURL: url, HTTPClient: srv.Client()})
	if len(cs) != 2 || cs[1].Status != core.CheckFail || cs[1].Code != "refused" {
		t.Fatalf("refused: %+v", cs)
	}
	// A name that does not resolve: no connection is tried.
	old := doctorLookupHost
	t.Cleanup(func() { doctorLookupHost = old })
	doctorLookupHost = func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") }
	cs = doctorPlatformChecks(context.Background(), DoctorOptions{APIURL: "https://platform.example.com"})
	if len(cs) != 1 || cs[0].Status != core.CheckFail || cs[0].Code != "unresolved" {
		t.Fatalf("unresolved: %+v", cs)
	}
	// No URL: skipped.
	t.Setenv(EnvAPIURL, "")
	if cs = doctorPlatformChecks(context.Background(), DoctorOptions{}); len(cs) != 1 || cs[0].Status != core.CheckSkip {
		t.Fatalf("no url: %+v", cs)
	}
}

func TestDoctorPolicyChecks(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("apiVersion: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := doctorPolicyChecks(DoctorOptions{LocalPolicyPath: bad})
	if cs[0].Status != core.CheckFail || cs[0].Code != "invalid" {
		t.Fatalf("invalid policy: %+v", cs[0])
	}
	cs = doctorPolicyChecks(DoctorOptions{LocalPolicyPath: filepath.Join(dir, "absent.yaml")})
	if cs[0].Status == core.CheckFail {
		// An explicit path that does not exist is refused like the
		// sensor does; the default path may be absent.
		t.Logf("explicit absent path: %+v", cs[0])
	}
	t.Setenv(core.EnvLocalPolicy, "")
	cs = doctorPolicyChecks(DoctorOptions{})
	if cs[0].Status != core.CheckPass || cs[1].Code != "not_set" || cs[1].Status != core.CheckWarn {
		t.Fatalf("absent policy: %+v", cs)
	}
	stop := filepath.Join(dir, "STOP")
	t.Setenv(core.EnvKillSwitchFile, stop)
	if cs = doctorPolicyChecks(DoctorOptions{}); cs[1].Status != core.CheckPass || cs[1].Code != "ready" {
		t.Fatalf("ready: %+v", cs[1])
	}
	if err := os.WriteFile(stop, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if cs = doctorPolicyChecks(DoctorOptions{}); cs[1].Code != "engaged" {
		t.Fatalf("engaged: %+v", cs[1])
	}
	t.Setenv(core.EnvKillSwitchFile, filepath.Join(dir, "no-such-dir", "STOP"))
	if cs = doctorPolicyChecks(DoctorOptions{}); cs[1].Code != "dir_missing" {
		t.Fatalf("dir missing: %+v", cs[1])
	}
}

// The sandbox checks judge what the host gives against the settings: a
// required control the host does not give is a failure with the cause.
func TestDoctorSandbox(t *testing.T) {
	clearEnv(t)
	old := doctorBackend
	t.Cleanup(func() { doctorBackend = old })
	doctorBackend = func(cfg executor.Config) (*executor.ProcessBackend, error) {
		cfg.Launcher = "/nonexistent/openctem-launcher"
		return old(cfg)
	}
	withProc(t, map[string]string{"sys/kernel/unprivileged_userns_clone": "0\n"})
	run := func(sandbox string) (*Kit, func(string) core.ConfigCheck) {
		k := &Kit{doc: newDoctor(settingsreg.New(), nil), out: &bytes.Buffer{}, errw: &bytes.Buffer{}}
		doctorSandbox(k, DoctorOptions{Sandbox: sandbox})
		return k, func(id string) core.ConfigCheck {
			c, ok := findReported(k, id)
			if !ok {
				t.Fatalf("no %s", id)
			}
			return c
		}
	}
	_, get := run("required")
	if c := get(CheckSandboxUnconfined); c.Status != core.CheckFail || c.Code != "required_unmet" {
		t.Fatalf("required: %+v", c)
	}
	t.Setenv(EnvSandboxNetwork, "required")
	_, get = run("auto")
	if c := get(CheckSandboxNetwork); c.Status != core.CheckFail || c.Code != "userns_disabled_host" {
		t.Fatalf("network required: %+v", c)
	}
	t.Setenv(EnvSandboxNetwork, "")
	_, get = run("off")
	if c := get(CheckSandboxUnconfined); c.Status != core.CheckWarn || c.Code != "acknowledged" {
		t.Fatalf("off: %+v", c)
	}
	t.Setenv(EnvSandbox, "bogus")
	_, get = run("")
	if c := get(CheckSandboxUnconfined); c.Status != core.CheckFail || c.Code != "settings_invalid" {
		t.Fatalf("bad setting: %+v", c)
	}
}

// SECURITY: the doctor's output (table and JSON) never carries a secret
// setting's value or URL credentials, and the JSON matches its schema.
func TestDoctorCommandNoSecretsAndSchema(t *testing.T) {
	clearEnv(t)
	t.Setenv("OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK", "1")
	srv := httptest.NewTLSServer(&platformStub{})
	t.Cleanup(srv.Close)
	const (
		apiKey   = "octk_example_secret_api_key_0123456789"
		token    = "octe_example_enrollment_token_abcdef"
		password = "example-proxy-password"
	)
	t.Setenv(EnvAPIKey, apiKey)
	t.Setenv(EnvEnrollmentToken, token)
	t.Setenv("HTTPS_PROXY", "http://user:"+password+"@proxy.example.com:3128")
	t.Setenv(EnvAPIURL, srv.URL)
	t.Setenv(EnvStateDir, t.TempDir())
	o := DoctorOptions{ProductName: "example-sensor", Version: "1.2.3", HTTPClient: srv.Client(), Timeout: 5 * time.Second}

	var js, table, errw bytes.Buffer
	code := DoctorCommand([]string{"--json"}, o, &js, &errw)
	if DoctorCommand(nil, o, &table, &errw) != code {
		t.Fatal("the table and the JSON runs exit differently")
	}
	for _, out := range []string{js.String(), table.String()} {
		for _, secret := range []string{apiKey, token, password} {
			if strings.Contains(out, secret) {
				t.Fatalf("output carries a secret value:\n%s", out)
			}
		}
	}
	var r DoctorReport
	if err := json.Unmarshal(js.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Schema != DoctorSchema || r.ExitCode != code || r.SDKVersion == "" {
		t.Fatalf("report %+v, exit %d", r, code)
	}
	switch {
	case r.Summary.Fail > 0 && code != DoctorExitFailure,
		r.Summary.Fail == 0 && r.Summary.Warn > 0 && code != DoctorExitWarning,
		r.Summary.Fail == 0 && r.Summary.Warn == 0 && code != DoctorExitOK:
		t.Fatalf("exit %d for summary %+v", code, r.Summary)
	}
	doctorFind(t, &r, CheckPlatformReach)
	doctorFind(t, &r, CheckKillSwitchPath)
	doctorFind(t, &r, CheckDoctorVersion)

	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "schemas", "sensor-doctor.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("sensor-doctor.v1.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("sensor-doctor.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(js.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("the JSON does not match its schema: %v\n%s", err, js.String())
	}
}

func TestDoctorCommandUsage(t *testing.T) {
	var out, errw bytes.Buffer
	if code := DoctorCommand([]string{"extra"}, DoctorOptions{}, &out, &errw); code != ExitUsage {
		t.Fatalf("extra argument: exit %d", code)
	}
	if code := DoctorCommand([]string{"-h"}, DoctorOptions{}, &out, &errw); code != DoctorExitOK || !strings.Contains(errw.String(), "Exit codes") {
		t.Fatalf("help: exit %d\n%s", code, errw.String())
	}
}
