package sensorkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/platform"
)

func clientOutbox(dir string) client.OutboxConfig { return client.OutboxConfig{Dir: dir} }

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testScanner is an in-process tool that reports one SARIF finding.
type testScanner struct {
	name      string
	installed bool
	block     chan struct{} // non-nil: Scan waits for it or ctx
	scans     chan string
}

func (s *testScanner) Name() string           { return s.name }
func (s *testScanner) Version() string        { return "1.0.0" }
func (s *testScanner) Capabilities() []string { return []string{"sast"} }
func (s *testScanner) IsInstalled(context.Context) (bool, string, error) {
	if !s.installed {
		return false, "", errors.New("not here")
	}
	return true, "1.0.0", nil
}

const testSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"kit-tool"}},"results":[{"ruleId":"r1","level":"error","message":{"text":"bad"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`

func (s *testScanner) Scan(ctx context.Context, target string, _ *core.ScanOptions) (*core.ScanResult, error) {
	if s.scans != nil {
		select {
		case s.scans <- target:
		default:
		}
	}
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &core.ScanResult{ScannerName: s.name, RawOutput: []byte(testSARIF)}, nil
}

type testContent struct {
	started chan struct{}
	stamped chan struct{}
}

func (c *testContent) Decorate(r core.CapabilityReport) core.CapabilityReport {
	for i := range r.Tools {
		r.Tools[i].Content = []core.ContentInfo{{Name: "kit-rules", Version: "7"}}
	}
	return r
}
func (c *testContent) Start(context.Context) { close(c.started) }
func (c *testContent) WrapPusher(p core.Pusher) core.Pusher {
	return stampPusher{Pusher: p, stamped: c.stamped}
}

type stampPusher struct {
	core.Pusher
	stamped chan struct{}
}

func (p stampPusher) PushFindings(ctx context.Context, r *ctis.Report) (*core.PushResult, error) {
	select {
	case p.stamped <- struct{}{}:
	default:
	}
	return p.Pusher.PushFindings(ctx, r)
}

// baseOptions points a kit at fake with private dirs and captured logs.
func baseOptions(t *testing.T, f *conformance.FakePlatform) (Options, *syncBuffer, *syncBuffer) {
	t.Helper()
	clearEnv(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvDrainGrace, "1s")
	// The host's filesystem would count as persistent and turn key renewal
	// on; tests that want it say so (persistentState after baseOptions).
	persistentState(t, false)
	out, errw := &syncBuffer{}, &syncBuffer{}
	return Options{
		Name: "kit-test", Version: "1.2.3",
		APIURL: f.URL(), APIKey: f.APIKey,
		Outbox:   OutboxSettings{Dir: filepath.Join(t.TempDir(), "outbox")},
		StateDir: t.TempDir(),
		Stdout:   out, Stderr: errw,
	}, out, errw
}

// runKit runs k until stop is closed; it returns Run's error.
func runKit(t *testing.T, k *Kit) (cancel func() error) {
	t.Helper()
	ctx, stop := context.WithCancel(context.WithValue(context.Background(), signalKey{}, true))
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()
	return func() error {
		stop()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			t.Fatal("Run did not return after cancel")
			return nil
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type heartbeat struct {
	Name         string          `json:"name"`
	InstanceID   string          `json:"instance_id"`
	Version      string          `json:"version"`
	Tools        []core.ToolInfo `json:"tools"`
	Capabilities []string        `json:"capabilities"`
	MaxJobs      int             `json:"max_concurrent_jobs"`
	SDK          *struct {
		Version string `json:"version"`
	} `json:"sdk"`
	Sensor *struct {
		Version string `json:"version"`
	} `json:"sensor"`
}

func lastBeat(t *testing.T, f *conformance.FakePlatform) heartbeat {
	t.Helper()
	beats := f.Heartbeats()
	if len(beats) == 0 {
		t.Fatal("no heartbeat")
	}
	var hb heartbeat
	if err := json.Unmarshal(beats[len(beats)-1], &hb); err != nil {
		t.Fatal(err)
	}
	return hb
}

// A whole sensor life on a v2 platform: hello, a first heartbeat that
// reports the tools before the first poll, a dispatched scan run through the
// middleware and the SDK's executor with its results delivered, scheduled
// scans, and a clean shutdown.
func TestRun_V2Lifecycle(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	cmdID := "0192a3b4-0000-7000-8000-000000000001"
	f.QueueCommand(cmdID)

	opts, out, errw := baseOptions(t, f)
	target := t.TempDir()
	opts.Targets = []string{target}
	opts.MaxJobs = 2
	stamped := make(chan struct{}, 4)
	content := &testContent{started: make(chan struct{}), stamped: stamped}
	opts.Content = content
	opts.ScanTargetPolicy = &core.ScanTargetPolicy{AllowedRoots: []string{target}}
	opts.AssetResolver = func(_, _ string) (ctis.AssetType, string) {
		return ctis.AssetTypeRepository, "github.com/openctemio/kit-test"
	}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	scans := make(chan string, 8)
	k.AddScanner(&testScanner{name: "kit-tool", installed: true, scans: scans}, As("kit-tool-fs"), WithCapabilities("container"))
	k.AddScanner(&testScanner{name: "missing-tool"})
	k.Tools().AddCapabilities("validate")
	var seen []string
	var mu sync.Mutex
	// The fake dispatches {"scanner":"fake"}: the middleware routes it to
	// the configured name and gives it a target, like a sensor's own
	// executor wrapper would.
	k.UseCommandMiddleware(func(next core.CommandExecutor) core.CommandExecutor {
		return execFunc(func(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
			mu.Lock()
			seen = append(seen, cmd.Type)
			mu.Unlock()
			if cmd.Type == "scan" {
				c := *cmd
				c.Payload = json.RawMessage(fmt.Sprintf(`{"scanner":"kit-tool-fs","target":%q}`, target))
				cmd = &c
			}
			return next.Execute(ctx, cmd)
		})
	}, "validate")
	stop := runKit(t, k)

	waitFor(t, "the command to complete", func() bool {
		s, e := f.CommandState(cmdID)
		if s == "failed" {
			t.Fatalf("command failed: %s\nstdout:%s\nstderr:%s", e, out.String(), errw.String())
		}
		return s == "completed"
	})
	waitFor(t, "findings delivered", func() bool { return f.AcceptedFindings() >= 1 })
	select {
	case <-content.started:
	default:
		t.Fatal("ContentStarter.Start not called")
	}
	select {
	case <-stamped:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatched results did not go through PusherWrapper")
	}
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	reqs := f.Requests()
	if reqs[0].Path != "/api/v2/sensor/hello" || reqs[1].Path != "/api/v2/sensor/heartbeat" {
		t.Fatalf("start sequence %s %s, want hello then heartbeat (before any poll)", reqs[0].Path, reqs[1].Path)
	}
	for _, r := range reqs {
		if strings.HasPrefix(r.Path, "/api/v1/") {
			t.Errorf("v1 request on a v2 platform: %s %s", r.Method, r.Path)
		}
	}
	hb := lastBeat(t, f)
	if hb.Name != "kit-test" || hb.Version != "1.2.3" || hb.SDK == nil || hb.Sensor == nil || hb.Sensor.Version != "1.2.3" {
		t.Fatalf("identity: %+v", hb)
	}
	// Every heartbeat names the process (api RFC-032 Phase 0 clone detection).
	if hb.InstanceID == "" || hb.InstanceID != core.ProcessInstanceID() {
		t.Fatalf("instance_id = %q, want the process id %q", hb.InstanceID, core.ProcessInstanceID())
	}
	if len(hb.Tools) != 2 || hb.Tools[0].Name != "kit-tool" || !hb.Tools[0].Installed || hb.Tools[1].Installed ||
		len(hb.Tools[0].Content) != 1 {
		t.Fatalf("tools: %+v", hb.Tools)
	}
	for _, c := range []string{"kit-tool", "sast", "container", "validate"} {
		if !strings.Contains(strings.Join(hb.Capabilities, ","), c) {
			t.Errorf("capabilities %v lack %s", hb.Capabilities, c)
		}
	}
	if hb.MaxJobs != 2 {
		t.Errorf("max_concurrent_jobs %d", hb.MaxJobs)
	}
	logs := out.String()
	for _, want := range []string{"  Outbox: ", "  Added scanner: kit-tool", "Command polling: on the heartbeat doorbell",
		"Concurrent jobs: up to 2", "✓ Connected to API", "kit-test started", "Mode: Hybrid", "Sensor stopped."} {
		if !strings.Contains(logs, want) {
			t.Errorf("stdout lacks %q:\n%s", want, logs)
		}
	}
	if !strings.Contains(errw.String(), "Warning: Scanner missing-tool skipped: its check failed: not here") {
		t.Errorf("stderr: %s", errw.String())
	}
	// Scheduled scan of the target ran too.
	if len(scans) < 2 {
		t.Errorf("scans %d, want the dispatched one and a scheduled one", len(scans))
	}
}

type execFunc func(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error)

func (f execFunc) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	return f(ctx, cmd)
}

// Against a platform without protocol v2 everything goes over v1.
func TestRun_V1Fallback(t *testing.T) {
	f := conformance.NewFakePlatform(false)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddScanner(&testScanner{name: "kit-tool", installed: true})
	stop := runKit(t, k)
	waitFor(t, "a v1 poll", func() bool { return len(f.RequestsTo("GET", "/api/v1/agent/commands")) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if len(f.RequestsTo("POST", "/api/v1/agent/heartbeat")) == 0 {
		t.Fatal("no v1 heartbeat")
	}
	for _, r := range f.Requests() {
		if strings.HasPrefix(r.Path, "/api/v2/") && r.Path != "/api/v2/sensor/hello" {
			t.Errorf("v2 request to a v1 platform: %s", r.Path)
		}
	}
	if hb := lastBeat(t, f); len(hb.Tools) != 1 || hb.Tools[0].Name != "kit-tool" {
		t.Fatalf("v1 heartbeat tools: %+v", hb.Tools)
	}
}

// Shutdown drains: a command still running after the drain grace is
// stopped and handed back to the platform; Run then returns nil.
func TestRun_DrainReleasesRunningCommand(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	cmdID := "0192a3b4-0000-7000-8000-000000000002"
	f.QueueCommand(cmdID)
	opts, out, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	// HandleCommand replaces the SDK's executor for "scan".
	k.HandleCommand("scan", execFunc(func(ctx context.Context, _ *core.Command) (*core.CommandExecutionResult, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	stop := runKit(t, k)
	select {
	case <-started:
	case <-time.After(15 * time.Second):
		t.Fatal("the command never started")
	}
	begin := time.Now()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(begin); d < time.Second {
		t.Errorf("returned after %s, before the 1s drain grace", d)
	}
	rel := f.Releases()
	if len(rel) != 1 || rel[0].CommandID != cmdID {
		t.Fatalf("releases %+v, want %s handed back", rel, cmdID)
	}
	if !strings.Contains(out.String(), "Draining: 1 command(s) running; up to 1s") {
		t.Errorf("stdout: %s", out.String())
	}
}

// While the platform rejects the key the sensor stays up, retrying with the
// heartbeat's backoff, and never polls; cancel stops it cleanly.
func TestRun_RejectedKeyWaitsAndStops(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, out, _ := baseOptions(t, f)
	opts.APIKey = "rda_wrong"
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	stop := runKit(t, k)
	waitFor(t, "a rejected heartbeat", func() bool {
		for _, r := range f.Requests() {
			if strings.HasSuffix(r.Path, "/heartbeat") && r.Status == 401 {
				return true
			}
		}
		return false
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if n := len(f.RequestsTo("GET", "/api/v2/sensor/commands")); n != 0 {
		t.Fatalf("%d polls with a rejected key", n)
	}
	if strings.Contains(out.String(), "Connected to API") || !strings.Contains(out.String(), "Sensor stopped.") {
		t.Fatalf("stdout: %s", out.String())
	}
}

// SENSOR_TOOLS narrows what is run and reported; As names count.
func TestRun_ToolAllowlist(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, _, errw := baseOptions(t, f)
	t.Setenv(EnvTools, "trivy-fs")
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddScanner(&testScanner{name: "trivy", installed: true}, As("trivy-fs"))
	k.AddScanner(&testScanner{name: "nuclei", installed: true})
	stop := runKit(t, k)
	waitFor(t, "a heartbeat", func() bool { return len(f.Heartbeats()) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	hb := lastBeat(t, f)
	if len(hb.Tools) != 1 || hb.Tools[0].Name != "trivy" {
		t.Fatalf("tools %+v, want only trivy", hb.Tools)
	}
	if !strings.Contains(errw.String(), "scanner nuclei is not in SENSOR_TOOLS") {
		t.Errorf("stderr: %s", errw.String())
	}
	// An empty, non-nil Tools sets no allowlist whatever SENSOR_TOOLS says.
	opts.Tools = []string{}
	k2, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k2.AddScanner(&testScanner{name: "nuclei", installed: true})
	if !k2.allowed(k2.scanners[0]) {
		t.Fatal("Tools: []string{} must lift the allowlist")
	}
}

func TestNew_Errors(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	cases := []struct {
		name string
		env  map[string]string
		opts func(*Options)
		want string
		code int
	}{
		{name: "no URL", opts: func(o *Options) { o.APIURL = "" }, want: "missing: [API_URL]", code: ExitUsage},
		{name: "drain grace", env: map[string]string{EnvDrainGrace: "lots"}, want: "SENSOR_DRAIN_GRACE", code: ExitUsage},
		{name: "max jobs", env: map[string]string{EnvMaxJobs: "0"}, want: "SENSOR_MAX_JOBS=0", code: ExitUsage},
		{name: "max jobs option", opts: func(o *Options) { o.MaxJobs = 101 }, want: "MaxJobs=101", code: ExitUsage},
		{name: "protocol", env: map[string]string{EnvProtocol: "v3"}, want: "SENSOR_PROTOCOL", code: ExitError},
		{name: "outbox", env: map[string]string{EnvOutboxMaxAge: "-1h"}, want: "SENSOR_OUTBOX_MAX_AGE", code: ExitError},
		{name: "private targets", env: map[string]string{"SENSOR_ALLOW_PRIVATE_TARGETS": "yes please"}, want: "SENSOR_ALLOW_PRIVATE_TARGETS", code: ExitError},
		{name: "CA file", env: map[string]string{EnvCACertFile: "/nonexistent/ca.pem"}, want: "CA certificate file", code: ExitError},
		{name: "template keys", env: map[string]string{EnvTemplateSigningKeys: "not-a-key"}, want: "SENSOR_TEMPLATE_SIGNING_KEYS", code: ExitUsage},
		{name: "template keys option", opts: func(o *Options) { o.TemplateSigningKeys = "c2hvcnQ=" }, want: "SENSOR_TEMPLATE_SIGNING_KEYS", code: ExitUsage},
		{name: "local policy missing", env: map[string]string{core.EnvLocalPolicy: "/nonexistent/sensor-policy.yaml"}, want: "local policy /nonexistent/sensor-policy.yaml does not exist", code: ExitUsage},
		{name: "local policy option missing", opts: func(o *Options) { o.LocalPolicyPath = "/nonexistent/p.yaml" }, want: "does not exist", code: ExitUsage},
		{name: "local policy shorthand", env: map[string]string{core.EnvAllowedPorts: "0"}, want: "SENSOR_ALLOWED_PORTS", code: ExitUsage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts, _, _ := baseOptions(t, f)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if c.opts != nil {
				c.opts(&opts)
			}
			_, err := New(opts)
			if err == nil || !strings.Contains(err.Error(), c.want) || ExitCode(err) != c.code {
				t.Fatalf("err = %v (exit %d), want %q (exit %d)", err, ExitCode(err), c.want, c.code)
			}
		})
	}
}

// Settings come from the environment when Options leave them zero.
func TestNew_ReadsEnvironment(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	t.Setenv(EnvAPIURL, opts.APIURL)
	t.Setenv(EnvAPIKey, opts.APIKey)
	t.Setenv(EnvSensorName, "env-name")
	t.Setenv(EnvSensorID, "env-id")
	t.Setenv(EnvMaxJobs, "7")
	t.Setenv(EnvTools, "a, b")
	opts.APIURL, opts.APIKey, opts.Name = "", "", ""
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer k.closeClient()
	if k.Client() == nil || k.Name() != "env-name" || k.s.sensorID != "env-id" || k.s.maxJobs != 7 ||
		strings.Join(k.s.allow, ",") != "a,b" || k.s.protocol != "auto" {
		t.Fatalf("settings %+v", k.s)
	}
}

// persistentState makes the kit see its state directory as persistent (or
// not) whatever the test host is.
func persistentState(t *testing.T, persistent bool) {
	t.Helper()
	prev := statePersistence
	statePersistence = func(string) platform.StatePersistence {
		return platform.StatePersistence{Persistent: persistent, Reason: "test"}
	}
	t.Cleanup(func() { statePersistence = prev })
}

// The renewed key survives a restart: a first run renews (the platform
// retires the configured key at once), a second kit started with the same
// configured key and state directory comes back on the renewed key, and the
// platform accepts its heartbeats.
func TestRun_RenewedKeySurvivesRestart(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, out, _ := baseOptions(t, f)
	persistentState(t, true)
	installed := opts.APIKey

	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	stop := runKit(t, k)
	waitFor(t, "a key renewal", func() bool { return len(f.RequestsTo("POST", "/api/v2/sensor/keys")) > 0 })
	file := platform.StateCredentialsFile(opts.StateDir)
	waitFor(t, "the renewed key saved in the state directory", func() bool {
		c, err := platform.NewFileCredentialStore(file).Load()
		return err == nil && c.APIKey == f.APIKey && c.APIKey != installed
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Key auto-renew: enabled, state persists") {
		t.Fatalf("stdout: %s", out.String())
	}
	st, err := os.Stat(file)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file mode: %v %v", st, err)
	}

	// Restart: same configured key (now refused by the platform), same state.
	beats := len(f.Heartbeats())
	opts2 := opts
	opts2.Stdout, opts2.Stderr = &syncBuffer{}, &syncBuffer{}
	k2, err := New(opts2)
	if err != nil {
		t.Fatal(err)
	}
	if k2.s.apiKey != f.APIKey || !strings.Contains(opts2.Stderr.(*syncBuffer).String(), "Using the renewed API key from "+file) {
		t.Fatalf("restart key %q, platform key %q", k2.s.apiKey, f.APIKey)
	}
	stop2 := runKit(t, k2)
	waitFor(t, "a heartbeat with the renewed key", func() bool { return len(f.Heartbeats()) > beats })
	if err := stop2(); err != nil {
		t.Fatal(err)
	}
}

// An administrator regenerated the key and the operator configured it: the
// configured key wins over the file renewed from the old one.
func TestNew_ChangedConfiguredKeyWins(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	persistentState(t, true)
	store := platform.NewFileCredentialStore(platform.StateCredentialsFile(opts.StateDir))
	exp := time.Now().Add(48 * time.Hour)
	if err := platform.RotatedKeySaver(store, "rda_old_installed", "")("rda_renewed_from_old", &exp); err != nil {
		t.Fatal(err)
	}

	opts.APIKey = "rda_old_installed"
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.closeClient()
	if k.s.apiKey != "rda_renewed_from_old" {
		t.Fatalf("same configured key: started with %q, want the renewed key", k.s.apiKey)
	}

	opts.APIKey = "rda_regenerated_by_admin"
	k, err = New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.closeClient()
	if k.s.apiKey != "rda_regenerated_by_admin" {
		t.Fatalf("changed configured key: started with %q, want it", k.s.apiKey)
	}
}

// Without persistent state the kit does not renew (a renewed key would be
// lost with the container), unless renewal is forced; NoKeyAutoRenew and
// PLATFORM_KEY_AUTORENEW=false turn it off on persistent state too.
func TestNew_KeyAutoRenewDecision(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	cases := []struct {
		name       string
		persistent bool
		env        string
		force, off bool
		want       bool
	}{
		{"ephemeral state", false, "", false, false, false},
		{"ephemeral state, forced by option", false, "", true, false, true},
		{"ephemeral state, forced by env", false, "true", false, false, true},
		{"persistent state", true, "", false, false, true},
		{"persistent state, off by option", true, "", false, true, false},
		{"persistent state, off by env", true, "false", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts, _, _ := baseOptions(t, f)
			persistentState(t, c.persistent)
			t.Setenv(EnvKeyAutoRenew, c.env)
			opts.KeyAutoRenew, opts.NoKeyAutoRenew = c.force, c.off
			k, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			k.closeClient()
			if k.s.key.autoRenew != c.want || k.s.key.why == "" {
				t.Fatalf("autoRenew = %v (%s), want %v", k.s.key.autoRenew, k.s.key.why, c.want)
			}
		})
	}
}

func TestKeyRenewer_SwapsEveryClient(t *testing.T) {
	api := client.New(&client.Config{BaseURL: "https://api.example", APIKey: "old"})
	r := &keyRenewer{
		renew: platform.NewPlatformClient(&platform.ClientConfig{BaseURL: "https://api.example", APIKey: "old"}),
		api:   api,
	}
	var _ platform.KeyRenewer = r
	r.SetAPIKey("new")
	if api.APIKeyHint() == core.APIKeyHint("old") {
		t.Fatal("the API client kept the old key")
	}
}

// Key auto-renewal: a key without a known expiry is renewed at start, saved
// to an explicit credentials file, and the new key is used from then on.
func TestRun_KeyAutoRenew(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	opts, out, _ := baseOptions(t, f)
	opts.KeyAutoRenew = true
	opts.CredentialsFile = filepath.Join(t.TempDir(), "creds.json")
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	stop := runKit(t, k)
	waitFor(t, "a key renewal", func() bool { return len(f.RequestsTo("POST", "/api/v2/sensor/keys")) > 0 })
	waitFor(t, "the renewed key saved", func() bool {
		c, err := platform.NewFileCredentialStore(opts.CredentialsFile).Load()
		return err == nil && c.APIKey != "" && c.APIKey != opts.APIKey
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Key auto-renew: enabled, enabled by configuration (credentials: "+opts.CredentialsFile+")") {
		t.Fatalf("stdout: %s", out.String())
	}
}

type statusErr struct{ code int }

func (e *statusErr) Error() string       { return fmt.Sprintf("http %d", e.code) }
func (e *statusErr) HTTPStatusCode() int { return e.code }

func TestWaitForAcceptedKey_RetriesWhileRejected(t *testing.T) {
	results := []error{&statusErr{401}, fmt.Errorf("wrapped: %w", &statusErr{403}), nil}
	delays := []time.Duration{30 * time.Second, time.Minute, 30 * time.Second}
	calls := 0
	first := func(context.Context) (time.Duration, error) {
		d, err := delays[calls], results[calls]
		calls++
		return d, err
	}
	var waited []time.Duration
	wait := func(_ context.Context, d time.Duration) bool { waited = append(waited, d); return true }
	var out bytes.Buffer
	if !waitForAcceptedKey(context.Background(), first, wait, &out) {
		t.Fatal("must return true once the key is accepted")
	}
	if calls != 3 || len(waited) != 2 || waited[0] != 30*time.Second || waited[1] != time.Minute {
		t.Fatalf("calls %d waited %v", calls, waited)
	}
	if out.String() != "✓ Connected to API\n" {
		t.Fatalf("out %q", out.String())
	}
}

func TestWaitForAcceptedKey_NetworkFailureDoesNotBlockStart(t *testing.T) {
	calls := 0
	first := func(context.Context) (time.Duration, error) {
		calls++
		return time.Minute, errors.New("dial tcp: connection refused")
	}
	wait := func(context.Context, time.Duration) bool { t.Fatal("must not wait on a network failure"); return false }
	var out bytes.Buffer
	if !waitForAcceptedKey(context.Background(), first, wait, &out) || calls != 1 || out.Len() != 0 {
		t.Fatalf("network failure: calls %d out %q", calls, out.String())
	}
}

func TestWaitForAcceptedKey_StopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	first := func(context.Context) (time.Duration, error) { return time.Hour, &statusErr{401} }
	if waitForAcceptedKey(ctx, first, sleepCtx, &bytes.Buffer{}) {
		t.Fatal("a canceled wait must return false")
	}
}

// The first SIGTERM cancels the context (drain) and says so.
func TestSignalContext(t *testing.T) {
	var out syncBuffer
	ctx, stop := SignalContext(context.Background(), &out)
	defer stop()
	if ctx.Value(signalKey{}) == nil {
		t.Fatal("context not marked")
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not cancel the context")
	}
	waitFor(t, "the shutdown message", func() bool {
		return strings.Contains(out.String(), "Shutting down... (running scans get a grace period; signal again to stop at once)")
	})
}

// The capability reporter reports "no tool" rather than nothing.
func TestCapabilityReporter_EmptyInventory(t *testing.T) {
	r := &capabilityReporter{tools: core.NewToolRegistry()}
	rep := r.CapabilityReport(context.Background())
	if rep.Tools == nil || rep.Capabilities == nil || len(rep.Tools) != 0 {
		t.Fatalf("report %+v", rep)
	}
}

// settingsTestScanner declares a settings schema.
type settingsTestScanner struct {
	testScanner
	schema *core.SettingsSchema
}

func (s *settingsTestScanner) SettingsSchema() *core.SettingsSchema { return s.schema }

// A scanner configured under another name keeps its settings schema, so a
// command dispatched under that name still gets typed settings.
func TestAliasScanner_ForwardsSettingsSchema(t *testing.T) {
	schema := core.MustParseSettingsSchema(`{"$schema":"https://json-schema.org/draft/2020-12/schema","x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{"ports":{"type":"string","x-octm-scope":"scan"}}}`)
	a := aliasScanner{Scanner: &settingsTestScanner{schema: schema}, name: "naabu-web"}
	if a.SettingsSchema() != schema {
		t.Error("alias hides the wrapped scanner's settings schema")
	}
	if (aliasScanner{Scanner: &testScanner{}, name: "x"}).SettingsSchema() != nil {
		t.Error("alias invents a schema")
	}
}
