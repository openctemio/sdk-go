package toolcompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

// legacyScanner is a scanner written against core.Scanner: it writes a CTIS
// report as its raw output.
type legacyScanner struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	// Token is a secret: it never leaves the sensor's process.
	Token string `json:"-"`
	// Undeclared makes it also report a secret finding, a type the
	// manifest does not declare.
	Undeclared bool `json:"undeclared,omitempty"`
}

func (s *legacyScanner) Name() string           { return "legacy" }
func (s *legacyScanner) Version() string        { return "2.4.1" }
func (s *legacyScanner) Capabilities() []string { return []string{"misconfiguration"} }
func (s *legacyScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "2.4.1", nil
}

func (s *legacyScanner) Scan(_ context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	if target == "down.example" {
		return nil, errors.New("connection refused")
	}
	title := fmt.Sprintf("%s on %s", s.Rule, target)
	if s.Token != "" {
		title += " (authenticated)"
	}
	if opts != nil && opts.RateLimit > 0 {
		title += fmt.Sprintf(" at %d rps", opts.RateLimit)
	}
	if opts != nil && opts.Settings != nil {
		if d, ok := opts.Settings.Int("depth"); ok {
			title += fmt.Sprintf(" depth %d", d)
		}
	}
	r := ctis.Report{Version: "1.3", Metadata: ctis.ReportMetadata{Timestamp: mustTime()},
		Tool:     &ctis.Tool{Name: "legacy", Version: "2.4.1"},
		Findings: []ctis.Finding{{Type: "misconfiguration", RuleID: s.Rule, Title: title, Severity: ctis.Severity(s.Severity)}}}
	if s.Undeclared {
		r.Findings = append(r.Findings, ctis.Finding{Type: "secret", Title: "a secret", Severity: "high"})
	}
	raw, _ := json.Marshal(r)
	return &core.ScanResult{ScannerName: "legacy", RawOutput: raw}, nil
}

var legacyManifest = tool.Manifest{
	Name: "legacy", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces:    []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetNone, Credentials: []tool.CredentialReq{{Name: "token", Kind: "token"}}},
}

// The compiled-in instances: the child builds the same ones (TestMain).
var (
	plainScanner = &legacyScanner{Rule: "default-rule", Severity: "medium"}
	plain        = FromScanner(legacyManifest, plainScanner)

	stateScanner = &legacyScanner{Rule: "default-rule", Severity: "medium"}
	stateful     = FromScanner(withName(legacyManifest, "legacy-state"), stateScanner, WithState(),
		WithPrepare(func(ctx tool.Context, legacy any) error {
			if sec, err := ctx.Secret("token"); err == nil {
				legacy.(*legacyScanner).Token = sec.Reveal()
			}
			if _, err := ctx.Secret("other"); !errors.Is(err, tool.ErrUndeclaredCredential) {
				return fmt.Errorf("an undeclared credential was delivered: %v", err)
			}
			return nil
		}))

	configured = FromScanner(withConfig(withName(legacyManifest, "legacy-config")), &legacyScanner{Rule: "cfg", Severity: "low"})

	multi = FromScanner(withName(legacyManifest, "legacy-multi"), &multiScanner{legacyScanner{Rule: "m", Severity: "low"}})

	coll = FromCollector(tool.Manifest{
		Name: "legacy-collector", Version: "1.0.0", Class: tool.Connector, Tier: tool.T0,
		Produces:    []string{"asset:repository"},
		Permissions: tool.Permissions{VendorHosts: []string{"api.vendor.example"}, Credentials: []tool.CredentialReq{{Name: "api_key", Kind: "api_key", Required: true}}},
	}, &legacyCollector{}, WithAPIKeyCredential("api_key"))
)

func withName(m tool.Manifest, name string) tool.Manifest { m.Name = name; return m }

func withConfig(m tool.Manifest) tool.Manifest {
	m.Config = json.RawMessage(`{"type":"object","additionalProperties":false,"x-octm-schema-version":1,"properties":{"depth":{"type":"integer","minimum":1,"maximum":5,"default":2}}}`)
	return m
}

// multiScanner scans every target in one call.
type multiScanner struct{ legacyScanner }

func (m *multiScanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return m.Scan(ctx, strings.Join(targets, "+"), opts)
}

// legacyCollector collects one repository with the API key it is given.
type legacyCollector struct{}

func (legacyCollector) Name() string                         { return "legacy-collector" }
func (legacyCollector) Type() string                         { return "api" }
func (legacyCollector) TestConnection(context.Context) error { return nil }
func (legacyCollector) Collect(_ context.Context, o *core.CollectOptions) (*core.CollectResult, error) {
	if o.APIKey != "vendor-key-123" {
		return nil, fmt.Errorf("unauthorized (got a key of %d bytes)", len(o.APIKey))
	}
	r := ctis.Report{Version: "1.3", Metadata: ctis.ReportMetadata{Timestamp: mustTime()},
		Assets: []ctis.Asset{{Type: "repository", Value: "github.com/acme/" + o.Repository, Name: o.Repository}}}
	return &core.CollectResult{Reports: []*ctis.Report{&r}}, nil
}

func TestMain(m *testing.M) {
	executor.RunLauncherIfRequested()
	adapter.Dispatch(plain, stateful, configured, multi, coll, capTool)
	os.Exit(m.Run())
}

func host(t *testing.T) *toolhost.Host {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &toolhost.Host{Self: exe, Sensor: "test", RuntimeName: "toolcompat-test"}
}

func targets(values ...string) []tool.Target {
	out := make([]tool.Target, len(values))
	for i, v := range values {
		out[i] = tool.Target{Ref: fmt.Sprintf("t%d", i), Value: v}
	}
	return out
}

func run(t *testing.T, b tool.Tool, task tool.Task, o toolhost.RunOptions) *toolhost.Outcome {
	t.Helper()
	out, err := host(t).RunBuiltin(context.Background(), b, task, o)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// normalize keeps a report's records: the envelope (schema version, tool,
// metadata, provenance) is the runtime's, so two reports of the same scan
// compare byte for byte on what the scanner found.
func normalize(t *testing.T, r *ctis.Report) string {
	t.Helper()
	cp := ctis.Report{Assets: r.Assets, Findings: r.Findings, Dependencies: r.Dependencies}
	b, err := testkit.Normalize(&cp)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestBridgedScannerParity: the same scan, run directly and through the
// bridge out of process, gives the same CTIS.
func TestBridgedScannerParity(t *testing.T) {
	res, err := plainScanner.Scan(context.Background(), "a.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := (&core.JSONParser{}).Parse(context.Background(), res.RawOutput, &core.ParseOptions{ToolName: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	out := run(t, plain, tool.Task{Targets: targets("a.example")}, toolhost.RunOptions{})
	if out.Status != tool.StatusOK || out.Err != nil {
		t.Fatalf("outcome %s %+v (stderr %s)", out.Status, out.Err, out.Stderr)
	}
	if got, want := normalize(t, out.Report), normalize(t, direct); got != want {
		t.Fatalf("CTIS differs\nbridged: %s\ndirect:  %s", got, want)
	}
	if out.Sandbox.Backend == "" {
		t.Fatal("no sandbox status: the bridge did not run out of process")
	}
}

// TestBridgeTargetsAndFailures: each target is scanned; a failed scan fails
// its target only.
func TestBridgeTargetsAndFailures(t *testing.T) {
	out := run(t, plain, tool.Task{Targets: targets("a.example", "down.example", "b.example")}, toolhost.RunOptions{})
	if out.Status != tool.StatusPartial {
		t.Fatalf("status %s", out.Status)
	}
	states := map[string]tool.TargetState{}
	for _, to := range out.Targets {
		states[to.Value] = to.State
	}
	if states["a.example"] != tool.StateDone || states["b.example"] != tool.StateDone || states["down.example"] != tool.StateFailed {
		t.Fatalf("targets %+v", out.Targets)
	}
	if len(out.Report.Findings) != 2 {
		t.Fatalf("findings %d", len(out.Report.Findings))
	}
}

// TestBridgeMultiTarget: a MultiTargetScanner gets every target at once.
func TestBridgeMultiTarget(t *testing.T) {
	out := run(t, multi, tool.Task{Targets: targets("a.example", "b.example")}, toolhost.RunOptions{})
	if out.Status != tool.StatusOK || len(out.Report.Findings) != 1 || !strings.Contains(out.Report.Findings[0].Title, "a.example+b.example") {
		t.Fatalf("outcome %s %+v", out.Status, out.Report.Findings)
	}
}

// TestBridgeStateAndCredentials: the scanner's exported state reaches the
// child; its secret field does not; the declared credential arrives only
// through ctx.Secret; scan options cross over.
func TestBridgeStateAndCredentials(t *testing.T) {
	stateScanner.Rule, stateScanner.Token = "operator-rule", "tok-in-parent-only"
	t.Cleanup(func() { stateScanner.Rule, stateScanner.Token = "default-rule", "" })
	local, err := stateful.Local(&core.ScanOptions{RateLimit: 7})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(local, []byte("tok-in-parent-only")) {
		t.Fatalf("a secret field crossed into Task.Local: %s", local)
	}
	out := run(t, stateful, tool.Task{Targets: targets("a.example"), Local: local}, toolhost.RunOptions{})
	if out.Err != nil || len(out.Report.Findings) != 1 {
		t.Fatalf("outcome %+v %+v (stderr %s)", out.Err, out.Report.Findings, out.Stderr)
	}
	f := out.Report.Findings[0]
	if f.RuleID != "operator-rule" || strings.Contains(f.Title, "authenticated") || !strings.Contains(f.Title, "at 7 rps") {
		t.Fatalf("finding %+v", f)
	}
	// With the declared credential stored by the operator.
	out = run(t, stateful, tool.Task{Targets: targets("a.example"), Local: local}, toolhost.RunOptions{
		Credentials: map[string]string{"token": "declared-token-1", "other": "never-delivered"}})
	if out.Err != nil || !strings.Contains(out.Report.Findings[0].Title, "authenticated") {
		t.Fatalf("outcome %+v %+v", out.Err, out.Report.Findings)
	}
	for _, l := range out.Logs {
		if strings.Contains(l.Msg, "declared-token-1") {
			t.Fatal("a credential reached the log")
		}
	}
}

// TestBridgeConfig: the task's configuration, validated against the
// manifest's schema, reaches the scanner as its settings.
func TestBridgeConfig(t *testing.T) {
	out := run(t, configured, tool.Task{Targets: targets("a.example"), Config: json.RawMessage(`{"depth":4}`)}, toolhost.RunOptions{})
	if out.Err != nil || !strings.Contains(out.Report.Findings[0].Title, "depth 4") {
		t.Fatalf("outcome %+v %+v", out.Err, out.Report.Findings)
	}
	out = run(t, configured, tool.Task{Targets: targets("a.example"), Config: json.RawMessage(`{"depth":9}`)}, toolhost.RunOptions{})
	if out.Err == nil || out.Err.Class != tool.InvalidInput {
		t.Fatalf("an out-of-range setting ran: %+v", out.Err)
	}
	out = run(t, configured, tool.Task{Targets: targets("a.example"), Config: json.RawMessage(`{"extra_args":["--evil"]}`)}, toolhost.RunOptions{})
	if out.Err == nil || out.Err.Class != tool.InvalidInput {
		t.Fatalf("an unknown setting ran: %+v", out.Err)
	}
}

// TestBridgeUndeclaredOutputQuarantined: a record type the manifest does
// not declare never reaches the report.
func TestBridgeUndeclaredOutputQuarantined(t *testing.T) {
	// The stateful bridge: its state carries the switch to the child.
	stateScanner.Undeclared = true
	t.Cleanup(func() { stateScanner.Undeclared = false })
	local, _ := stateful.Local(nil)
	out := run(t, stateful, tool.Task{Targets: targets("a.example"), Local: local}, toolhost.RunOptions{})
	for _, f := range out.Report.Findings {
		if f.Type == "secret" {
			t.Fatal("an undeclared finding type was delivered")
		}
	}
	if out.Stats.Quarantined["finding:secret"] != 1 || out.Status != tool.StatusPartial {
		t.Fatalf("stats %+v status %s", out.Stats, out.Status)
	}
}

// TestBridgeHostileLocal: an unreadable Task.Local fails the task as
// invalid input; nothing is scanned.
func TestBridgeHostileLocal(t *testing.T) {
	out := run(t, stateful, tool.Task{Targets: targets("a.example"), Local: json.RawMessage(`{"state":"not an object"}`)}, toolhost.RunOptions{})
	if out.Err == nil || out.Err.Class != tool.InvalidInput || len(out.Report.Findings) != 0 {
		t.Fatalf("outcome %+v", out.Err)
	}
}

// TestBridgedCollector: the collector runs out of process with the API key
// as a declared credential; the sensor's APIKey never crosses in Local.
func TestBridgedCollector(t *testing.T) {
	local, err := coll.Local(&core.CollectOptions{Repository: "web", APIKey: "sensor-side-key"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(local, []byte("sensor-side-key")) {
		t.Fatalf("the API key crossed into Task.Local: %s", local)
	}
	out := run(t, coll, tool.Task{Local: local}, toolhost.RunOptions{Credentials: map[string]string{"api_key": "vendor-key-123"}})
	if out.Err != nil || len(out.Report.Assets) != 1 || out.Report.Assets[0].Value != "github.com/acme/web" {
		t.Fatalf("outcome %+v %+v (stderr %s)", out.Err, out.Report.Assets, out.Stderr)
	}
	out = run(t, coll, tool.Task{Local: local}, toolhost.RunOptions{})
	if out.Err == nil || out.Err.Class != tool.InvalidInput {
		t.Fatalf("a required credential missing ran: %+v", out.Err)
	}
}

func TestFromScannerPanics(t *testing.T) {
	for name, fn := range map[string]func(){
		"nil scanner":      func() { FromScanner(legacyManifest, nil) },
		"state of a value": func() { FromScanner(legacyManifest, valueScannerOf(), WithState()) },
		"invalid manifest": func() { FromScanner(tool.Manifest{Name: "X"}, plainScanner) },
		"nil collector":    func() { FromCollector(legacyManifest, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic")
				}
			}()
			fn()
		})
	}
}

// scannerValue is a core.Scanner implemented on a value (not a pointer).
type scannerValue struct{}

func (scannerValue) Name() string           { return "v" }
func (scannerValue) Version() string        { return "1" }
func (scannerValue) Capabilities() []string { return nil }
func (scannerValue) Scan(context.Context, string, *core.ScanOptions) (*core.ScanResult, error) {
	return nil, nil
}
func (scannerValue) IsInstalled(context.Context) (bool, string, error) { return true, "1", nil }

func valueScannerOf() core.Scanner { return scannerValue{} }

func mustTime() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) }
