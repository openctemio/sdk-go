package sensorkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/outbox"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
	"github.com/openctemio/sdk-go/pkg/tool/toolcompat"
)

// contractTool is a new tool written against the tool contract.
var contractTool = tool.New(tool.Manifest{
	Name: "kit-contract", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Capabilities: []string{"web"},
	Produces:     []string{"finding:misconfiguration"},
	Permissions:  tool.Permissions{Network: tool.NetNone, Credentials: []tool.CredentialReq{{Name: "api_key", Kind: "api_key"}}},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	key, kerr := ctx.Secret("api_key")
	if _, err := ctx.Secret("other_tool_key"); !errors.Is(err, tool.ErrUndeclaredCredential) {
		return fmt.Errorf("an undeclared credential was delivered: %v", err)
	}
	for _, kv := range os.Environ() {
		if kerr == nil && strings.Contains(kv, key.Reveal()) {
			return errors.New("a credential is in the environment")
		}
	}
	for _, t := range task.Targets {
		title := "contract finding on " + t.Value
		if kerr == nil {
			title += " (with key)"
		}
		if err := ctx.Emit().Finding(t, ctis.Finding{Type: "misconfiguration", RuleID: "kc", Title: title, Severity: "low"}); err != nil {
			return err
		}
		ctx.TargetDone(t)
	}
	return nil
})

// probeScanner is a legacy core.Scanner; ReadPath is a file it tries to
// read (a protected file must stay unreadable in the sandbox).
type probeScanner struct {
	ReadPath string `json:"read_path,omitempty"`
}

func (s *probeScanner) Name() string           { return "kit-bridged" }
func (s *probeScanner) Version() string        { return "3.1.0" }
func (s *probeScanner) Capabilities() []string { return []string{"sast"} }
func (s *probeScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "3.1.0", nil
}

func (s *probeScanner) Scan(_ context.Context, target string, _ *core.ScanOptions) (*core.ScanResult, error) {
	read := "none"
	if s.ReadPath != "" {
		if _, err := os.ReadFile(s.ReadPath); err == nil {
			read = "READ-OK"
		} else {
			read = "denied"
		}
	}
	r := ctis.Report{Version: "1.3", Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()},
		Findings: []ctis.Finding{{Type: "misconfiguration", RuleID: "kb", Title: "bridged finding on " + target + " read=" + read, Severity: "medium"}}}
	raw, _ := json.Marshal(r)
	return &core.ScanResult{RawOutput: raw}, nil
}

var (
	probe         = &probeScanner{}
	bridgedLegacy = toolcompat.FromScanner(tool.Manifest{
		Name: "kit-bridged", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Produces: []string{"finding:misconfiguration"}, Permissions: tool.Permissions{Network: tool.NetNone},
	}, probe, toolcompat.WithState())
)

func TestMain(m *testing.M) {
	executor.RunLauncherIfRequested()
	adapter.Dispatch(contractTool, bridgedLegacy, loggingTool)
	os.Exit(m.Run())
}

// scanPayload is a scan command for tool on target.
func scanPayload(tool, target string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"scanner":%q,"target":%q}`, tool, target))
}

func waitCompleted(t *testing.T, f *conformance.FakePlatform, id string, out, errw *syncBuffer) {
	t.Helper()
	waitFor(t, "command "+id, func() bool {
		s, e := f.CommandState(id)
		if s == "failed" {
			t.Fatalf("command %s failed: %s\nstdout:%s\nstderr:%s", id, e, out.String(), errw.String())
		}
		return s == "completed"
	})
}

func acceptedTitles(f *conformance.FakePlatform) []string {
	var out []string
	for _, r := range f.AcceptedReports() {
		for _, fd := range r.Findings {
			out = append(out, fd.Title)
		}
	}
	return out
}

// TestKit_ContractTools: a new tool and a bridged legacy scanner, both on
// the tool contract, are reported with their contracts, run dispatched
// scans out of process and deliver through the outbox. The tool gets the
// credential its manifest declares and nothing else, and cannot read the
// outbox key.
func TestKit_ContractTools(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetManifest(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	opts.ToolCredentials = func(name string) map[string]string {
		if name == "kit-contract" {
			return map[string]string{"api_key": "k-contract-123", "other_tool_key": "never"}
		}
		return nil
	}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := outbox.DefaultKeyFile(opts.Outbox.Dir)
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("outbox key: %v", err)
	}
	probe.ReadPath = keyFile
	t.Cleanup(func() { probe.ReadPath = "" })
	k.AddTool(contractTool)
	k.AddTool(bridgedLegacy)

	f.QueueCommandPayload("0192a3b4-0000-7000-8000-0000000000c1", "scan", scanPayload("kit-contract", "1.1.1.1"))
	f.QueueCommandPayload("0192a3b4-0000-7000-8000-0000000000c2", "scan", scanPayload("kit-bridged", "8.8.8.8"))
	stop := runKit(t, k)
	waitCompleted(t, f, "0192a3b4-0000-7000-8000-0000000000c1", out, errw)
	waitCompleted(t, f, "0192a3b4-0000-7000-8000-0000000000c2", out, errw)
	waitFor(t, "findings delivered", func() bool { return len(acceptedTitles(f)) >= 2 })
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	titles := strings.Join(acceptedTitles(f), "\n")
	if !strings.Contains(titles, "contract finding on 1.1.1.1 (with key)") {
		t.Errorf("contract tool output missing or without its credential:\n%s", titles)
	}
	if !strings.Contains(titles, "bridged finding on 8.8.8.8") {
		t.Errorf("bridged scanner output missing:\n%s", titles)
	}
	if st := executor.Current().Status(); st.Landlock > 0 {
		if !strings.Contains(titles, "read=denied") {
			t.Errorf("a tool read the outbox key in the sandbox (%+v):\n%s", st, titles)
		}
	} else {
		t.Logf("no Landlock on this host: the protected-path read is not enforced (%+v)", st)
	}
	// The heartbeat reports both tools; the manifest carries their
	// contracts (digest, class, tier, produces).
	hb := lastBeat(t, f)
	names := map[string]core.ToolInfo{}
	for _, ti := range hb.Tools {
		names[ti.Name] = ti
	}
	if !names["kit-contract"].Installed || !names["kit-bridged"].Installed || names["kit-bridged"].Version != "3.1.0" {
		t.Fatalf("tools: %+v", hb.Tools)
	}
	mans := f.Manifests()
	if len(mans) == 0 {
		t.Fatal("no sensor manifest")
	}
	last := string(mans[len(mans)-1])
	for _, want := range []string{contractTool.Manifest().Digest(), bridgedLegacy.Manifest().Digest()} {
		if !strings.Contains(last, want) {
			t.Errorf("the sensor manifest lacks contract digest %s", want)
		}
	}
	if strings.Contains(out.String()+errw.String(), "k-contract-123") {
		t.Error("a credential reached the sensor's log")
	}
}

// TestKitPolicy_FollowsReload: admission reads the local policy in force,
// so a reloaded policy applies to the next task.
func TestKitPolicy_FollowsReload(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	pol := k.toolHost().Policy
	if !pol.AllowsTool("kit-contract") || pol.KillSwitchEngaged() {
		t.Fatal("no local policy: everything allowed")
	}
	lp, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\ntools:\n  allow: [\"other\"]\nkill_switch: true\n"), core.LocalPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	k.SetLocalPolicy(lp)
	if pol.AllowsTool("kit-contract") || !pol.KillSwitchEngaged() {
		t.Fatal("the reloaded policy is not used for admission")
	}
}

// TestKit_AdapterDirsDefaultFromEnv: SENSOR_ADAPTER_DIRS when the option
// is nil.
func TestKit_AdapterDirsDefaultFromEnv(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	t.Setenv(EnvAdapterDirs, a+string(filepath.ListSeparator)+" "+string(filepath.ListSeparator)+b)
	k := &Kit{}
	if got := k.adapterDirs(); len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("dirs %v", got)
	}
	k.opts.AdapterDirs = []string{}
	if got := k.adapterDirs(); len(got) != 0 {
		t.Fatalf("an empty option must disable the env: %v", got)
	}
}
