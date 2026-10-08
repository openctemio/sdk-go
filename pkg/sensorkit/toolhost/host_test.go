package toolhost

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/internal/toolwire"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

// echoTool is a well-behaved compiled-in tool: one finding per target, and
// what it could see of its environment.
var echoTool = tool.New(tool.Manifest{
	Name: "echo-tool", Version: "1.2.0", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"domain"}, Produces: []string{"finding:misconfiguration", "asset:domain"},
	Permissions: tool.Permissions{Network: tool.NetNone, Credentials: []tool.CredentialReq{{Name: "api_key", Kind: "api_key"}}},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	if k, err := ctx.Secret("api_key"); err == nil {
		ctx.Log().Info("using key " + k.Reveal())
		if len(os.Args) > 1 && os.Args[1] == adapter.ToolArg {
			fmt.Println("stray print with key", k.Reveal()) // must not corrupt the protocol
		}
	}
	if _, err := ctx.Secret("db_password"); !errors.Is(err, tool.ErrUndeclaredCredential) {
		return fmt.Errorf("undeclared credential delivered: %v", err)
	}
	if p := os.Getenv("TOOLHOST_READ"); p != "" {
		if _, err := os.ReadFile(p); err == nil {
			return errors.New("read a protected file")
		}
	}
	if os.Getenv("TOOLHOST_SLEEP") != "" {
		<-ctx.Done()
		return ctx.Err()
	}
	_ = ctx.Emit().Report(&ctis.Report{Tool: &ctis.Tool{Name: "pretender", Version: "v3.1", Vendor: "Acme"},
		Properties: ctis.Properties{"note": "x"}})
	for _, t := range task.Targets {
		if err := ctx.Emit().Finding(t, ctis.Finding{Type: "misconfiguration", RuleID: "r1", Title: "issue on " + t.Value, Severity: "medium"}); err != nil {
			return err
		}
		ctx.TargetDone(t)
	}
	w, err := ctx.Artifact("raw.txt", "text/plain")
	if err != nil {
		return err
	}
	_, _ = w.Write([]byte("raw"))
	return w.Close()
})

func TestMain(m *testing.M) {
	executor.RunLauncherIfRequested()
	adapter.Dispatch(echoTool, dialTool, retestTool, contractTool)
	if mode := os.Getenv("TOOLHOST_HOSTILE"); mode != "" {
		os.Exit(hostile(mode))
	}
	os.Exit(m.Run())
}

var hostileManifest = tool.Manifest{
	Name: "hostile", Version: "0.0.1", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"domain"}, Produces: []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetNone, Credentials: []tool.CredentialReq{{Name: "api_key", Kind: "api_key"}}},
	Resources:   tool.Resources{IdleTimeout: tool.Duration(2 * time.Second), Timeout: tool.Duration(30 * time.Second), MaxRecords: 50},
}

// hostile is an adapter that misbehaves as mode says.
func hostile(mode string) int {
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	send := func(s string) { _, _ = out.WriteString(s + "\n"); _ = out.Flush() }
	read := func() map[string]any {
		line, err := in.ReadBytes('\n')
		if err != nil {
			os.Exit(0)
		}
		var m map[string]any
		_ = json.Unmarshal(line, &m)
		return m
	}
	m := hostileManifest
	if mode == "liar" {
		m.Permissions.Network = tool.NetVendor
		m.Class = tool.Connector
	}
	if mode == "retest-liar" || mode == "retest-evidence" {
		m.Retest = true
	}
	mb, _ := json.Marshal(m.Normalized())
	handshake := func() map[string]any {
		read() // hello
		send(`{"v":1,"type":"hello","protocol":1,"sdk":{"name":"hostile"}}`)
		read() // describe
		send(`{"v":1,"type":"manifest","manifest":` + string(mb) + `}`)
		return read() // run
	}
	switch mode {
	case "garbage":
		handshake()
		for range 1100 {
			send("this is not json")
		}
		time.Sleep(10 * time.Second)
	case "longline":
		handshake()
		send(`{"v":1,"type":"log","level":"info","msg":"` + strings.Repeat("a", 2<<20) + `"}`)
		time.Sleep(10 * time.Second)
	case "flood":
		handshake()
		for i := 0; ; i++ {
			send(fmt.Sprintf(`{"v":1,"type":"record","kind":"finding","target":"t1","data":{"type":"misconfiguration","title":"f%d","severity":"low"}}`, i))
		}
	case "noresult":
		handshake()
		send(`{"v":1,"type":"record","kind":"finding","target":"t1","data":{"type":"misconfiguration","title":"half","severity":"low"}}`)
		return 0
	case "silent":
		handshake()
		time.Sleep(time.Minute)
	case "liar":
		handshake()
		send(`{"v":1,"type":"result","status":"ok"}`)
	case "symlink":
		run := handshake()
		task, _ := run["task"].(map[string]any)
		wd, _ := task["workdir"].(string)
		_ = os.Symlink("/etc/hostname", filepath.Join(wd, "a.txt"))
		send(`{"v":1,"type":"artifact","name":"a.txt","media_type":"text/plain","path":"a.txt","sha256":"00","size":1}`)
		send(`{"v":1,"type":"artifact","name":"b.txt","media_type":"text/plain","path":"../../etc/passwd","sha256":"00","size":1}`)
		send(`{"v":1,"type":"target_status","target":"t1","status":"done"}`)
		send(`{"v":1,"type":"result","status":"ok"}`)
	case "dirty":
		run := handshake()
		task, _ := run["task"].(map[string]any)
		creds, _ := json.Marshal(task["credentials"])
		send(`{"v":1,"type":"log","level":"info","msg":"creds ` + strings.ReplaceAll(string(creds), `"`, `'`) + `"}`)
		send(`{"v":1,"type":"report_info","info":{"tool":{"name":"nuclei"},"metadata":{"properties":{"provenance":"forged"}}}}`)
		send(`{"v":1,"type":"record","kind":"finding","target":"t1","data":{"type":"misconfiguration","title":"evil\u202e\u0007title \u001b[31m","severity":"low"}}`)
		send(`{"v":1,"type":"record","kind":"asset","data":{"type":"ip_address","value":"10.0.0.1"}}`)
		send(`{"v":1,"type":"record","kind":"finding","data":{"type":"misconfiguration","title":"x","severity":"low","unknown_member":1}}`)
		send(`{"v":1,"type":"future_message","x":1}`)
		send(`{"v":1,"type":"target_status","target":"t1","status":"done"}`)
		send(`{"v":1,"type":"target_status","target":"t9","status":"done"}`)
		send(`{"v":1,"type":"result","status":"ok","error":{"class":"tool_crashed"}}`)
	case "retest-liar":
		handshake()
		send(`{"v":1,"type":"record","kind":"finding","target":"t1","data":{"type":"misconfiguration","title":"sneaked in","severity":"low"}}`)
		send(`{"v":1,"type":"verdict","item":"not-in-task","verdict":"fixed"}`)
		send(`{"v":1,"type":"verdict","item":"f1","verdict":"fixed","detail":"never reached it"}`)
		send(`{"v":1,"type":"result","status":"ok"}`)
	case "retest-evidence":
		// f1: fixed with six items (over the cap); f2: fixed with an
		// invalid item; f3: fixed with an answered exchange whose
		// Authorization value is not marked.
		handshake()
		ex := `{"kind":"http_exchange","version":1,"http":{"request":{"method":"GET","url":"https://a.example/x","headers":[{"name":"Authorization","value":"Bearer leak-me"}]},"response":{"status":200}}}`
		six := strings.TrimSuffix(strings.Repeat(ex+",", 6), ",")
		send(`{"v":1,"type":"verdict","item":"f1","verdict":"fixed","evidence":[` + six + `]}`)
		send(`{"v":1,"type":"verdict","item":"f2","verdict":"fixed","evidence":[{"kind":"Not A Kind","version":1}]}`)
		send(`{"v":1,"type":"verdict","item":"f3","verdict":"fixed","template_digest":"sha256:t","evidence":[` + ex + `]}`)
		send(`{"v":1,"type":"target_status","target":"t1","status":"done"}`)
		send(`{"v":1,"type":"result","status":"ok"}`)
	case "claims-ok":
		handshake()
		send(`{"v":1,"type":"result","status":"ok"}`)
	case "jsonl-cli":
		// A port scanner writing one JSON object per open port.
		fmt.Println(`{"ip":"192.0.2.10","port":443,"protocol":"TCP","host":"a.example"}`)
		fmt.Println(`{"ip":"192.0.2.10","port":22,"protocol":"tcp","host":"a.example"}`)
		fmt.Println(`{"note":"progress line without a port"}`)
	case "nuclei-cli":
		fmt.Println(`{"template-id":"tech-exposed","info":{"name":"Exposed panel","severity":"medium"},"type":"http","host":"https://a.example","matched-at":"https://a.example/admin","timestamp":"2026-10-07T00:00:00Z"}`)
	case "sarif-cli":
		fmt.Println(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cli","rules":[{"id":"R1","shortDescription":{"text":"rule"}}]}},"results":[{"ruleId":"R1","level":"error","message":{"text":"bad thing"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":3}}}]}]}]}`)
	case "ctis-cli":
		fmt.Println(`{"version":"1.3","metadata":{"timestamp":"2026-01-01T00:00:00Z"},"findings":[{"type":"misconfiguration","title":"from cli","severity":"high"},{"type":"secret","title":"undeclared","severity":"high"}]}`)
		return 2
	case "egress-probe":
		// A CONNECT to its target through the proxy it was given, one to a
		// host it was not given, and a direct dial; the results go in the
		// finding title.
		var res []string
		proxyAddr := strings.TrimPrefix(os.Getenv("HTTPS_PROXY"), "http://")
		connect := func(target string) string {
			c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
			if err != nil {
				return "noproxy"
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
			line, _ := bufio.NewReader(c).ReadString('\n')
			if f := strings.Fields(line); len(f) > 1 {
				return f[1]
			}
			return "?"
		}
		res = append(res, "target="+connect(os.Getenv("TOOLHOST_TARGET")), "outside="+connect("outside.example:80"))
		if c, err := net.DialTimeout("tcp", "192.0.2.1:80", 2*time.Second); err == nil {
			_ = c.Close()
			res = append(res, "direct=reached")
		} else {
			res = append(res, "direct=blocked")
		}
		fmt.Printf(`{"version":"1.3","metadata":{"timestamp":"2026-01-01T00:00:00Z"},"findings":[{"type":"misconfiguration","title":%q,"severity":"low"}]}`+"\n", strings.Join(res, " "))
		return 0
	case "env-cli":
		// Reports, as a finding title, which vendor variables it can see.
		var seen []string
		for _, k := range []string{"TRIVY_PASSWORD", "SEMGREP_APP_TOKEN", "PDCP_API_KEY", "DOCKER_HOST"} {
			if os.Getenv(k) != "" {
				seen = append(seen, k)
			}
		}
		fmt.Printf(`{"version":"1.3","metadata":{"timestamp":"2026-01-01T00:00:00Z"},"findings":[{"type":"misconfiguration","title":"seen:%s","severity":"low"}]}`+"\n", strings.Join(seen, ","))
		return 0
	}
	return 0
}

// SECURITY: an operator-installed program gets no tool's vendor
// environment (TRIVY_*, SEMGREP_*, PDCP_*, DOCKER_HOST): one tool cannot
// read another's credentials from the sensor's environment.
func TestInstalledToolGetsNoVendorEnvironment(t *testing.T) {
	for k, v := range map[string]string{"TRIVY_PASSWORD": "t-secret", "SEMGREP_APP_TOKEN": "s-secret", "PDCP_API_KEY": "p-secret", "DOCKER_HOST": "tcp://d:2376"} {
		t.Setenv(k, v)
	}
	exe, _ := os.Executable()
	m := tool.Manifest{
		Name: "env-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T0,
		Consumes: []string{"repository"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetNone},
		Run:         &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	task := tool.Task{Targets: []tool.Target{{Ref: "r", Type: "repository", Value: "github.com/acme/app"}}}
	out, err := testHost(t).RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "env-cli"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != "seen:" {
		t.Fatalf("the installed tool saw vendor variables: %+v (status %s, stderr %s)", out.Report.Findings, out.Status, out.Stderr)
	}
}

func testHost(t *testing.T) *Host {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Host{Self: exe, Sensor: "test-sensor", RuntimeName: "toolhost-test"}
}

var oneTarget = []tool.Target{{Ref: "t1", Type: "domain", Value: "a.example"}}

func hostileRun(t *testing.T, mode string, m tool.Manifest, task tool.Task) *Outcome {
	t.Helper()
	exe, _ := os.Executable()
	m.Run = &tool.RunSpec{Argv: []string{exe}}
	if task.Targets == nil {
		task.Targets = oneTarget
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := testHost(t).RunManifest(ctx, m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": mode},
		Credentials: map[string]string{"api_key": "sk-declared-123", "db_password": "never-delivered"}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBuiltinRunsOutOfProcess(t *testing.T) {
	task := tool.Task{ID: "task-1", Targets: []tool.Target{{Ref: "t1", Type: "domain", Value: "a.example"}, {Ref: "t2", Type: "domain", Value: "b.example"}}}
	out, err := testHost(t).RunBuiltin(context.Background(), echoTool, task, RunOptions{
		Credentials: map[string]string{"api_key": "sk-live-abcdef", "db_password": "hunter2"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusOK || out.Err != nil {
		t.Fatalf("status %s err %v stderr %s logs %+v", out.Status, out.Err, out.Stderr, out.Logs)
	}
	if len(out.Report.Findings) != 2 || out.Report.Tool.Name != "echo-tool" || out.Report.Tool.Version != "v3.1" {
		t.Fatalf("report %+v tool %+v", out.Report.Findings, out.Report.Tool)
	}
	all := fmt.Sprintf("%+v %s", out.Logs, out.Stderr)
	if strings.Contains(all, "sk-live-abcdef") || strings.Contains(all, "hunter2") {
		t.Fatalf("a secret reached the logs: %s", all)
	}
	if !strings.Contains(out.Stderr, "stray print") {
		t.Fatalf("stdout of tool code not moved to stderr: %q", out.Stderr)
	}
	if len(out.Artifacts) != 1 || string(out.Artifacts[0].Data) != "raw" {
		t.Fatalf("artifacts %+v", out.Artifacts)
	}
	prov, _ := json.Marshal(out.Report.Metadata.Properties["provenance"])
	for _, want := range []string{`"tool":"echo-tool"`, `"task_id":"task-1"`, `"sensor":"test-sensor"`, `"manifest_digest":"sha256:`, "built-in"} {
		if !strings.Contains(string(prov), want) {
			t.Errorf("provenance %s lacks %s", prov, want)
		}
	}
	// The same tool in-process (testkit) gives the same CTIS.
	in := testkit.Run(t, echoTool, task, testkit.Options{Secrets: map[string]string{"api_key": "sk-live-abcdef"}})
	a, _ := testkit.Normalize(in.Report)
	b, _ := testkit.Normalize(out.Report)
	if string(a) != string(b) {
		t.Fatalf("in-process and out-of-process reports differ:\n%s\n%s", a, b)
	}
}

// SECURITY (acceptance): a compiled-in tool runs in the sandbox and cannot
// read the sensor's protected files.
func TestBuiltinRunsInTheSandbox(t *testing.T) {
	key := filepath.Join(t.TempDir(), "sensor.key")
	if err := os.WriteFile(key, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	be, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, ReadDeny: []string{key}, WorkRoot: t.TempDir()})
	if err != nil {
		t.Skipf("sandbox not available: %v", err)
	}
	h := testHost(t)
	h.Backend = be
	out, err := h.RunBuiltin(context.Background(), echoTool, tool.Task{Targets: oneTarget}, RunOptions{Env: map[string]string{"TOOLHOST_READ": key}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusOK || !out.Sandbox.Sandboxed {
		t.Fatalf("status %s err %v sandbox %+v stderr %s", out.Status, out.Err, out.Sandbox, out.Stderr)
	}
}

func TestRequiredCredentialMissingFailsBeforeStart(t *testing.T) {
	m := hostileManifest
	m.Permissions.Credentials = []tool.CredentialReq{{Name: "token", Kind: "token", Required: true}}
	exe, _ := os.Executable()
	m.Run = &tool.RunSpec{Argv: []string{exe}}
	out, err := testHost(t).RunManifest(context.Background(), m, tool.Task{Targets: oneTarget}, RunOptions{Trusted: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusFailed || out.Err.Class != tool.InvalidInput {
		t.Fatalf("%s %v", out.Status, out.Err)
	}
}

func TestUntrustedAdapterNeedsNetworkEnforcement(t *testing.T) {
	m := hostileManifest
	m.Run = &tool.RunSpec{Argv: []string{"/bin/true"}}
	_, err := testHost(t).RunManifest(context.Background(), m, tool.Task{Targets: oneTarget}, RunOptions{})
	if tool.ClassOf(err) != tool.RefusedByPolicy {
		t.Fatalf("untrusted adapter on the process backend: %v", err)
	}
}

// SECURITY (acceptance): the hostile-adapter matrix is bounded.
func TestHostileAdapters(t *testing.T) {
	cases := []struct {
		mode   string
		status tool.Status
		class  tool.ErrorClass
	}{
		{"garbage", tool.StatusFailed, tool.OutputRejected},
		{"longline", tool.StatusFailed, tool.OutputRejected},
		{"flood", tool.StatusPartial, tool.ResourceExhausted},
		{"noresult", tool.StatusFailed, tool.ToolCrashed},
		{"silent", tool.StatusFailed, tool.Timeout},
		{"liar", tool.StatusFailed, tool.OutputRejected},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			start := time.Now()
			out := hostileRun(t, c.mode, hostileManifest, tool.Task{})
			if out.Status != c.status || out.Err == nil || out.Err.Class != c.class {
				t.Fatalf("status %s err %v (stderr %q)", out.Status, out.Err, out.Stderr)
			}
			if time.Since(start) > 30*time.Second {
				t.Fatalf("took %s", time.Since(start))
			}
			if c.mode == "flood" && (out.Stats.Records != 50 || !out.Stats.Capped || len(out.Report.Findings)+len(out.Report.Assets) != 50) {
				t.Fatalf("flood: %+v", out.Stats)
			}
			if c.mode == "noresult" && len(out.Report.Findings) != 1 {
				t.Fatalf("records before the crash lost: %+v", out.Report.Findings)
			}
		})
	}
}

func TestHostileOutputIsCleaned(t *testing.T) {
	out := hostileRun(t, "dirty", hostileManifest, tool.Task{})
	if out.Status != tool.StatusPartial || out.Err != nil {
		t.Fatalf("status %s err %v", out.Status, out.Err)
	}
	if out.Report.Tool.Name != "hostile" {
		t.Fatalf("tool name claimed: %+v", out.Report.Tool)
	}
	if p, _ := json.Marshal(out.Report.Metadata.Properties["provenance"]); !strings.Contains(string(p), `"tool":"hostile"`) {
		t.Fatalf("provenance forged: %s", p)
	}
	if len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != "eviltitle [31m" {
		t.Fatalf("findings %+v", out.Report.Findings)
	}
	if out.Stats.Quarantined["asset:ip_address"] != 1 || out.Stats.Invalid < 2 {
		t.Fatalf("stats %+v", out.Stats)
	}
	logs := fmt.Sprintf("%+v", out.Logs)
	if strings.Contains(logs, "never-delivered") || strings.Contains(logs, "db_password") {
		t.Fatalf("an undeclared credential was delivered: %s", logs)
	}
	if strings.Contains(logs, "sk-declared-123") || !strings.Contains(logs, "api_key") {
		t.Fatalf("declared credential not delivered or not redacted: %s", logs)
	}
}

func TestResultOKWithoutTargetsIsPartial(t *testing.T) {
	out := hostileRun(t, "claims-ok", hostileManifest, tool.Task{})
	if out.Status != tool.StatusPartial {
		t.Fatalf("status %s", out.Status)
	}
}

func TestArtifactSymlinkEscapeRefused(t *testing.T) {
	out := hostileRun(t, "symlink", hostileManifest, tool.Task{})
	if len(out.Artifacts) != 0 || out.Stats.Invalid < 2 {
		t.Fatalf("artifacts %+v stats %+v", out.Artifacts, out.Stats)
	}
}

func TestCancelStopsTheTool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(500 * time.Millisecond); cancel() }()
	start := time.Now()
	out, err := testHost(t).RunBuiltin(ctx, echoTool, tool.Task{Targets: oneTarget}, RunOptions{Env: map[string]string{"TOOLHOST_SLEEP": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusCanceled || time.Since(start) > 15*time.Second {
		t.Fatalf("status %s err %v after %s", out.Status, out.Err, time.Since(start))
	}
}

func TestExecProfile(t *testing.T) {
	exe, _ := os.Executable()
	m := tool.Manifest{
		Name: "cli-tool", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T0,
		Consumes: []string{"repository"}, Produces: []string{"finding:vulnerability", "finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetNone},
		Config:      json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"mode":{"type":"string","default":"fast"}}}`),
		Run:         &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe, "{{config.mode}}", "{{target.value}}"}, Output: &tool.OutputSpec{Format: tool.OutputSARIF, From: "stdout"}},
	}
	task := tool.Task{Targets: []tool.Target{{Ref: "r", Type: "repository", Value: "github.com/acme/app"}}}
	out, err := testHost(t).RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "sarif-cli"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusOK || len(out.Report.Findings) != 1 {
		t.Fatalf("status %s err %v findings %+v stderr %s", out.Status, out.Err, out.Report.Findings, out.Stderr)
	}
	// A config value that would be a flag never reaches argv.
	task.Config = json.RawMessage(`{"mode":"--output=/etc/x"}`)
	out, _ = testHost(t).RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "sarif-cli"}})
	if out.Status != tool.StatusFailed || out.Err.Class != tool.InvalidInput {
		t.Fatalf("flag injection: %s %v", out.Status, out.Err)
	}
	// CTIS output, exit code mapped, undeclared type quarantined.
	m.Run = &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}, ExitCodes: map[string]string{"2": "ok"}}
	m.Config = nil
	task.Config = nil
	out, _ = testHost(t).RunManifest(context.Background(), m, task, RunOptions{Trusted: true, Env: map[string]string{"TOOLHOST_HOSTILE": "ctis-cli"}})
	if out.Status != tool.StatusPartial || len(out.Report.Findings) != 1 || out.Stats.Quarantined["finding:secret"] != 1 {
		t.Fatalf("ctis exec: %s %v %+v", out.Status, out.Err, out.Stats)
	}
}

func TestToolwireReaderBoundsLines(t *testing.T) {
	r := toolwire.NewReader(strings.NewReader(strings.Repeat("x", toolwire.MaxLine+10) + "\n"))
	if _, err := r.Next(); !errors.Is(err, toolwire.ErrLineTooLong) {
		t.Fatalf("got %v", err)
	}
}

// The adapter protocol schema names exactly the message types both sides
// implement.
func TestAdapterSchemaMatchesWire(t *testing.T) {
	var sch struct {
		Properties struct {
			Type struct {
				Enum []string `json:"enum"`
			} `json:"type"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(tool.AdapterProtocolJSONSchema(), &sch); err != nil {
		t.Fatal(err)
	}
	want := []string{toolwire.TypeHello, toolwire.TypeDescribe, toolwire.TypeValidate, toolwire.TypeRun, toolwire.TypeCancel,
		toolwire.TypeManifest, toolwire.TypeValidation, toolwire.TypeLog, toolwire.TypeProgress, toolwire.TypeRecord,
		toolwire.TypeReportInfo, toolwire.TypeTargetStatus, toolwire.TypeArtifact, toolwire.TypeHeartbeat, toolwire.TypeVerdict, toolwire.TypeResult}
	if strings.Join(sch.Properties.Type.Enum, ",") != strings.Join(want, ",") {
		t.Fatalf("schema types %v, wire types %v", sch.Properties.Type.Enum, want)
	}
}
