package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/webscope"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// fakeToolEnv makes the test binary act as an exec-profile tool.
const fakeToolEnv = "CONFORMANCE_FAKE_TOOL"

var awsKeyRE = regexp.MustCompile(`AKIA[A-Z2-7]{16}`)

// fakeTool is an exec-profile tool that writes CTIS on stdout:
//
//	ports  <host> <ports>  connects to each port, reports the open ones
//	dial-b <host> <ports>  also connects to $CONFORMANCE_B (out of scope)
//	ports-bad ...          as ports, without the transport protocol
//	secrets <dir>          reports AWS keys in <dir>/config.py, masked
//	                       ($CONFORMANCE_LEAK=1 also puts the raw key in the description)
//	probe <url>            GETs the URL and reports status and title
//	crawl <url> <scope>    follows links from the URL, keeping to the web
//	                       scope file ($CONFORMANCE_IGNORE_SCOPE=1: ignores it)
func fakeTool(mode string, args []string) int {
	report := map[string]any{"version": "1.6", "metadata": map[string]any{"timestamp": "2026-01-01T00:00:00Z"}}
	var assets, findings []map[string]any
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch mode {
	case "ports", "dial-b", "ports-bad":
		if mode == "dial-b" {
			if c, err := net.DialTimeout("tcp", os.Getenv("CONFORMANCE_B"), time.Second); err == nil {
				_ = c.Close()
			}
		}
		host := arg(0)
		for _, p := range strings.Split(arg(1), ",") {
			if p == "" {
				continue
			}
			c, err := net.DialTimeout("tcp", net.JoinHostPort(host, p), 500*time.Millisecond)
			if err != nil {
				continue
			}
			_ = c.Close()
			var port int
			_, _ = fmt.Sscan(p, &port)
			props := map[string]any{"host": host, "port": port, "protocol": "tcp"}
			if mode == "ports-bad" {
				delete(props, "protocol")
			}
			assets = append(assets, map[string]any{"type": "open_port", "value": net.JoinHostPort(host, p), "properties": props})
		}
	case "secrets":
		b, _ := os.ReadFile(filepath.Join(arg(0), "config.py"))
		for _, k := range awsKeyRE.FindAllString(string(b), -1) {
			f := map[string]any{"type": "secret", "rule_id": "aws-access-key", "title": "AWS access key", "severity": "high",
				"location": map[string]any{"path": "config.py", "start_line": 1},
				"secret":   map[string]any{"secret_type": "aws_access_key", "masked_value": k[:4] + "****"}}
			if os.Getenv("CONFORMANCE_LEAK") == "1" {
				f["description"] = "found " + k
			}
			findings = append(findings, f)
		}
	case "probe":
		resp, err := http.Get(arg(0)) //nolint:gosec,noctx // the fixture URL the suite gave
		if err != nil {
			return 1
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		title := ""
		if m := regexp.MustCompile(`<title>([^<]*)</title>`).FindSubmatch(body); m != nil {
			title = string(m[1])
		}
		assets = append(assets, map[string]any{"type": "http_service", "value": arg(0),
			"properties": map[string]any{"status_code": resp.StatusCode, "title": title}})
	case "crawl":
		assets = fakeCrawl(arg(0), arg(1))
	case "evidence":
		// A finding with an HTTP exchange; $CONFORMANCE_UNMARKED=1 leaves the
		// Authorization value unmarked.
		ex := map[string]any{"kind": "http_exchange", "version": 1, "http": map[string]any{
			"request":  map[string]any{"method": "GET", "url": arg(0) + "/.env", "headers": []any{map[string]any{"name": "Authorization", "value": "Bearer conformance"}}},
			"response": map[string]any{"status": 200, "body": "APP_ENV=production"}}}
		if os.Getenv("CONFORMANCE_UNMARKED") != "1" {
			ex["sensitive"] = []any{map[string]any{"pointer": "/http/request/headers/0/value", "kind": "authorization"}}
		}
		findings = append(findings, map[string]any{"type": "misconfiguration", "rule_id": "dotenv", "title": ".env exposed", "asset_value": arg(0),
			"severity": "high", "evidence_items": []any{ex}})
	default:
		return 2
	}
	if assets != nil {
		report["assets"] = assets
	}
	if findings != nil {
		report["findings"] = findings
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	return 0
}

// fakeManifest writes a tool directory for a fakeTool mode.
func fakeManifest(t *testing.T, body string, files map[string]string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	doc := "apiVersion: openctem.io/tool/v1\nname: fake-tool\nversion: 1.0.0\nclass: target-scan\n" +
		strings.ReplaceAll(body, "EXE", fmt.Sprintf("%q", exe))
	if err := os.WriteFile(filepath.Join(dir, "tool.yaml"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "tool.yaml")
}

const portsTool = `tier: T1
implements: [{capability: scan.ports@1, params: {ports: {key: ports}}, output_shape: open_port_assets}]
consumes: [ip_address, domain]
produces: [asset:open_port]
config: {type: object, additionalProperties: false, properties: {ports: {type: string, maxLength: 2048}}}
permissions: {network: targets}
run: {profile: exec, argv: [EXE, "{{target.value}}", "{{config.ports}}"], output: {format: ctis, from: stdout}}
`

func runContract(path string, opts ContractOptions) *suiteRecorder {
	r := &suiteRecorder{}
	func() {
		defer func() { _ = recover() }()
		RunContractSuite(r, path, opts)
	}()
	return r
}

func hasErr(r *suiteRecorder, want string) bool {
	for _, e := range r.errs {
		if strings.Contains(e, want) {
			return true
		}
	}
	return false
}

// freeAddr is a free TCP address on host.
func freeAddr(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// A port scanner that reports exactly the open ports and connects only to
// its target passes the scan.ports@1 suite and the scope check.
func TestContractSuite_PortScanner(t *testing.T) {
	b := freeAddr(t, "127.0.0.2")
	r := runContract(fakeManifest(t, portsTool, nil), ContractOptions{Capability: true, Scope: true, ScopeListenAddr: b,
		Env: map[string]string{fakeToolEnv: "ports"}, Timeout: 20 * time.Second})
	if len(r.errs) > 0 {
		t.Fatalf("errors: %v", r.errs)
	}
}

// SECURITY (acceptance): a tool that connects to an address it was not
// given fails the scope check.
func TestContractSuite_ScopeCatchesAnOutOfScopeConnection(t *testing.T) {
	b := freeAddr(t, "127.0.0.2")
	r := runContract(fakeManifest(t, portsTool, nil), ContractOptions{Scope: true, ScopeListenAddr: b,
		Env: map[string]string{fakeToolEnv: "dial-b", "CONFORMANCE_B": b}, Timeout: 20 * time.Second})
	if !hasErr(r, "Scope: the tool connected") {
		t.Fatalf("errors: %v", r.errs)
	}
}

// A port scanner that misses the transport protocol fails the capability
// suite and, through its fixture, the fixture contract.
func TestContractSuite_RequiredPaths(t *testing.T) {
	body := portsTool + "selftest: [{name: one, task: t.json, expect: e.json}]\n"
	task := `{"targets":[{"ref":"t1","type":"ip_address","value":"127.0.0.1"}],"config":{"ports":"` + strings.Split(freeAddrListening(t), ":")[1] + `"}}`
	r := runContract(fakeManifest(t, body, map[string]string{"t.json": task}), ContractOptions{Capability: true,
		Env: map[string]string{fakeToolEnv: "ports-bad"}, Timeout: 20 * time.Second})
	if !hasErr(r, "FixtureContract/one/scan.ports@1") || !hasErr(r, "properties.protocol") {
		t.Fatalf("errors: %v", r.errs)
	}
}

// freeAddrListening is a loopback address that accepts connections for
// the rest of the test.
func freeAddrListening(t *testing.T) string {
	t.Helper()
	l, err := listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.close)
	return l.ln.Addr().String()
}

const secretsTool = `tier: T0
implements: [{capability: secrets.code@1}]
consumes: [repository]
produces: [finding:secret]
permissions: {network: none}
run: {profile: exec, argv: [EXE, "{{target.value}}"], output: {format: ctis, from: stdout}}
`

// SECURITY (acceptance): a secret scanner that masks the value passes; one
// that leaks the raw value anywhere in its output fails.
func TestContractSuite_Secrets(t *testing.T) {
	path := fakeManifest(t, secretsTool, nil)
	if r := runContract(path, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "secrets"}}); len(r.errs) > 0 {
		t.Fatalf("masked: %v", r.errs)
	}
	r := runContract(path, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "secrets", "CONFORMANCE_LEAK": "1"}})
	if !hasErr(r, "a raw secret value reached the report") {
		t.Fatalf("leak not caught: %v", r.errs)
	}
}

func TestContractSuite_ProbeHTTP(t *testing.T) {
	body := `tier: T1
implements: [{capability: probe.http@1}]
consumes: [http_service]
produces: [asset:http_service]
permissions: {network: targets}
run: {profile: exec, argv: [EXE, "{{target.value}}"], output: {format: ctis, from: stdout}}
`
	r := runContract(fakeManifest(t, body, nil), ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "probe"}})
	if len(r.errs) > 0 {
		t.Fatalf("errors: %v", r.errs)
	}
}

// A tool that finds nothing fails the suites of the capabilities that have
// a fixture with something to find; capabilities without one only log.
func TestContractSuite_FindsNothing(t *testing.T) {
	body := `tier: T1
implements: [{capability: vuln.templates@1}, {capability: sast.code@1}, {capability: sca.deps@1}, {capability: discover.subdomains@1}]
consumes: [http_service, repository, domain]
produces: [finding:vulnerability, asset:subdomain]
permissions: {network: targets}
run: {profile: exec, argv: [EXE, "{{target.value}}"], output: {format: ctis, from: stdout}}
`
	r := runContract(fakeManifest(t, body, nil), ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "secrets"}})
	for _, want := range []string{"Capability/vuln.templates@1: found nothing", "Capability/sast.code@1: found nothing", "Capability/sca.deps@1: found no dependency"} {
		if !hasErr(r, want) {
			t.Errorf("missing %q in %v", want, r.errs)
		}
	}
	if hasErr(r, "discover.subdomains") {
		t.Errorf("a capability without an active suite failed: %v", r.errs)
	}
	// A port scanner that cannot be told its ports fails its suite.
	noPorts := strings.Replace(portsTool, "params: {ports: {key: ports}}, ", "", 1)
	if r := runContract(fakeManifest(t, noPorts, nil), ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "ports"}}); !hasErr(r, "does not take the standard param ports") {
		t.Errorf("errors: %v", r.errs)
	}
}

func TestContractSuite_ManifestErrors(t *testing.T) {
	if r := runContract("missing/tool.yaml", ContractOptions{}); !hasErr(r, "Manifest:") {
		t.Fatalf("errors: %v", r.errs)
	}
}

func TestLintDescriptor(t *testing.T) {
	m := tool.Manifest{Name: "x", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1, Capabilities: []string{"portscan"}, Retest: true,
		Implements: []tool.Implementation{{Capability: "scan.ports@1"}},
		Run:        &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{"x"}}}
	var got []string
	for _, l := range LintDescriptor(m) {
		got = append(got, l.Path)
		if l.String() == "" {
			t.Fatal("empty")
		}
	}
	for _, want := range []string{"/capabilities", "/retest", "/selftest", "/presentation/display_name", "/engine/version_probe", "/safety/rate_param"} {
		if !strings.Contains(strings.Join(got, " "), want) {
			t.Errorf("lint misses %s: %v", want, got)
		}
	}
	m.Implements = nil
	if !strings.Contains(fmt.Sprint(LintDescriptor(m)), "/implements") {
		t.Error("no implements not linted")
	}
}

func TestFuzzOutput(t *testing.T) {
	r := &suiteRecorder{}
	m := tool.Manifest{Name: "f", Run: &tool.RunSpec{Profile: tool.ProfileExec, Output: &tool.OutputSpec{Format: tool.OutputSARIF}}}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "fuzz"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "fuzz", "seed.sarif"), []byte(`{"version":"2.1.0","runs":[]}`), 0o600)
	FuzzOutput(r, m, dir, 300*time.Millisecond)
	for _, f := range []string{tool.OutputCTIS, tool.OutputJSONLCTIS, "nuclei"} {
		m.Run.Output.Format = f
		FuzzOutput(r, m, dir, 200*time.Millisecond)
	}
	if len(r.errs) > 0 {
		t.Fatalf("errors: %v", r.errs)
	}
	m.Run.Output.Format = "unknown-format"
	FuzzOutput(r, m, dir, time.Millisecond)
	FuzzOutput(r, tool.Manifest{Name: "adapter"}, dir, time.Millisecond)
	// The checks themselves.
	if msg := fuzzOne(func(context.Context, []byte) ([]byte, int, error) { panic("boom") }, nil); !strings.Contains(msg, "panicked") {
		t.Fatal(msg)
	}
	n := 0
	if msg := fuzzOne(func(context.Context, []byte) ([]byte, int, error) { n++; return []byte{byte(n)}, 1, nil }, nil); !strings.Contains(msg, "differ") {
		t.Fatal(msg)
	}
	if msg := fuzzOne(func(context.Context, []byte) ([]byte, int, error) { return nil, fuzzMaxRecords + 1, nil }, nil); !strings.Contains(msg, "above the cap") {
		t.Fatal(msg)
	}
}

var linkRE = regexp.MustCompile(`(?:href|action)="([^"]+)"|fetch\("([^"]+)"\)`)

// fakeCrawl follows the links of the start page and its children (depth
// 2), checking each against the web scope file unless told to ignore it,
// and reports every page it fetched as a discovered_url.
func fakeCrawl(start, scopeFile string) []map[string]any {
	var scope *webscope.Scope
	if b, err := os.ReadFile(scopeFile); err == nil {
		_ = json.Unmarshal(b, &scope)
	}
	if os.Getenv("CONFORMANCE_IGNORE_SCOPE") == "1" {
		scope = nil
	}
	base, err := url.Parse(start)
	if err != nil {
		return nil
	}
	var assets []map[string]any
	seen := map[string]bool{}
	queue := []*url.URL{base}
	for depth := 0; depth < 3 && len(queue) > 0; depth++ {
		var next []*url.URL
		for _, u := range queue {
			if seen[u.String()] {
				continue
			}
			seen[u.String()] = true
			if scope.Allows("GET", u, []string{base.Hostname()}) != nil {
				continue
			}
			client := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return scope.Allows("GET", req.URL, []string{base.Hostname()})
			}}
			resp, err := client.Get(u.String()) //nolint:noctx // the fixture
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			assets = append(assets, map[string]any{"type": "discovered_url", "value": u.String(),
				"properties": map[string]any{"host": u.Hostname()}})
			for _, m := range linkRE.FindAllStringSubmatch(string(body), -1) {
				ref := m[1] + m[2]
				if l, err := u.Parse(ref); err == nil {
					next = append(next, l)
				}
			}
		}
		queue = next
	}
	return assets
}

const crawlTool = `tier: T1
implements: [{capability: crawl.web@1}]
consumes: [http_service]
produces: [asset:discovered_url]
permissions: {network: targets}
FEATURES
run: {profile: exec, argv: [EXE, "{{target.value}}", "{{task.web_scope_file}}"], output: {format: ctis, from: stdout}}
`

// SECURITY (acceptance): a crawler that keeps to the web scope passes the
// crawl.web suite; one that requests a denied path fails it, and one that
// does not declare features.web_scope fails it without running.
func TestContractSuite_WebScope(t *testing.T) {
	declared := fakeManifest(t, strings.Replace(crawlTool, "FEATURES", "features: {web_scope: true}", 1), nil)
	if r := runContract(declared, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "crawl"}}); len(r.errs) > 0 {
		t.Fatalf("a crawler that keeps to the scope: %v", r.errs)
	}
	r := runContract(declared, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "crawl", "CONFORMANCE_IGNORE_SCOPE": "1"}})
	if !hasErr(r, "which the web scope denies") {
		t.Fatalf("a crawler that ignores the scope passed: %v", r.errs)
	}
	undeclared := fakeManifest(t, strings.Replace(crawlTool, "FEATURES", "", 1), nil)
	if r := runContract(undeclared, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "crawl"}}); !hasErr(r, "must declare features.web_scope") {
		t.Fatalf("an undeclared crawler passed: %v", r.errs)
	}
}

// SECURITY (acceptance): a tool whose evidence leaves an Authorization
// value unmarked fails; one that marks it passes.
func TestContractSuite_EvidenceMarked(t *testing.T) {
	body := `tier: T1
implements: [{capability: vuln.templates@1}]
consumes: [http_service]
produces: [finding:misconfiguration]
permissions: {network: targets}
run: {profile: exec, argv: [EXE, "{{target.value}}"], output: {format: ctis, from: stdout}}
`
	path := fakeManifest(t, body, nil)
	if r := runContract(path, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "evidence"}}); len(r.errs) > 0 {
		t.Fatalf("marked: %v", r.errs)
	}
	r := runContract(path, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "evidence", "CONFORMANCE_UNMARKED": "1"}})
	if !hasErr(r, "Authorization header value is not marked sensitive") {
		t.Fatalf("unmarked evidence passed: %v", r.errs)
	}
}
