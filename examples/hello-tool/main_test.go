package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func TestMain(m *testing.M) {
	executor.RunLauncherIfRequested()
	// The fixtures and the fake platform listen on 127.0.0.1; the SDK refuses
	// loopback by default.
	httpsec.AllowLoopback = true
	os.Exit(m.Run())
}

func serve(t *testing.T, header string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if header != "" {
			w.Header().Set("X-Content-Type-Options", header)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func taskFor(url string) tool.Task {
	return tool.Task{Targets: []tool.Target{{Ref: "t1", Type: "http_service", Value: url}}}
}

// In-process, with the rules the runtime applies: a missing header is one
// finding, a present header is none, an unreachable target is a failed
// target and not a finding.
func TestRun(t *testing.T) {
	res := testkit.Run(t, newTool(), taskFor(serve(t, "")))
	res.RequireStatus(t, tool.StatusOK)
	if n := len(res.Report.Findings); n != 1 || res.Report.Findings[0].RuleID != ruleID {
		t.Fatalf("findings = %+v", res.Report.Findings)
	}

	res = testkit.Run(t, newTool(), taskFor(serve(t, "nosniff")))
	res.RequireStatus(t, tool.StatusOK)
	if n := len(res.Report.Findings); n != 0 {
		t.Fatalf("a service with the header has %d findings", n)
	}

	dead := httptest.NewServer(nil)
	url := dead.URL
	dead.Close()
	res = testkit.Run(t, newTool(), taskFor(url))
	if len(res.Report.Findings) != 0 || len(res.Targets) != 1 || res.Targets[0].Class != tool.TargetUnreachable {
		t.Fatalf("unreachable target: findings %d, targets %+v", len(res.Report.Findings), res.Targets)
	}
}

// buildInstalled builds the program and lays it out the way an operator
// installs a tool: tool.yaml, fixtures and bin/hello-tool in one directory
// that only its owner can write.
func buildInstalled(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "bin", "hello-tool"), ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	for _, f := range []string{"tool.yaml", "fixtures/task.json", "fixtures/expect.ctis.json"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "tool.yaml")
}

// The built program passes the adapter-protocol suite a third-party tool
// must pass: handshake, describe equals tool.yaml, nothing but protocol on
// stdout, exit on EOF, cancel, and the self-test fixtures through the
// runtime's own host.
func TestConformance(t *testing.T) {
	conformance.RunToolSuite(t, buildInstalled(t), conformance.ToolSuiteOptions{Timeout: 30 * time.Second})
}

// The report a tool produces is what a sensor sends: it reaches a platform
// that implements the results contract, and is accepted whole.
func TestReportReachesPlatform(t *testing.T) {
	res := testkit.Run(t, newTool(), taskFor(serve(t, "")))
	res.RequireStatus(t, tool.StatusOK)

	fp := conformance.NewFakePlatform(true)
	defer fp.Close()
	c := client.New(&client.Config{BaseURL: fp.URL(), APIKey: fp.APIKey, MaxRetries: 1, Protocol: client.ProtocolV2})
	defer func() { _ = c.Close() }()
	pushed, err := c.PushFindings(context.Background(), res.Report)
	if err != nil {
		t.Fatal(err)
	}
	stored := fp.Reports()[pushed.ReportID]
	if stored == nil || !stored.Committed || stored.Status.Accepted.Findings != 1 {
		t.Fatalf("stored = %+v", stored)
	}
}
