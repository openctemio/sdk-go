package toolcli

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// pyTool scaffolds a python tool and replaces its run() with body.
func pyTool(t *testing.T, body string) (tool.Manifest, string) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	dir := filepath.Join(t.TempDir(), "tool")
	if code, out := run(t, "init", "--kind", KindPython, "--capability", "probe.http@1", "--name", "pyt", dir); code != ExitOK {
		t.Fatalf("init: %s", out)
	}
	src := filepath.Join(dir, "pyt.py")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i, j := strings.Index(s, "def run(ctx, task):"), strings.Index(s, "if __name__")
	s = s[:i] + body + "\n\n" + s[j:]
	if err := os.WriteFile(src, []byte(s), 0o755); err != nil { //nolint:gosec // a test tool must be executable
		t.Fatal(err)
	}
	m, err := tool.LoadManifestFile(filepath.Join(dir, "tool.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return m, dir
}

// The helper stops a long run when the runtime cancels the task, and says
// so in the result.
func TestPythonHelperCancel(t *testing.T) {
	m, dir := pyTool(t, `def run(ctx, task):
    import time
    while True:
        ctx.check()
        time.sleep(0.05)`)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(time.Second, cancel)
	start := time.Now()
	out, err := (&toolhost.Host{Sensor: "test"}).RunManifest(ctx, m,
		tool.Task{Targets: []tool.Target{{Ref: "a", Type: "http_service", Value: "https://a.example"}}},
		toolhost.RunOptions{Trusted: true, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != tool.StatusCanceled || time.Since(start) > 8*time.Second {
		t.Fatalf("status %s after %v (stderr %s)", out.Status, time.Since(start), out.Stderr)
	}
}

// ctx.connect() goes through the task's forwarder when one is set: the
// target is reached, another host is refused.
func TestPythonHelperConnectsThroughTheForwarder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hello\n"))
			_ = c.Close()
		}
	}()
	fw := egress.New(egress.Scope{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, egress.Limits{})
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fw.Serve(ctx, pl) }()

	m, dir := pyTool(t, `def run(ctx, task):
    host, port = task.targets[0].host_port()
    s = ctx.connect(host, port)
    got = s.recv(16).decode().strip()
    s.close()
    try:
        ctx.connect("outside.example", 80)
        outside = "reached"
    except ConnectionRefusedError:
        outside = "refused"
    ctx.log("info", "probe " + got + " " + outside)
    ctx.done(task.targets[0])`)
	out, err := (&toolhost.Host{Sensor: "test"}).RunManifest(context.Background(), m,
		tool.Task{Targets: []tool.Target{{Ref: "a", Type: "http_service", Value: "http://" + ln.Addr().String()}}},
		toolhost.RunOptions{Trusted: true, Dir: dir, Env: map[string]string{"OPENCTEM_EGRESS_PROXY": "http://" + pl.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range out.Logs {
		found = found || l.Msg == "probe hello refused"
	}
	if !found || out.Status != tool.StatusOK {
		t.Fatalf("logs %+v status %s stderr %s", out.Logs, out.Status, out.Stderr)
	}
	if len(fw.Refusals()) != 1 || fw.Refusals()[0].Host != "outside.example" {
		t.Fatalf("refusals %+v", fw.Refusals())
	}
}
