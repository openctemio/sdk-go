//go:build linux

package toolhost

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// privateAddr is an address of this host a proxy endpoint may have (not
// loopback, not link-local), or an invalid one.
func privateAddr() netip.Addr {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !upstream.Denied(p.Addr()) {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

// SECURITY (acceptance): on a backend that confines the network, a pooled
// task reaches its target only through the pool's proxy (with the pool's
// credentials, which the tool never sees: not in its environment, not in
// its arguments), and the forwarder records the endpoint.
func TestConfinedTaskReachesItsTargetThroughThePool(t *testing.T) {
	be, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, ConfineNetwork: true, RequireNetwork: true,
		Limits: executor.Limits{Processes: 256}})
	if err != nil {
		if os.Getenv("OPENCTEM_TEST_REQUIRE_NETNS") == "1" {
			t.Fatalf("network confinement required by the environment, not available: %v", err)
		}
		t.Skipf("network confinement not available here: %v", err)
	}
	host := privateAddr()
	if !host.IsValid() {
		t.Skip("no non-loopback address for a test proxy")
	}
	const user, pass = "pool-user-7", "pool-pass-9-secret"
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	proxy, err := net.Listen("tcp", netip.AddrPortFrom(host, 0).String())
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	defer proxy.Close()
	var tunnels atomic.Int64
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if req.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) {
					_, _ = io.WriteString(c, "HTTP/1.1 407 Auth\r\n\r\n")
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				_ = up.Close()
				tunnels.Add(1)
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
			}()
		}
	}()
	pport := proxy.Addr().(*net.TCPAddr).Port
	pool, err := upstream.New(upstream.Config{Mode: upstream.ModePool, PoolID: "p1", AppliesTo: upstream.AppliesAll,
		Endpoints: []upstream.Endpoint{{ID: "ep-1", Scheme: upstream.SchemeHTTP, Host: host.String(), Port: pport, Weight: 1, Auth: true}}},
		upstream.Options{Key: "job-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SetCredentials([]upstream.Credential{{EndpointID: "ep-1", Username: user, Password: pass}}); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	m := tool.Manifest{
		Name: "pool-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"open_port"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetTargets},
		Run:         &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	h := testHost(t)
	h.Backend = be
	task := tool.Task{Targets: []tool.Target{{Ref: "a", Type: "open_port", Value: target.Addr().String()}}, Egress: pool}
	out, err := h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true,
		Env: map[string]string{"TOOLHOST_HOSTILE": "egress-pool-probe", "TOOLHOST_TARGET": target.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Report == nil || len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != "target=200" {
		t.Fatalf("probe: %+v (status %s, stderr %s)", out.Report, out.Status, out.Stderr)
	}
	if tunnels.Load() != 1 {
		t.Fatalf("%d tunnels through the pool", tunnels.Load())
	}
	seen := out.Report.Findings[0].Description
	if seen == "" || strings.Contains(seen, user) || strings.Contains(seen, pass) {
		t.Fatalf("the tool saw the pool's credentials (or nothing was reported): %q", seen)
	}
	var recorded bool
	for _, r := range out.Egress {
		recorded = recorded || r.Endpoint == "ep-1"
		if strings.Contains(r.Reason, pass) {
			t.Fatal("credential in a record")
		}
	}
	if !recorded {
		t.Fatalf("no record names the endpoint: %+v", out.Egress)
	}
	if r := pool.Report(); len(r.Endpoints) != 1 || r.Endpoints[0].OK != 1 {
		t.Fatalf("pool report %+v", r)
	}
}
