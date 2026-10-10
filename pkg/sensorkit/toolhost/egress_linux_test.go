//go:build linux

package toolhost

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/scopelimit"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY (acceptance, api RFC-060): on a backend that confines the
// network, a tool reaches its target through its forwarder, a host it was
// not given is refused and recorded, and a direct connection has no route.
func TestConfinedTaskReachesOnlyItsTargets(t *testing.T) {
	be, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, ConfineNetwork: true, RequireNetwork: true,
		Limits: executor.Limits{Processes: 256}})
	if err != nil {
		if os.Getenv("OPENCTEM_TEST_REQUIRE_NETNS") == "1" {
			t.Fatalf("network confinement required by the environment, not available: %v", err)
		}
		t.Skipf("network confinement not available here: %v", err)
	}
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
			_ = c.Close()
		}
	}()
	target := ln.Addr().String()
	exe, _ := os.Executable()
	m := tool.Manifest{
		Name: "egress-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"open_port"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetTargets},
		Run:         &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	h := testHost(t)
	h.Backend = be
	task := tool.Task{Targets: []tool.Target{{Ref: "a", Type: "open_port", Value: target}}}
	out, err := h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true,
		Env: map[string]string{"TOOLHOST_HOSTILE": "egress-probe", "TOOLHOST_TARGET": target}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Sandbox.NetworkEnforced {
		t.Fatalf("sandbox %+v", out.Sandbox)
	}
	if len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != "target=200 outside=403 direct=blocked" {
		b, _ := json.Marshal(out.Report.Findings)
		t.Fatalf("probe: %s (status %s, stderr %s)", b, out.Status, out.Stderr)
	}
	var refused, allowed bool
	for _, r := range out.Egress {
		switch {
		case r.Verdict == egress.Refused && r.Host == "outside.example":
			refused = true
		case r.Verdict == egress.Allowed && r.Addr == "127.0.0.1":
			allowed = true
		}
	}
	if !refused || !allowed {
		t.Fatalf("egress records %+v", out.Egress)
	}
	logged := false
	for _, l := range out.Logs {
		logged = logged || strings.Contains(l.Msg, "egress refused outside.example:80")
	}
	if !logged {
		t.Fatalf("the refusal is not in the task log: %+v", out.Logs)
	}
}

// A task's scope: its targets with the addresses admitted for names, its
// vendor hosts, or any public address.
func TestTaskScope(t *testing.T) {
	h := &Host{}
	s := h.taskScope(context.Background(), tool.Manifest{Permissions: tool.Permissions{Network: tool.NetTargets}},
		tool.Task{Targets: []tool.Target{{Value: "192.0.2.5"}, {Value: "198.51.100.0/24"}, {Value: "https://localhost:8443/x"}}})
	if len(s.Prefixes) != 2 || s.Prefixes[0].String() != "192.0.2.5/32" || s.Prefixes[1].String() != "198.51.100.0/24" {
		t.Fatalf("prefixes %v", s.Prefixes)
	}
	if addrs := s.Names["localhost"]; len(addrs) == 0 {
		t.Fatalf("names %v", s.Names)
	}
	s = h.taskScope(context.Background(), tool.Manifest{Permissions: tool.Permissions{Network: tool.NetVendor, VendorHosts: []string{"api.vendor.example:443"}}}, tool.Task{})
	if len(s.Vendor) != 1 || s.Vendor[0] != "api.vendor.example" {
		t.Fatalf("vendor %v", s.Vendor)
	}
	if s = h.taskScope(context.Background(), tool.Manifest{Permissions: tool.Permissions{Network: tool.NetEgressProxy}}, tool.Task{}); !s.AnyPublic {
		t.Fatal("egress-proxy is any public address")
	}
	// SECURITY: a resolver tool gets its targets' names for DNS and no
	// connection at all.
	s = h.taskScope(context.Background(), tool.Manifest{Permissions: tool.Permissions{Network: tool.NetResolver}},
		tool.Task{Targets: []tool.Target{{Value: "localhost"}}})
	if !s.DNSOnly || s.AnyPublic || len(s.Names["localhost"]) == 0 {
		t.Fatalf("resolver scope %+v", s)
	}
	if s = h.taskScope(context.Background(), tool.Manifest{Permissions: tool.Permissions{Network: tool.NetTargets}}, tool.Task{}); s.DNSOnly {
		t.Fatal("targets is not DNS-only")
	}
	if networkClass(tool.NetResolver) != executor.NetworkResolver {
		t.Fatal("resolver network class")
	}
}

// SECURITY (acceptance, scope limits): on a backend that confines the
// network, a task whose target is limited to a port and a path reaches the
// path through its forwarder; a request outside the prefix and a
// connection to another port of the target are refused, recorded and never
// reach the server, whatever the tool asks.
func TestConfinedTaskKeepsToScopeLimits(t *testing.T) {
	be, err := executor.NewProcessBackend(executor.Config{Mode: executor.ModeRequired, ConfineNetwork: true, RequireNetwork: true,
		Limits: executor.Limits{Processes: 256}})
	if err != nil {
		if os.Getenv("OPENCTEM_TEST_REQUIRE_NETNS") == "1" {
			t.Fatalf("network confinement required by the environment, not available: %v", err)
		}
		t.Skipf("network confinement not available here: %v", err)
	}
	var mu sync.Mutex
	var served []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served = append(served, r.URL.EscapedPath())
		mu.Unlock()
	}))
	defer srv.Close()
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	otherPort := other.Listener.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("http://localhost:%d", port)
	exe, _ := os.Executable()
	m := tool.Manifest{
		Name: "limits-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"http_service"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetTargets},
		Run:         &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{exe}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
	}
	h := testHost(t)
	h.Backend = be
	task := tool.Task{Targets: []tool.Target{{Ref: "a", Type: "http_service", Value: target + "/api/"}},
		Limits: []scopelimit.Limit{{Host: "localhost", Ports: strconv.Itoa(port), PathPrefix: "/api"}}}
	out, err := h.RunManifest(context.Background(), m, task, RunOptions{Trusted: true,
		Env: map[string]string{"TOOLHOST_HOSTILE": "limits-probe", "TOOLHOST_TARGET": target, "TOOLHOST_OTHER_PORT": strconv.Itoa(otherPort)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Report.Findings) != 1 || out.Report.Findings[0].Title != "api=200 admin=403 dotdot=403 port=403" {
		b, _ := json.Marshal(out.Report.Findings)
		t.Fatalf("probe: %s (status %s, stderr %s, err %+v)", b, out.Status, out.Stderr, out.Err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(served) != 1 || served[0] != "/api/x" {
		t.Fatalf("the server served %v", served)
	}
	var paths, ports int
	for _, r := range out.Egress {
		switch {
		case r.Verdict == egress.Refused && r.Protocol == egress.ProtocolHTTPPath:
			paths++
		case r.Verdict == egress.Refused && r.Port == otherPort:
			ports++
		}
	}
	if paths != 2 || ports != 1 {
		t.Fatalf("egress records %+v", out.Egress)
	}
}
