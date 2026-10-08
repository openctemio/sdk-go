//go:build linux

package executor

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// newConfinedBackend is a required-mode backend that confines the
// network, or skips the test where user namespaces are not available (a
// host with AppArmor's user namespace restriction, a container under the
// default seccomp profile).
func newConfinedBackend(t *testing.T, deny ...string) *ProcessBackend {
	t.Helper()
	b, err := NewProcessBackend(Config{Mode: ModeRequired, ReadDeny: deny, WorkRoot: t.TempDir(),
		Limits: Limits{Processes: 64}, ConfineNetwork: true})
	if err != nil {
		if os.Getenv("OPENCTEM_TEST_REQUIRE_NETNS") == "1" {
			t.Fatalf("network confinement required by the environment, not available: %v", err)
		}
		t.Skipf("network confinement not available here: %v", err)
	}
	if !b.Status().NetworkEnforced {
		t.Fatalf("a confined backend must report NetworkEnforced: %+v", b.Status())
	}
	return b
}

// fakeForwarder serves a unix socket in dir: each connection gets
// "world\n" after its first line (a stand-in for pkg/sensorkit/egress).
func fakeForwarder(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "proxy.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := bufio.NewReader(c).ReadString('\n'); err == nil {
					_, _ = io.WriteString(c, "world\n")
				}
			}()
		}
	}()
	return path
}

// fakeDNS answers every query on a unix stream socket (RFC 1035 framing)
// with 192.0.2.99.
func fakeDNS(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "dns.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					var m dnsmessage.Message
					if m.Unpack(q) != nil || len(m.Questions) == 0 {
						return
					}
					m.Response = true
					if m.Questions[0].Type == dnsmessage.TypeA {
						m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
							Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 99}}}}
					}
					out, _ := m.Pack()
					binary.BigEndian.PutUint16(l[:], uint16(len(out))) //nolint:gosec // a small test answer
					_, _ = c.Write(append(l[:], out...))
				}
			}()
		}
	}()
	return path
}

// SECURITY (acceptance, RFC-060): a confined task has no route out. Not to
// the internet, not to the sensor's own loopback services.
func TestConfinedTaskHasNoRoute(t *testing.T) {
	b := newConfinedBackend(t)
	for _, addr := range []string{"192.0.2.1:80", "169.254.169.254:80", "[2001:db8::1]:443"} {
		if out, _ := runTool(t, b, TaskSpec{ID: "dial"}, "dial", addr); !strings.HasPrefix(out, "ERR") || !strings.Contains(out, "unreachable") {
			t.Errorf("dial %s: %q, want network unreachable", addr, out)
		}
	}
	// The host's loopback is another namespace's: a service the sensor
	// listens on there is not reachable.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if out, _ := runTool(t, b, TaskSpec{ID: "dial-host-lo"}, "dial", ln.Addr().String()); !strings.HasPrefix(out, "ERR") {
		t.Errorf("reached the host loopback: %q", out)
	}
}

// A confined task's only way out is its forwarder: the relay carries its
// proxy connections and DNS queries to the forwarder's sockets, and the
// proxy variables name the relay whatever the caller set.
func TestConfinedTaskReachesItsForwarder(t *testing.T) {
	b := newConfinedBackend(t)
	dir := t.TempDir()
	spec := TaskSpec{ID: "relay", EgressProxy: fakeForwarder(t, dir), EgressDNS: fakeDNS(t, dir),
		SetEnv: map[string]string{"HTTPS_PROXY": "http://elsewhere:3128", "NO_PROXY": "*"}}
	if out, _ := runTool(t, b, spec, "relay"); out != "OK world" {
		t.Fatalf("relay: %q", out)
	}
	if out, _ := runTool(t, b, spec, "resolve", "target.example"); out != "OK 192.0.2.99" {
		t.Fatalf("resolve through the relay: %q", out)
	}
	if out, _ := runTool(t, b, spec, "proxyenv"); out != "http://"+RelayProxyAddr+" true" {
		t.Fatalf("proxy variables: %q", out)
	}
	// Without forwarder sockets a confined task has no network at all.
	if out, _ := runTool(t, b, TaskSpec{ID: "none"}, "relay"); !strings.HasPrefix(out, "ERR") {
		t.Fatalf("no forwarder, yet the relay answered: %q", out)
	}
}

// SECURITY: the tool runs as root of its user namespace with no
// capabilities, and the rest of the sandbox still applies to it.
func TestConfinedToolKeepsTheSandbox(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "sensor-key")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := newConfinedBackend(t, secret)
	if out, _ := runTool(t, b, TaskSpec{ID: "caps"}, "capeff"); out != "0000000000000000 0000000000000000" {
		t.Errorf("capabilities: %q, want none", out)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "bind"}, "bindlow"); !strings.HasPrefix(out, "ERR") {
		t.Errorf("bound a privileged port: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "read"}, "read", secret); !strings.HasPrefix(out, "ERR") {
		t.Errorf("read a protected file: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "unshare"}, "unshare"); !strings.HasPrefix(out, "ERR") {
		t.Errorf("made a namespace: %q", out)
	}
	if out, _ := runTool(t, b, TaskSpec{ID: "write"}, "write", "own.txt"); out != "OK" {
		t.Errorf("own directory: %q", out)
	}
}
