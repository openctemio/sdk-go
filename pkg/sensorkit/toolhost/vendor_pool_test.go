package toolhost

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// recordingPool is a job's proxy pool: it records the connections the
// forwarder hands it and answers each with an open pipe.
type recordingPool struct {
	mu    sync.Mutex
	dials []string
}

func (p *recordingPool) Dial(ctx context.Context, _, addr string) (net.Conn, error) {
	p.mu.Lock()
	p.dials = append(p.dials, egress.TargetHost(ctx)+"@"+addr)
	p.mu.Unlock()
	c, s := net.Pipe()
	go func() { _, _ = s.Read(make([]byte, 1)); _ = s.Close() }()
	return c, nil
}

func (p *recordingPool) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.dials...)
}

// connect asks the task's forwarder for a tunnel to hostport; it returns
// the status code.
func connect(t *testing.T, proxySock, hostport string) int {
	t.Helper()
	c, err := net.DialTimeout("unix", proxySock, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("CONNECT " + hostport + " HTTP/1.1\r\nHost: " + hostport + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// SECURITY (verification for passive tools): a target-scan task of network
// vendor in a job with a proxy pool reaches its vendor hosts, and the
// hosts of the keys it received, only through the pool; a keyed host whose
// key was not delivered, a target and any other host are refused; DNS for
// a name it may not reach is NXDOMAIN; and a refused connection does not
// mark the task's targets unreached (it never contacts them).
func TestVendorTaskRoutesThroughThePool(t *testing.T) {
	pool := &recordingPool{}
	h := &Host{Backend: statusBackend{st: executor.Status{NetworkEnforced: true}},
		lookupVendor: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}}
	m := secretTool.Manifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("a target-scan tool of network vendor: %v", err)
	}
	task := tool.Task{Targets: []tool.Target{{Ref: "t1", Type: "domain_name", Value: "victim.example"}}}
	if e := h.checkEgress(m, pool); e != nil {
		t.Fatalf("a vendor task in a pooled job refused: %+v", e)
	}
	p := &prepared{m: m, task: task, egress: pool, keyed: []string{"api.shodan.io"}}
	eg, err := h.startEgress(context.Background(), h.backend(), p)
	if err != nil || eg == nil {
		t.Fatalf("forwarder: %v", err)
	}
	defer eg.stop()
	for _, hp := range []string{"crt.sh:443", "api.shodan.io:443"} {
		if code := connect(t, eg.proxyPath(), hp); code != http.StatusOK {
			t.Fatalf("%s: %d", hp, code)
		}
	}
	for _, hp := range []string{"www.virustotal.com:443", "victim.example:443", "attacker.example:443"} {
		if code := connect(t, eg.proxyPath(), hp); code == http.StatusOK {
			t.Fatalf("%s reachable", hp)
		}
	}
	got := strings.Join(pool.got(), " ")
	if got != "crt.sh@1.1.1.1:443 api.shodan.io@1.1.1.1:443" {
		t.Fatalf("pool dials %q", got)
	}
	for _, name := range []string{"attacker.example.", "www.virustotal.com."} {
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		raw, _ := q.Pack()
		resp, err := eg.fw.AnswerDNS(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(resp); err != nil || m.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("DNS for %s: rcode %v %v", name, m.RCode, err)
		}
	}
	out := &Outcome{Status: tool.StatusOK, Targets: []TargetOutcome{{Ref: "t1", State: tool.StateDone}}}
	eg.finish(out, task.Targets)
	if out.Targets[0].State != tool.StateDone || out.Status != tool.StatusOK {
		t.Fatalf("a refused vendor connection marked the target: %+v", out.Targets[0])
	}
}
