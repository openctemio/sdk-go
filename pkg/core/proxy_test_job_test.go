package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
)

type fakePreparer struct {
	cfg *upstream.Config
	err error
}

func (f *fakePreparer) PrepareEgress(_ context.Context, _ string, cfg *upstream.Config) (*upstream.Pool, error) {
	f.cfg = cfg
	if f.err != nil {
		return nil, f.err
	}
	return upstream.New(*cfg, upstream.Options{Key: "c1"})
}

func proxyTestCommand(t *testing.T, p ProxyTestPayload) *Command {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &Command{ID: "c1", Type: CommandTypeProxyTest, Payload: b}
}

func TestProxyTestExecutorRefusesWhatItCannotRun(t *testing.T) {
	x := &ProxyTestExecutor{Egress: &fakePreparer{}}
	if _, err := x.Execute(context.Background(), &Command{ID: "c1", Payload: json.RawMessage(`{`)}); err == nil {
		t.Fatal("unreadable payload")
	}
	if _, err := x.Execute(context.Background(), proxyTestCommand(t, ProxyTestPayload{})); err == nil {
		t.Fatal("no endpoint")
	}
	veto := &fakePreparer{err: egressRefusal(RefusalEgressRefusedByHost, "no")}
	x = &ProxyTestExecutor{Egress: veto}
	_, err := x.Execute(context.Background(), proxyTestCommand(t, ProxyTestPayload{Egress: testEgress(false)}))
	if RefusalOf(err) == nil {
		t.Fatalf("the local veto must fail the command as a refusal: %v", err)
	}
	if _, err := (&ProxyTestExecutor{}).Execute(context.Background(), proxyTestCommand(t, ProxyTestPayload{Egress: testEgress(false)})); err == nil {
		t.Fatal("no preparer")
	}
}

// An echo address a proxy must never be asked to reach (loopback) makes
// every endpoint's result a failure without a single tunnel; the command
// itself completes, with the result under the metadata key.
func TestProxyTestExecutorCompletesWithPerEndpointResults(t *testing.T) {
	prep := &fakePreparer{}
	x := &ProxyTestExecutor{Egress: prep}
	res, err := x.Execute(context.Background(), proxyTestCommand(t, ProxyTestPayload{
		Egress: testEgress(false), Echo: ProxyTestEcho{URL: "https://127.0.0.1/echo?t=x", AltPort: 80}}))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := res.Metadata[MetadataKeyProxyTest].(ProxyTestResult)
	if !ok || r.PoolID != "pool-1" || len(r.Endpoints) != 2 {
		t.Fatalf("result %+v", res.Metadata)
	}
	for _, e := range r.Endpoints {
		if e.OK || e.Class != upstream.ClassEchoFailed {
			t.Fatalf("endpoint %+v", e)
		}
	}
}

// DialContextVia checks the policy first, then hands the dial function the
// checked ip:port, never the name.
func TestDialContextViaChecksThenDialsThroughTheGivenDialer(t *testing.T) {
	var lp *LocalPolicy
	var got []string
	dial := lp.DialContextVia(func(_ context.Context, network, addr string) (net.Conn, error) {
		got = append(got, addr)
		return nil, errors.New("stop")
	})
	// A blocked address never reaches the dialer.
	if _, err := dial(context.Background(), "tcp", "127.0.0.1:443"); err == nil || len(got) != 0 {
		t.Fatalf("loopback reached the dialer: %v %v", err, got)
	}
	ip := netip.MustParseAddr("93.184.216.34")
	if _, err := dial(context.Background(), "tcp", net.JoinHostPort(ip.String(), "443")); err == nil || len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("dials %v err %v", got, err)
	}
}
