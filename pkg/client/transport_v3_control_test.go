package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/sdk-go/pkg/sensorproto/v3"
	"github.com/openctemio/sdk-go/pkg/sensorproto/v3/sensorv3connect"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// beatPlatform answers heartbeats and counts them.
type beatPlatform struct {
	sensorv3connect.UnimplementedSensorServiceHandler
	beats atomic.Int64
}

func (b *beatPlatform) Heartbeat(context.Context, *connect.Request[sensorv3.HeartbeatRequest]) (*connect.Response[sensorv3.HeartbeatResponse], error) {
	b.beats.Add(1)
	return connect.NewResponse(&sensorv3.HeartbeatResponse{HeartbeatJson: []byte(`{}`)}), nil
}

func beatServer(t *testing.T) (*httptest.Server, *beatPlatform, *atomic.Int64) {
	t.Helper()
	p := &beatPlatform{}
	mux := http.NewServeMux()
	mux.Handle(sensorv3connect.NewSensorServiceHandler(p))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	var conns atomic.Int64
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, p, &conns
}

func heartbeat(t *testing.T, rt http.RoundTripper, base string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+protov2.PathPrefix+protov2.HeartbeatPath, http.NoBody)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

// On v3 the heartbeat went through the same service client, and over
// HTTP/2 the same connection, as result uploads: a large slow upload could
// hold it until the sensor looked stale. The control client's requests now
// use the binding's control client (v3State.ctl), and the data client's
// do not.
func TestV3_ControlTrafficUsesItsOwnClient(t *testing.T) {
	data, dataP, _ := beatServer(t)
	ctl, ctlP, _ := beatServer(t)
	svc := (&v3Manager{c: &Client{baseURL: data.URL}, next: data.Client().Transport}).httpsClient("")
	ctlSvc := (&v3Manager{c: &Client{baseURL: ctl.URL}, next: ctl.Client().Transport}).httpsControlClient("")
	var state atomic.Pointer[v3State]
	state.Store(&v3State{svc: svc, ctl: ctlSvc, binding: BindingHTTPS})
	rt := &v3RoundTripper{next: http.DefaultTransport, state: &state, prefix: protov2.PathPrefix}

	heartbeat(t, rt.withNext(http.DefaultTransport), data.URL)
	if ctlP.beats.Load() != 1 || dataP.beats.Load() != 0 {
		t.Fatalf("control heartbeat: %d on the control client, %d on the data client", ctlP.beats.Load(), dataP.beats.Load())
	}
	heartbeat(t, rt, data.URL)
	if dataP.beats.Load() != 1 {
		t.Fatalf("the data client's request went to the control client")
	}
	// A binding without a control client: control traffic shares svc.
	state.Store(&v3State{svc: svc, binding: BindingHTTPS})
	heartbeat(t, rt.withNext(http.DefaultTransport), data.URL)
	if dataP.beats.Load() != 2 {
		t.Fatal("control traffic was lost without a control client")
	}
}

// The HTTPS binding's control client opens a connection of its own.
func TestV3_HTTPSControlClientHasItsOwnConnection(t *testing.T) {
	srv, p, conns := beatServer(t)
	m := &v3Manager{c: &Client{baseURL: srv.URL}, next: srv.Client().Transport}
	var state atomic.Pointer[v3State]
	state.Store(&v3State{svc: m.httpsClient(""), ctl: m.httpsControlClient(""), binding: BindingHTTPS})
	rt := &v3RoundTripper{next: http.DefaultTransport, state: &state, prefix: protov2.PathPrefix}
	for range 3 {
		heartbeat(t, rt, srv.URL)
		heartbeat(t, rt.withNext(http.DefaultTransport), srv.URL)
	}
	if p.beats.Load() != 6 {
		t.Fatalf("%d heartbeats", p.beats.Load())
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("%d connections, want 2 (one for data, one for control)", n)
	}
}

// ownPool clones the transport under the signer and keeps the signer.
func TestOwnPoolKeepsTheSigner(t *testing.T) {
	base := &http.Transport{}
	signed := &sensorsig.Transport{Base: base, MaxBody: 7}
	got, ok := ownPool(signed).(*sensorsig.Transport)
	if !ok || got == signed || got.MaxBody != 7 {
		t.Fatalf("ownPool(signed) = %#v", got)
	}
	if tr, ok := got.Base.(*http.Transport); !ok || tr == base || tr.Proxy == nil {
		t.Fatalf("base %#v not cloned with the platform proxy", got.Base)
	}
	if rt := ownPool(http.NewFileTransport(http.Dir("."))); rt == nil {
		t.Fatal("an unknown transport was dropped")
	}
}
