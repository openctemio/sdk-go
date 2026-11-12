package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/sdk-go/pkg/sensorproto/v3"
	"github.com/openctemio/sdk-go/pkg/sensorproto/v3/sensorv3connect"
)

// bigV3Platform answers hello and the commands poll over v3 with a message
// larger than the client reads.
type bigV3Platform struct {
	sensorv3connect.UnimplementedSensorServiceHandler
	big []byte
}

func (b *bigV3Platform) Hello(context.Context, *connect.Request[sensorv3.HelloRequest]) (*connect.Response[sensorv3.HelloResponse], error) {
	return connect.NewResponse(&sensorv3.HelloResponse{HelloJson: b.big}), nil
}

func (b *bigV3Platform) ClaimCommands(context.Context, *connect.Request[sensorv3.ClaimCommandsRequest]) (*connect.Response[sensorv3.ClaimCommandsResponse], error) {
	return connect.NewResponse(&sensorv3.ClaimCommandsResponse{CommandsJson: b.big}), nil
}

// An answer over the size limit is ErrResponseTooLarge on the v3 binding as
// on v2 (the v3 client reads at most maxResponseBodyBytes), not a 429 or a
// binding failure. The commands poll goes once more over v2 HTTPS, whose
// answer keeps its first bytes for the poller to name the command.
func TestV3_OversizedAnswerIsResponseTooLarge(t *testing.T) {
	big := []byte(`{"commands":[{"id":"0b7f7a1e-5a3c-4f43-9d0e-2f6c1c8f3a11","payload":"` +
		strings.Repeat("a", maxResponseBodyBytes) + `"}]}`)
	mux := http.NewServeMux()
	mux.Handle(sensorv3connect.NewSensorServiceHandler(&bigV3Platform{big: big}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := &v3Manager{c: &Client{baseURL: srv.URL}, next: http.DefaultTransport}
	svc := m.httpsClient("")
	var v2Polls int
	v2 := sizeTestRT(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == protov2.PathPrefix+protov2.CommandsPath {
			v2Polls++
		}
		return jsonResponse(http.StatusOK, big), nil
	})
	var failures int
	var state atomic.Pointer[v3State]
	state.Store(&v3State{svc: svc, binding: BindingHTTPS})
	rt := &v3RoundTripper{next: v2, state: &state, prefix: protov2.PathPrefix, failed: func(Binding, error) { failures++ }}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+protov2.PathPrefix+protov2.HelloPath, nil)
	_, err := rt.RoundTrip(req)
	var tl *ResponseTooLargeError
	if !errors.Is(err, core.ErrResponseTooLarge) || !errors.As(err, &tl) {
		t.Fatalf("hello over the limit: err = %v, want ErrResponseTooLarge", err)
	}
	if failures != 0 {
		t.Fatalf("an oversized answer counted as %d binding failure(s)", failures)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+protov2.PathPrefix+protov2.CommandsPath+"?limit=1", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("commands poll: %v", err)
	}
	if v2Polls != 1 {
		t.Fatalf("the oversized commands poll went %d times over v2 HTTPS, want once", v2Polls)
	}
}

// The platform's own resource-exhausted answer is a rate limit (429), not
// an oversized answer.
func TestV3_PlatformResourceExhaustedIsARateLimit(t *testing.T) {
	wire := connect.NewWireError(connect.CodeResourceExhausted, errors.New("slow down"))
	resp, err := answer[sensorv3.HelloResponse](nil, wire, nil)
	if err != nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("wire resource-exhausted: resp=%v err=%v, want 429", resp, err)
	}
	local := connect.NewError(connect.CodeResourceExhausted, errors.New("message size 11 is larger than configured max 10"))
	if _, err := answer[sensorv3.HelloResponse](nil, local, nil); !errors.Is(err, core.ErrResponseTooLarge) {
		t.Fatalf("local resource-exhausted: err = %v, want ErrResponseTooLarge", err)
	}
}

type sizeTestRT func(*http.Request) (*http.Response, error)

func (f sizeTestRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
