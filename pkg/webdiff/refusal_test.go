package webdiff

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/webscope"
)

// scopeTransport refuses every request after allow the way the sensor
// client's own web scope does: an error wrapping webscope.ErrOutOfScope.
type scopeTransport struct {
	next  http.RoundTripper
	allow int64
	msg   string
	n     atomic.Int64
	sent  atomic.Int64
}

func (s *scopeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.n.Add(1)
	if s.n.Load() > s.allow {
		return nil, fmt.Errorf("%w: %s", webscope.ErrOutOfScope, s.msg)
	}
	s.sent.Add(1)
	return s.next.RoundTrip(r)
}

// The client's own request cap is a budget stop: the request is not retried
// and the origin is not reported blocked.
func TestClientRequestCapIsBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(http.NotFound))
	defer srv.Close()
	tr := &scopeTransport{next: http.DefaultTransport, allow: 4, msg: "request cap of 4 requests per host reached"}
	p, err := New(&http.Client{Transport: tr}, srv.URL, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	runOn(t, p, []string{"/a", "/b", "/c", "/d"})
	if p.Stopped() != GapBudget {
		t.Fatalf("stopped %q, want %q", p.Stopped(), GapBudget)
	}
	if got := tr.n.Load(); got != 5 {
		t.Fatalf("%d requests reached the client, want the 4 allowed and 1 refused (no retry)", got)
	}
}

// Any other refusal of the client's scope is a filtered candidate: counted
// as scope_filtered, never retried, never blocked.
func TestClientScopeRefusalIsFiltered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(http.NotFound))
	defer srv.Close()
	base := http.DefaultTransport
	var refused atomic.Int64
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/private" {
			refused.Add(1)
			return nil, fmt.Errorf("%w: path /private is denied", webscope.ErrOutOfScope)
		}
		return base.RoundTrip(r)
	})
	p, err := New(&http.Client{Transport: rt}, srv.URL, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	runOn(t, p, []string{"/private", "/public"})
	if p.Stopped() != "" || p.Gaps()[GapScopeFiltered] != 1 || refused.Load() != 1 {
		t.Fatalf("stopped %q gaps %v refused %d", p.Stopped(), p.Gaps(), refused.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A rate above MaxRate is lowered to it.
func TestRateBounded(t *testing.T) {
	if got := (Options{Rate: 1e9}).withDefaults().Rate; got != MaxRate {
		t.Fatalf("rate %v, want %d", got, MaxRate)
	}
	if got := (Options{}).withDefaults().Rate; got != DefaultRate {
		t.Fatalf("rate %v, want %d", got, DefaultRate)
	}
}

// An origin an edge network fronts is held to FrontedRate; a direct one
// keeps its rate.
func TestFrontedOriginIsSlowed(t *testing.T) {
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "8a-FRA")
		http.NotFound(w, r)
	}))
	defer front.Close()
	o := fastOptions()
	p, err := New(testClient(nil), front.URL, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Canary(context.Background()); err != nil && !errors.Is(err, ErrStopped) {
		t.Fatal(err)
	}
	if got := float64(p.limiter.Limit()); got != FrontedRate {
		t.Fatalf("fronted origin limit %v, want %d", got, FrontedRate)
	}
	direct := httptest.NewServer(http.HandlerFunc(http.NotFound))
	defer direct.Close()
	p2, _ := New(testClient(nil), direct.URL, o)
	if _, err := p2.Canary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := float64(p2.limiter.Limit()); got != MaxRate {
		t.Fatalf("direct origin limit %v, want %d", got, MaxRate)
	}
}
