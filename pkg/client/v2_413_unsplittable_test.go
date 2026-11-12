package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/outbox"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// A single finding larger than an ingress's body limit was re-sent in a
// tight loop, with no back-off, until the caller's deadline: splitting
// cannot make it smaller and the give-up rule only knew 1 KiB requests. It
// is now refused once the split stops making progress, with an error and a
// log line that say why, and the outbox keeps it as a dead letter.
func TestPushResultsV2_UnsplittableFindingIsNotRetriedInALoop(t *testing.T) {
	var puts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
			w.Header().Set("Content-Type", protov2.MediaTypeJSON)
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2,
				Features: []string{protov2.FeatureResults}, MediaTypes: []string{protov2.MediaTypeCTIS}})
			return
		}
		puts.Add(1)
		w.WriteHeader(http.StatusRequestEntityTooLarge) // a proxy's body limit
	}))
	defer srv.Close()

	c := New(&Config{BaseURL: srv.URL, APIKey: "k"})
	r := ctis.NewReport()
	r.Tool = &ctis.Tool{Name: "nuclei"}
	r.Findings = []ctis.Finding{{Title: "big", Description: strings.Repeat("A", 200_000)}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var logs []string
	_, err := c.PushResultsV2(ctx, r, &V2PushOptions{Logf: func(f string, a ...any) { logs = append(logs, f) }})
	if ctx.Err() != nil {
		t.Fatalf("still looping at the deadline after %d PUTs: %v", puts.Load(), err)
	}
	if !errors.Is(err, errUnsplittable) {
		t.Fatalf("err = %v, want errUnsplittable", err)
	}
	if n := puts.Load(); n > 3 {
		t.Fatalf("%d PUTs of a request that cannot get smaller, want at most 3", n)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "cannot be split further") {
		t.Fatalf("no log line says why: %q", logs)
	}
	var pe *outbox.PermanentError
	if !errors.As(classify(err), &pe) {
		t.Fatalf("classify(%v) is not permanent: the outbox would retry it", err)
	}
}
