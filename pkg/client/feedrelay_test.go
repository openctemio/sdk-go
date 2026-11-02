package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/feedrelay"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// An empty answer carries the platform's Retry-After; a refusal is an
// HTTPError that reports its status and Retry-After to the relay.
func TestNextFeedRelayRetryAfter(t *testing.T) {
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != protov2.PathPrefix+feedrelay.NextPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "test-key", MaxRetries: 0})
	round, wait, err := c.NextFeedRelay(context.Background())
	if err != nil || round != nil || wait != 15*time.Second {
		t.Fatalf("204: %v %v %v", round, wait, err)
	}
	status = http.StatusTooManyRequests
	_, _, err = c.NextFeedRelay(context.Background())
	var he *HTTPError
	if !errors.As(err, &he) || he.HTTPStatusCode() != http.StatusTooManyRequests || he.RetryAfterHint() != 15*time.Second {
		t.Fatalf("429: %v", err)
	}
}
