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

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

const oversizedCommandID = "0b7f7a1e-5a3c-4f43-9d0e-2f6c1c8f3a11"

// oversizedPollServer is a v2 platform whose GET /commands answers a body of
// 11 MiB (one command with a huge payload); it counts those requests.
func oversizedPollServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		w.Header().Set(protov2.HeaderProtocol, "2")
		if r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: []string{protov2.FeatureCommands},
				MediaTypes: []string{protov2.MediaTypeCTIS}, Limits: protov2.DefaultLimits()})
			return
		}
		polls.Add(1)
		_, _ = w.Write([]byte(`{"commands":[{"id":"` + oversizedCommandID + `","type":"scan","payload":"`))
		chunk := []byte(strings.Repeat("a", 1<<20))
		for range 11 {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte(`"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &polls
}

// An answer over the 10 MiB limit comes back as a typed error, is asked for
// once (not once per retry), and keeps the start of the answer.
func TestPollCommands_OversizedAnswerIsTypedAndNotRetried(t *testing.T) {
	srv, polls := oversizedPollServer(t)
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 3, RetryDelay: time.Millisecond})

	_, err := c.GetCommandsLimit(context.Background(), 5)
	if !errors.Is(err, core.ErrResponseTooLarge) {
		t.Fatalf("err = %v, want core.ErrResponseTooLarge", err)
	}
	if got := polls.Load(); got != 1 {
		t.Fatalf("the oversized answer was requested %d times, want 1 (no retry)", got)
	}
	var tl *ResponseTooLargeError
	if !errors.As(err, &tl) {
		t.Fatalf("err %T is not *ResponseTooLargeError", err)
	}
	if tl.Limit != maxResponseBodyBytes || len(tl.Head) != responseHeadBytes {
		t.Fatalf("limit %d head %d bytes, want %d and %d", tl.Limit, len(tl.Head), maxResponseBodyBytes, responseHeadBytes)
	}
	if !strings.Contains(string(tl.Head), oversizedCommandID) {
		t.Fatalf("head %.80q does not hold the command id", tl.Head)
	}
	var hp core.ResponseHeadProvider
	if !errors.As(err, &hp) || len(hp.ResponseHead()) != responseHeadBytes {
		t.Fatal("the error does not expose its head to the poller")
	}
}
