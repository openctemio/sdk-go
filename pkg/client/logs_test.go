package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/outbox"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// logsServer is a v2 platform whose hello lists features and whose logs
// resource answers status.
func logsServer(t *testing.T, features []string, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		w.Header().Set(protov2.HeaderProtocol, "2")
		switch r.URL.Path {
		case protov2.PathPrefix + protov2.HelloPath:
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: features,
				MediaTypes: []string{protov2.MediaTypeCTIS}, Limits: protov2.DefaultLimits()})
		case protov2.CommandActionPath("c1", protov2.LogsAction):
			calls.Add(1)
			if status != http.StatusOK {
				w.Header().Set("Content-Type", protov2.MediaTypeProblem)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"type":"https://openctem.io/problems/ingest/command-not-found","title":"gone","status":404}`))
				return
			}
			_ = json.NewEncoder(w).Encode(protov2.CommandLogsResponse{Stored: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func logBatch() protov2.CommandLogsRequest {
	return protov2.CommandLogsRequest{Seq: 0, Lines: []protov2.CommandLogLine{{TS: time.Now().UTC(), Level: "info", Msg: "hello"}}}
}

func logDelivery(t *testing.T) *outbox.Delivery {
	t.Helper()
	payload, err := json.Marshal(commandLogItem{CommandID: "c1", Batch: logBatch()})
	if err != nil {
		t.Fatal(err)
	}
	return &outbox.Delivery{Meta: outbox.Meta{Kind: outbox.KindCommandLog, CommandID: "c1"}, Payload: payload}
}

func TestSendCommandLogs(t *testing.T) {
	srv, calls := logsServer(t, []string{protov2.FeatureCommands, protov2.FeatureLogs}, http.StatusOK)
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	res, err := c.SendCommandLogs(context.Background(), "c1", logBatch())
	if err != nil || res.Stored != 1 || calls.Load() != 1 {
		t.Fatalf("res %+v err %v calls %d", res, err, calls.Load())
	}
	// Delivered from the outbox: success.
	if err := deliverLog(t, c); err != nil {
		t.Fatal(err)
	}
}

// deliverLog delivers one stored log batch through Deliver.
func deliverLog(t *testing.T, c *Client) error {
	t.Helper()
	_, err := c.Deliver(context.Background(), logDelivery(t))
	return err
}

// A platform without the feature is never called, and a refusal for good
// drops the batch instead of dead-lettering it (which would mark the
// command's results refused).
func TestCommandLogsAreBestEffort(t *testing.T) {
	srv, calls := logsServer(t, []string{protov2.FeatureCommands}, http.StatusOK)
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	if _, err := c.SendCommandLogs(context.Background(), "c1", logBatch()); !errors.Is(err, ErrLogsUnsupported) {
		t.Fatalf("without the feature: %v", err)
	}
	if err := deliverLog(t, c); err != nil || calls.Load() != 0 {
		t.Fatalf("delivery without the feature: %v (%d calls)", err, calls.Load())
	}

	srv, calls = logsServer(t, []string{protov2.FeatureCommands, protov2.FeatureLogs}, http.StatusNotFound)
	c = New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	if err := deliverLog(t, c); err != nil || calls.Load() != 1 {
		t.Fatalf("a refused batch must be dropped: %v (%d calls)", err, calls.Load())
	}
}
