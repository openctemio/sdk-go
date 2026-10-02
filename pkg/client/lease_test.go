package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"sync"
	"testing"
	"time"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// A platform from before leases answers claim and start without
// lease_epoch: complete and fail then carry no X-OpenCTEM-Lease-Epoch.
func TestLeaseEpoch_ClaimWithoutEpochSendsNoHeader(t *testing.T) {
	var mu sync.Mutex
	sent := map[string][]string{} // action -> header values (with presence)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		w.Header().Set(protov2.HeaderProtocol, "2")
		if r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: []string{protov2.FeatureCommands},
				MediaTypes: []string{protov2.MediaTypeCTIS}, Limits: protov2.DefaultLimits()})
			return
		}
		action := path.Base(r.URL.Path)
		mu.Lock()
		if v := r.Header.Values(protov2.HeaderLeaseEpoch); len(v) > 0 {
			sent[action] = append(sent[action], v...)
		} else {
			sent[action] = append(sent[action], "<none>")
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{"id":"c1","status":"running"}`))
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
	ctx := context.Background()
	for _, step := range []func() error{
		func() error { return c.AcknowledgeCommand(ctx, "c1") },
		func() error { return c.StartCommand(ctx, "c1") },
		func() error { return c.FailCommand(ctx, "c1", "boom") },
		func() error { return c.CompleteCommand(ctx, "c1", nil) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, a := range []string{protov2.ClaimAction, protov2.StartAction, protov2.FailAction, protov2.CompleteAction} {
		if len(sent[a]) != 1 || sent[a][0] != "<none>" {
			t.Fatalf("%s sent lease header %q", a, sent[a])
		}
	}
}

func TestLeaseTable(t *testing.T) {
	var lt leaseTable
	if lt.epoch("x") != 0 {
		t.Fatal("unknown command has an epoch")
	}
	lt.record("x", 2)
	if lt.epoch("x") != 2 || leaseHeader(2).Get(protov2.HeaderLeaseEpoch) != "2" {
		t.Fatal("recorded epoch")
	}
	lt.record("x", 0) // an answer without an epoch forgets it
	if lt.epoch("x") != 0 || leaseHeader(0) != nil {
		t.Fatal("epoch 0 kept or sent")
	}
	for i := range maxLeaseEntries + 10 {
		lt.record(strconv.Itoa(i), 1)
	}
	if len(lt.m) != maxLeaseEntries {
		t.Fatalf("table holds %d entries", len(lt.m))
	}
	lt.forget("5000")
	if lt.epoch("5000") != 0 {
		t.Fatal("forget")
	}
}
