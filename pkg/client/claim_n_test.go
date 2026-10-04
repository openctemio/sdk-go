package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// claimNServer is a v2 platform whose hello lists features; GET /commands
// answers one command, acknowledged when the poll asked to claim.
func claimNServer(t *testing.T, features []string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		w.Header().Set(protov2.HeaderProtocol, "2")
		if r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: features,
				MediaTypes: []string{protov2.MediaTypeCTIS}, Limits: protov2.DefaultLimits()})
			return
		}
		feat := r.Header.Get(legacyv1.HeaderSensorFeatures)
		mu.Lock()
		asked = append(asked, feat)
		mu.Unlock()
		status := "pending"
		if feat == protov2.FeatureCapacity {
			status = "acknowledged"
		}
		_, _ = w.Write([]byte(`{"commands":[{"id":"c1","type":"scan","status":"` + status + `","lease_epoch":1}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

func TestClaimN_AsksOnlyWhenThePlatformOffersIt(t *testing.T) {
	for _, tc := range []struct {
		name        string
		features    []string
		opts        []Option
		wantHeader  string
		wantClaimed bool
	}{
		{"offered", []string{protov2.FeatureCommands, protov2.FeatureCapacity}, nil, protov2.FeatureCapacity, true},
		{"not offered", []string{protov2.FeatureCommands}, nil, "", false},
		{"opted out", []string{protov2.FeatureCommands, protov2.FeatureCapacity}, []Option{WithoutClaimOnPoll()}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, asked := claimNServer(t, tc.features)
			c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
			for _, o := range tc.opts {
				o(c)
			}
			resp, err := c.GetCommandsLimit(context.Background(), 3)
			if err != nil {
				t.Fatal(err)
			}
			if got := asked(); len(got) != 1 || got[0] != tc.wantHeader {
				t.Fatalf("features header %q, want %q", got, tc.wantHeader)
			}
			if len(resp.Commands) != 1 || resp.Commands[0].Claimed != tc.wantClaimed {
				t.Fatalf("claimed = %v, want %v", resp.Commands[0].Claimed, tc.wantClaimed)
			}
		})
	}
}
