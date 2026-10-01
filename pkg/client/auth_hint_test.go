package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

// A 401 from the platform must be recognized by pkg/core as an auth failure,
// even wrapped, and the client must name its key without revealing it.
func TestAuthFailureVisibleToCore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"UNAUTHORIZED","message":"Invalid API key"}`))
	}))
	defer srv.Close()

	key := "rda_5d221b75e7c2c415af4ef576b6ecc6993539ae83aba2c94d12074a3060c49c70"
	c := New(&Config{BaseURL: srv.URL, APIKey: key, MaxRetries: 1})
	err := c.SendHeartbeat(context.Background(), &core.SensorStatus{Name: "t"})
	if got := core.AuthFailureStatus(err); got != http.StatusUnauthorized {
		t.Fatalf("AuthFailureStatus(%v) = %d, want 401", err, got)
	}
	var hinter core.APIKeyHinter = c
	if got := hinter.APIKeyHint(); got != "rda_5d22…" {
		t.Fatalf("APIKeyHint = %q", got)
	}
}

// Through the web UI origin (or a proxy that strips Authorization) the API
// answers 401 "API key required": the advice must point at API_URL, not at
// the key.
func TestAuthFailureAdvice_KeyNeverReachedAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"UNAUTHORIZED","code":"UNAUTHORIZED","message":"API key required"}`))
	}))
	defer srv.Close()

	c := New(&Config{BaseURL: srv.URL, APIKey: "rda_5d221b75e7c2c415", MaxRetries: 1})
	err := c.SendHeartbeat(context.Background(), &core.SensorStatus{Name: "t"})
	advice := core.AuthFailureAdvice(err, c.APIKeyHint())
	if !strings.Contains(advice, "never reached the API") || !strings.Contains(advice, "API_URL") {
		t.Fatalf("advice %q", advice)
	}
}
