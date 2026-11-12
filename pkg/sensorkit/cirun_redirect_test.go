package sensorkit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The default HTTP client of runner mode carries the run token and the CI
// id token: it follows no redirect.
func TestCIRunDefaultClientRefusesRedirects(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	var cfg CIRunConfig
	cfg.normalize()
	req, _ := http.NewRequest(http.MethodPost, redirecting.URL, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := cfg.HTTPClient.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want an error naming the refused redirect", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the redirect target got %d request(s), want 0", n)
	}
}
