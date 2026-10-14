package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The content fetcher talks to the platform's content routes with the
// sensor's credentials, and reuses the last desired document on a 304.
func TestContentFetcherUsesThePlatformAndTheSensorKey(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("If-None-Match") == `"e1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"e1"`)
		_, _ = w.Write([]byte(`{"packs":[],"revoked":["sha256:` + "aa00000000000000000000000000000000000000000000000000000000000000" + `"]}`))
	}))
	defer server.Close()
	f := New(&Config{BaseURL: server.URL, APIKey: "test-key"}).ContentFetcher()
	d, changed, err := f.Desired(context.Background())
	if err != nil || !changed || len(d.Revoked) != 1 {
		t.Fatalf("%+v %v %v", d, changed, err)
	}
	d2, changed, err := f.Desired(context.Background())
	if err != nil || changed || d2 != d {
		t.Fatalf("304 not reused: %v %v", changed, err)
	}
	if len(paths) != 2 || paths[0] != ContentPath+"/desired" {
		t.Fatalf("paths %v", paths)
	}
}
