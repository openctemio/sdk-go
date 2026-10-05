package client

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/openctemio/sdk-go/pkg/ctis"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// v2Features are the hello features a current platform lists.
var v2Features = []string{protov2.FeatureResults, protov2.FeatureHeartbeat, protov2.FeatureCommands,
	protov2.FeatureSuppressions, protov2.FeatureFingerprints, protov2.FeatureKeys}

// v2Platform serves fn as a protocol v2 platform: GET /api/v2/sensor/hello
// lists results and the control features; every other request goes to fn.
func v2Platform(t *testing.T, fn http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == protov2.PathPrefix+protov2.HelloPath {
			w.Header().Set("Content-Type", protov2.MediaTypeJSON)
			_ = json.NewEncoder(w).Encode(protov2.Hello{Protocol: 2, Features: v2Features,
				MediaTypes: []string{protov2.MediaTypeCTIS}, Encodings: []string{"gzip", "zstd"},
				Digests: []string{"sha-256"}, Limits: protov2.DefaultLimits()})
			return
		}
		fn(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// noV2Platform is a platform without protocol v2: every /api/v2/ request is
// a plain 404, as an API from before 2026-10 answers.
func noV2Platform(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(srv.Close)
	return srv
}

// acceptResults answers a whole-report PUT .../results/{id} with 202 and a
// completed status counting the report's findings and assets.
func acceptResults(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.Method != http.MethodPut || !strings.Contains(r.URL.Path, protov2.ResultsPath+"/") {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch r.Header.Get("Content-Encoding") {
	case "zstd":
		dec, _ := zstd.NewReader(nil)
		body, _ = dec.DecodeAll(body, nil)
		dec.Close()
	case "gzip":
		if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			body, _ = io.ReadAll(zr)
		}
	}
	var rep ctis.Report
	_ = json.Unmarshal(body, &rep)
	id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	st := protov2.Status{ReportID: id, State: protov2.StateCompleted, Errors: []protov2.ItemError{}}
	st.Accepted.Findings = len(rep.Findings)
	st.Accepted.Assets = len(rep.Assets)
	w.Header().Set("Content-Type", protov2.MediaTypeJSON)
	w.Header().Set(protov2.HeaderProtocol, "2")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(st)
}

// testReport is a small report with the tool protocol v2 requires.
func testReport() *ctis.Report {
	r := ctis.NewReport()
	r.Tool = &ctis.Tool{Name: "semgrep"}
	return r
}
