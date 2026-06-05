package tenable

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests exercise the request/response wiring against an httptest mock that
// emulates the documented Nessus REST API. They do NOT verify behaviour against
// a real appliance — that requires a live-instance spike (RFC-007 Phase 2).

func TestNessusPro_New_Validation(t *testing.T) {
	if _, err := NewNessusProClient("", Credentials{AccessKey: "a", SecretKey: "b"}, nil); err == nil {
		t.Fatal("empty base URL must error")
	}
	if _, err := NewNessusProClient("https://n", Credentials{}, nil); err == nil {
		t.Fatal("missing keys must error")
	}
}

func TestNessusPro_AuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("X-ApiKeys")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c, _ := NewNessusProClient(srv.URL, Credentials{AccessKey: "AK", SecretKey: "SK"}, srv.Client())
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if gotAuth != "accessKey=AK; secretKey=SK" {
		t.Fatalf("auth header wrong: %q", gotAuth)
	}
}

func TestNessusPro_LaunchPollExport(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scans", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		_, _ = w.Write([]byte(`{"scan":{"id":42}}`))
	})
	mux.HandleFunc("/scans/42/launch", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"scan_uuid":"abc"}`))
	})
	mux.HandleFunc("/scans/42", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"status":"completed"}}`))
	})
	mux.HandleFunc("/scans/42/export", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"file":7}`))
	})
	mux.HandleFunc("/scans/42/export/7/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("/scans/42/export/7/download", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<NessusClientData_v2></NessusClientData_v2>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := NewNessusProClient(srv.URL, Credentials{AccessKey: "AK", SecretKey: "SK"}, srv.Client())
	ctx := context.Background()

	ref, err := c.Launch(ctx, LaunchRequest{Targets: []string{"10.0.0.0/24"}, TemplateUUID: "tmpl"})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if ref.ScanID != "42" {
		t.Fatalf("scan id wrong: %q", ref.ScanID)
	}

	state, err := c.Poll(ctx, ref)
	if err != nil || state != ScanCompleted {
		t.Fatalf("Poll: state=%q err=%v", state, err)
	}

	body, err := c.Export(ctx, ref)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	defer func() { _ = body.Close() }()
	buf := make([]byte, 64)
	n, _ := body.Read(buf)
	if !strings.Contains(string(buf[:n]), "NessusClientData_v2") {
		t.Fatalf("export body wrong: %q", string(buf[:n]))
	}
}

func TestNessusPro_LaunchRequiresTemplate(t *testing.T) {
	c, _ := NewNessusProClient("https://n", Credentials{AccessKey: "a", SecretKey: "b"}, nil)
	if _, err := c.Launch(context.Background(), LaunchRequest{Targets: []string{"1.1.1.1"}}); err == nil {
		t.Fatal("missing template uuid must error")
	}
}

