package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

func TestDoRequest_ResponseSizeLimits(t *testing.T) {
	t.Run("oversized success body rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			chunk := strings.Repeat("a", 1<<20)
			for i := 0; i < 11; i++ { // 11 MiB > 10 MiB cap
				_, _ = w.Write([]byte(chunk))
			}
		}))
		defer srv.Close()
		c := New(&Config{BaseURL: srv.URL, MaxRetries: 1, RetryDelay: time.Millisecond})
		c.maxRetries = 0
		if _, err := c.doRequest(context.Background(), "GET", srv.URL+"/x", nil); err == nil ||
			!strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("expected size-limit error, got %v", err)
		}
	})

	t.Run("error body truncated", func(t *testing.T) {
		big := strings.Repeat("E", 1<<20) // 1 MiB error page
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(big))
		}))
		defer srv.Close()
		c := New(&Config{BaseURL: srv.URL})
		_, err := c.doRequest(context.Background(), "GET", srv.URL+"/x", nil)
		httpErr, ok := IsHTTPError(err)
		if !ok {
			t.Fatalf("expected HTTPError, got %v", err)
		}
		if len(httpErr.Body) > maxErrorBodyBytes {
			t.Errorf("HTTPError.Body = %d bytes, cap is %d", len(httpErr.Body), maxErrorBodyBytes)
		}
		if msg := httpErr.Error(); len(msg) > maxErrorMessageBytes+200 || !strings.Contains(msg, "truncated") {
			t.Errorf("Error() not truncated: %d bytes", len(msg))
		}
	})

	t.Run("normal body passes", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer srv.Close()
		c := New(&Config{BaseURL: srv.URL})
		data, err := c.doRequest(context.Background(), "GET", srv.URL+"/x", nil)
		if err != nil || string(data) != `{"ok":true}` {
			t.Fatalf("got %q, %v", data, err)
		}
	})
}

func TestClient_BaseURLValidation(t *testing.T) {
	for _, bad := range []string{"", "ftp://api.example.com", "file:///etc/passwd", "https://user:pw@api.example.com", "api.example.com"} {
		c := New(&Config{BaseURL: bad, MaxRetries: 1})
		if err := c.SendHeartbeat(context.Background(), &core.SensorStatus{}); err == nil {
			t.Errorf("base URL %q accepted", bad)
		}
	}
}

// The API never redirects. A redirect must not be followed, and the bearer
// key must never reach the redirect target.
func TestClient_RefusesRedirects(t *testing.T) {
	var leaked sync.Map
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			leaked.Store("auth", a)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer api.Close()

	c := New(&Config{BaseURL: api.URL, APIKey: "oct_secret", MaxRetries: 1, RetryDelay: time.Millisecond})
	if err := c.SendHeartbeat(context.Background(), &core.SensorStatus{}); err == nil {
		t.Fatal("redirect was followed")
	}
	if v, ok := leaked.Load("auth"); ok {
		t.Fatalf("API key forwarded to redirect target: %v", v)
	}
}

// Command IDs come from the server and must not be able to rewrite the path.
func TestCommandEndpoints_EscapeIDs(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(&Config{BaseURL: srv.URL})

	if err := c.AcknowledgeCommand(context.Background(), "../../admin/users?x=1"); err != nil {
		t.Fatal(err)
	}
	want := "/api/v2/sensor/commands/..%2F..%2Fadmin%2Fusers%3Fx=1/claim"
	if gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

type countingExecutor struct {
	mu   sync.Mutex
	seen []string
}

func (e *countingExecutor) Execute(_ context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen = append(e.seen, cmd.ID)
	return &core.CommandExecutionResult{}, nil
}

func (e *countingExecutor) ids() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.seen...)
}

// GetCommands used to drop ExpiresAt, so the poller's expiry check never
// fired and stale commands ran. End to end through the real client: the
// expired command is neither acknowledged nor executed.
func TestCommandPoller_SkipsExpiredCommands(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	commands := []Command{
		{ID: "expired", Type: "health_check", ExpiresAt: &past, CreatedAt: past.Add(-time.Hour)},
		{ID: "fresh", Type: "health_check", ExpiresAt: &future},
		{ID: "no-expiry", Type: "health_check"},
	}
	var mu sync.Mutex
	var acked []string
	served := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/sensor/commands":
			mu.Lock()
			first := !served
			served = true
			mu.Unlock()
			if first {
				_ = json.NewEncoder(w).Encode(map[string]any{"commands": commands})
				return
			}
			_, _ = w.Write([]byte(`{"commands":[]}`))
		case strings.HasSuffix(r.URL.Path, "/claim"):
			mu.Lock()
			acked = append(acked, strings.Split(r.URL.Path, "/")[5])
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	c := New(&Config{BaseURL: srv.URL})

	resp, err := c.GetCommands(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Commands[0].ExpiresAt.Equal(past) {
		t.Fatalf("ExpiresAt not propagated: %v", resp.Commands[0].ExpiresAt)
	}
	mu.Lock()
	served = false // let the poller receive the batch again
	mu.Unlock()

	exec := &countingExecutor{}
	poller := core.NewCommandPoller(c, exec, &core.CommandPollerConfig{
		PollInterval: time.Hour, AllowedTypes: []string{"health_check"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- poller.Start(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for len(exec.ids()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	ids := exec.ids()
	for _, id := range ids {
		if id == "expired" {
			t.Fatal("expired command was executed")
		}
	}
	if len(ids) != 2 {
		t.Fatalf("expected fresh + no-expiry to run, got %v", ids)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range acked {
		if id == "expired" {
			t.Fatal("expired command was acknowledged")
		}
	}
}
