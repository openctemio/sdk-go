package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// suppressionServer answers each path with the given status (200 bodies are a
// one-rule list) and records the paths requested and the key presented.
type suppressionServer struct {
	mu     sync.Mutex
	status map[string]int
	paths  []string
	auth   []string
}

func (s *suppressionServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	code, ok := s.status[r.URL.Path]
	s.mu.Unlock()
	if !ok {
		code = http.StatusNotFound
	}
	w.WriteHeader(code)
	if code == http.StatusOK {
		_, _ = w.Write([]byte(`{"rules":[{"rule_id":"r1","tool_name":"gitleaks","path_pattern":"testdata/**"}],"count":1}`))
	}
}

func newSuppressionClient(t *testing.T, s *suppressionServer) *Client {
	t.Helper()
	srv := httptest.NewServer(v1Only(s.ServeHTTP))
	t.Cleanup(srv.Close)
	return New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 1, RetryDelay: time.Millisecond})
}

func TestGetSuppressions_UsesSensorRoute(t *testing.T) {
	s := &suppressionServer{status: map[string]int{legacyv1.PathSuppressions: http.StatusOK}}
	c := newSuppressionClient(t, s)

	rules, err := c.GetSuppressions(context.Background())
	if err != nil {
		t.Fatalf("GetSuppressions: %v", err)
	}
	if len(rules) != 1 || rules[0].RuleID != "r1" || rules[0].ToolName != "gitleaks" {
		t.Fatalf("rules = %+v", rules)
	}
	if len(s.paths) != 1 || s.paths[0] != "/api/v1/agent/suppressions" {
		t.Fatalf("paths = %v, want only /api/v1/agent/suppressions", s.paths)
	}
	if s.auth[0] != "Bearer rda_test" {
		t.Errorf("Authorization = %q", s.auth[0])
	}
}

func TestGetSuppressions_FallsBackOnceOn404(t *testing.T) {
	// An API from before the sensor route: 404 there, the user route answers.
	s := &suppressionServer{status: map[string]int{legacyv1.PathSuppressionsUser: http.StatusOK}}
	c := newSuppressionClient(t, s)

	rules, err := c.GetSuppressions(context.Background())
	if err != nil {
		t.Fatalf("GetSuppressions: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %+v", rules)
	}
	want := []string{legacyv1.PathSuppressions, legacyv1.PathSuppressionsUser}
	if strings.Join(s.paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v", s.paths, want)
	}
}

func TestGetSuppressions_ReturnsErrors(t *testing.T) {
	tests := []struct {
		name      string
		status    map[string]int
		wantPaths int
		wantIn    string
	}{
		{
			// The old API: no sensor route, and the user route refuses a
			// sensor key. This used to be swallowed as "no rules".
			name:      "old API refuses the sensor key",
			status:    map[string]int{legacyv1.PathSuppressionsUser: http.StatusUnauthorized},
			wantPaths: 2,
			wantIn:    "refused this key",
		},
		{
			name:      "sensor route refuses the key: no fallback",
			status:    map[string]int{legacyv1.PathSuppressions: http.StatusUnauthorized},
			wantPaths: 1,
			wantIn:    "refused this key",
		},
		{
			name:      "server error",
			status:    map[string]int{legacyv1.PathSuppressions: http.StatusInternalServerError},
			wantPaths: 2, // one retry
			wantIn:    "fetch suppression rules",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &suppressionServer{status: tt.status}
			c := newSuppressionClient(t, s)
			rules, err := c.GetSuppressions(context.Background())
			if err == nil {
				t.Fatalf("GetSuppressions returned %v and no error", rules)
			}
			if !strings.Contains(err.Error(), tt.wantIn) {
				t.Errorf("error %q does not contain %q", err, tt.wantIn)
			}
			if len(s.paths) != tt.wantPaths {
				t.Errorf("requests = %v, want %d", s.paths, tt.wantPaths)
			}
		})
	}
}
