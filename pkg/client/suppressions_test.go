package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

const suppressionsPath = protov2.PathPrefix + protov2.SuppressionsPath

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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if code == http.StatusOK {
		_, _ = w.Write([]byte(`{"rules":[{"rule_id":"r1","tool_name":"gitleaks","path_pattern":"testdata/**"}],"count":1}`))
	}
}

func newSuppressionClient(t *testing.T, s *suppressionServer) *Client {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 1, RetryDelay: time.Millisecond})
}

func TestGetSuppressions_UsesSensorRoute(t *testing.T) {
	s := &suppressionServer{status: map[string]int{suppressionsPath: http.StatusOK}}
	c := newSuppressionClient(t, s)

	rules, err := c.GetSuppressions(context.Background())
	if err != nil {
		t.Fatalf("GetSuppressions: %v", err)
	}
	if len(rules) != 1 || rules[0].RuleID != "r1" || rules[0].ToolName != "gitleaks" {
		t.Fatalf("rules = %+v", rules)
	}
	if len(s.paths) != 1 || s.paths[0] != suppressionsPath {
		t.Fatalf("paths = %v, want only %s", s.paths, suppressionsPath)
	}
	if s.auth[0] != "Bearer rda_test" {
		t.Errorf("Authorization = %q", s.auth[0])
	}
}

// A platform without protocol v2: ErrV2Unsupported, and no fall-back to the
// retired v1 route or the user route.
func TestGetSuppressions_NoV2IsAnError(t *testing.T) {
	s := &suppressionServer{status: map[string]int{}}
	c := newSuppressionClient(t, s)
	if _, err := c.GetSuppressions(context.Background()); !errors.Is(err, ErrV2Unsupported) {
		t.Fatalf("err = %v, want ErrV2Unsupported", err)
	}
	for _, p := range s.paths {
		if p != suppressionsPath {
			t.Fatalf("requested %s; only %s may be asked", p, suppressionsPath)
		}
	}
}

func TestGetSuppressions_ReturnsErrors(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantPaths int
	}{
		{"the platform refuses the key", http.StatusUnauthorized, 1},
		{"server error", http.StatusInternalServerError, 2}, // one retry
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &suppressionServer{status: map[string]int{suppressionsPath: tt.status}}
			c := newSuppressionClient(t, s)
			rules, err := c.GetSuppressions(context.Background())
			if err == nil {
				t.Fatalf("GetSuppressions returned %v and no error", rules)
			}
			if !strings.Contains(err.Error(), "fetch suppression rules") {
				t.Errorf("error %q", err)
			}
			if len(s.paths) != tt.wantPaths {
				t.Errorf("requests = %v, want %d", s.paths, tt.wantPaths)
			}
		})
	}
}
