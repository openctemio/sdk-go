package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	h := NewHandler(WithVersion("1.0.0"), WithTimeout(1*time.Second))

	t.Run("Register and check", func(t *testing.T) {
		h.Register("test", &PingCheck{})

		response := h.Check(context.Background())

		if response.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", response.Status, StatusHealthy)
		}

		if response.Version != "1.0.0" {
			t.Errorf("Version = %v, want %v", response.Version, "1.0.0")
		}

		if len(response.Checks) != 1 {
			t.Errorf("Checks = %d, want 1", len(response.Checks))
		}

		if _, ok := response.Checks["test"]; !ok {
			t.Error("Expected 'test' check in response")
		}
	})

	t.Run("Unregister", func(t *testing.T) {
		h.Unregister("test")
		response := h.Check(context.Background())

		if len(response.Checks) != 0 {
			t.Errorf("Checks after unregister = %d, want 0", len(response.Checks))
		}
	})

	t.Run("RegisterFunc", func(t *testing.T) {
		h.RegisterFunc("func-check", func(ctx context.Context) CheckResult {
			return CheckResult{
				Status:  StatusHealthy,
				Message: "custom check",
			}
		})

		response := h.Check(context.Background())

		if result, ok := response.Checks["func-check"]; !ok {
			t.Error("Expected 'func-check' in response")
		} else if result.Message != "custom check" {
			t.Errorf("Message = %v, want 'custom check'", result.Message)
		}
	})
}

func TestHandlerReadiness(t *testing.T) {
	h := NewHandler()

	t.Run("Default is ready", func(t *testing.T) {
		if !h.IsReady() {
			t.Error("Default should be ready")
		}
	})

	t.Run("SetReady false", func(t *testing.T) {
		h.SetReady(false)
		if h.IsReady() {
			t.Error("Should not be ready after SetReady(false)")
		}
	})

	t.Run("SetReady true", func(t *testing.T) {
		h.SetReady(true)
		if !h.IsReady() {
			t.Error("Should be ready after SetReady(true)")
		}
	})
}

func TestLivenessHandler(t *testing.T) {
	h := NewHandler()

	t.Run("Always returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()

		h.LivenessHandler().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)

		if response["status"] != string(StatusHealthy) {
			t.Errorf("Status = %v, want %v", response["status"], StatusHealthy)
		}
	})
}

func TestReadinessHandler(t *testing.T) {
	h := NewHandler()

	t.Run("Returns 200 when ready", func(t *testing.T) {
		h.SetReady(true)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()

		h.ReadinessHandler().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("Returns 503 when not ready", func(t *testing.T) {
		h.SetReady(false)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()

		h.ReadinessHandler().ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusServiceUnavailable)
		}
	})

	t.Run("Returns 503 when check fails", func(t *testing.T) {
		h.SetReady(true)
		h.RegisterFunc("failing", func(ctx context.Context) CheckResult {
			return CheckResult{
				Status: StatusUnhealthy,
				Error:  "test failure",
			}
		})

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()

		h.ReadinessHandler().ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusServiceUnavailable)
		}
	})
}

func TestHealthHandler(t *testing.T) {
	h := NewHandler()

	t.Run("Returns full response", func(t *testing.T) {
		h.Register("ping", &PingCheck{})

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		h.HealthHandler().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var response Response
		json.Unmarshal(w.Body.Bytes(), &response)

		if response.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", response.Status, StatusHealthy)
		}

		if len(response.Checks) != 1 {
			t.Errorf("Checks = %d, want 1", len(response.Checks))
		}
	})
}

func TestCheckStatusAggregation(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		expected Status
	}{
		{
			name:     "all healthy",
			statuses: []Status{StatusHealthy, StatusHealthy},
			expected: StatusHealthy,
		},
		{
			name:     "one degraded",
			statuses: []Status{StatusHealthy, StatusDegraded},
			expected: StatusDegraded,
		},
		{
			name:     "one unhealthy",
			statuses: []Status{StatusHealthy, StatusUnhealthy},
			expected: StatusUnhealthy,
		},
		{
			name:     "degraded and unhealthy",
			statuses: []Status{StatusDegraded, StatusUnhealthy},
			expected: StatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler()

			for i, status := range tt.statuses {
				s := status // capture
				h.RegisterFunc(string(rune('a'+i)), func(ctx context.Context) CheckResult {
					return CheckResult{Status: s}
				})
			}

			response := h.Check(context.Background())

			if response.Status != tt.expected {
				t.Errorf("Status = %v, want %v", response.Status, tt.expected)
			}
		})
	}
}

func TestPingCheck(t *testing.T) {
	check := &PingCheck{}

	if check.Name() != "ping" {
		t.Errorf("Name = %v, want 'ping'", check.Name())
	}

	result := check.Check(context.Background())

	if result.Status != StatusHealthy {
		t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
	}

	if result.Message != "pong" {
		t.Errorf("Message = %v, want 'pong'", result.Message)
	}
}

func TestHTTPCheck(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		check := &HTTPCheck{
			URL:     server.URL,
			Timeout: 1 * time.Second,
		}

		result := check.Check(context.Background())

		if result.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
		}
	})

	t.Run("Server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		check := &HTTPCheck{
			URL:     server.URL,
			Timeout: 1 * time.Second,
		}

		result := check.Check(context.Background())

		if result.Status != StatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusUnhealthy)
		}
	})

	t.Run("Connection error", func(t *testing.T) {
		check := &HTTPCheck{
			URL:     "http://localhost:99999",
			Timeout: 100 * time.Millisecond,
		}

		result := check.Check(context.Background())

		if result.Status != StatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusUnhealthy)
		}

		if result.Error == "" {
			t.Error("Expected error message")
		}
	})
}

func TestDatabaseCheck(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		check := &DatabaseCheck{
			PingFunc: func(ctx context.Context) error {
				return nil
			},
		}

		result := check.Check(context.Background())

		if result.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
		}
	})

	t.Run("Failure", func(t *testing.T) {
		check := &DatabaseCheck{
			PingFunc: func(ctx context.Context) error {
				return errors.New("connection refused")
			},
		}

		result := check.Check(context.Background())

		if result.Status != StatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusUnhealthy)
		}

		if result.Error != "connection refused" {
			t.Errorf("Error = %v, want 'connection refused'", result.Error)
		}
	})

	t.Run("No ping func", func(t *testing.T) {
		check := &DatabaseCheck{}

		result := check.Check(context.Background())

		if result.Status != StatusUnknown {
			t.Errorf("Status = %v, want %v", result.Status, StatusUnknown)
		}
	})
}

func TestDefaultHandler(t *testing.T) {
	h := Default()

	if h == nil {
		t.Error("Default handler should not be nil")
	}

	// Should have ping check registered
	response := h.Check(context.Background())

	if _, ok := response.Checks["ping"]; !ok {
		t.Error("Default handler should have ping check")
	}
}

func TestRegisterRoutes(t *testing.T) {
	mux := http.NewServeMux()

	RegisterRoutes(mux, &ServerConfig{
		LivenessPath:  "/live",
		ReadinessPath: "/ready",
		HealthPath:    "/health",
	})

	tests := []struct {
		path string
		code int
	}{
		{"/live", http.StatusOK},
		{"/ready", http.StatusOK},
		{"/health", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			if w.Code != tt.code {
				t.Errorf("%s: Status = %d, want %d", tt.path, w.Code, tt.code)
			}
		})
	}
}

func TestCheckFunc(t *testing.T) {
	fn := CheckFunc(func(ctx context.Context) CheckResult {
		return CheckResult{
			Status:  StatusHealthy,
			Message: "test",
		}
	})

	// Name returns empty string for CheckFunc
	if fn.Name() != "" {
		t.Errorf("Name = %v, want ''", fn.Name())
	}

	result := fn.Check(context.Background())

	if result.Status != StatusHealthy {
		t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
	}

	if result.Message != "test" {
		t.Errorf("Message = %v, want 'test'", result.Message)
	}
}

// =============================================================================
// Security Options Tests
// =============================================================================

func TestSecurityOptions(t *testing.T) {
	t.Run("WithHideVersion", func(t *testing.T) {
		h := NewHandler(WithVersion("1.0.0"), WithHideVersion())
		h.Register("ping", &PingCheck{})

		response := h.Check(context.Background())

		if response.Version != "" {
			t.Errorf("Version should be hidden, got %v", response.Version)
		}
	})

	t.Run("WithHideUptime", func(t *testing.T) {
		h := NewHandler(WithHideUptime())
		h.Register("ping", &PingCheck{})

		response := h.Check(context.Background())

		if response.Uptime != 0 {
			t.Errorf("Uptime should be hidden, got %v", response.Uptime)
		}
	})

	t.Run("WithHideDetails", func(t *testing.T) {
		h := NewHandler(WithHideDetails())
		h.Register("ping", &PingCheck{})

		response := h.Check(context.Background())

		if len(response.Checks) != 0 {
			t.Errorf("Checks should be hidden, got %v", response.Checks)
		}
	})

	t.Run("WithSecureDefaults", func(t *testing.T) {
		h := NewHandler(WithVersion("1.0.0"), WithSecureDefaults())
		h.Register("ping", &PingCheck{})

		response := h.Check(context.Background())

		if response.Version != "" {
			t.Error("Version should be hidden with secure defaults")
		}
		if response.Uptime != 0 {
			t.Error("Uptime should be hidden with secure defaults")
		}
		if len(response.Checks) != 0 {
			t.Error("Checks should be hidden with secure defaults")
		}
		// Status should still be visible
		if response.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", response.Status, StatusHealthy)
		}
	})
}

// =============================================================================
// Memory Check Tests
// =============================================================================

func TestMemoryCheck(t *testing.T) {
	t.Run("basic check", func(t *testing.T) {
		check := &MemoryCheck{}
		result := check.Check(context.Background())

		if result.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
		}

		// Should have metadata
		if result.Metadata == nil {
			t.Error("Metadata should not be nil")
		}
		if _, ok := result.Metadata["heap_alloc_bytes"]; !ok {
			t.Error("Metadata should contain heap_alloc_bytes")
		}
		if _, ok := result.Metadata["goroutines"]; !ok {
			t.Error("Metadata should contain goroutines")
		}
	})

	t.Run("with heap limit", func(t *testing.T) {
		// Set a very low limit that will fail
		check := &MemoryCheck{MaxHeapBytes: 1}
		result := check.Check(context.Background())

		if result.Status != StatusUnhealthy {
			t.Errorf("Status = %v, want %v (heap should exceed 1 byte)", result.Status, StatusUnhealthy)
		}
	})

	t.Run("with high heap limit", func(t *testing.T) {
		// Set a high limit that will pass
		check := &MemoryCheck{MaxHeapBytes: 1024 * 1024 * 1024} // 1GB
		result := check.Check(context.Background())

		if result.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
		}
	})
}

// =============================================================================
// Disk Check Tests
// =============================================================================

func TestDiskCheck(t *testing.T) {
	t.Run("basic check on root", func(t *testing.T) {
		check := &DiskCheck{Path: "/"}
		result := check.Check(context.Background())

		if result.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
		}

		// Should have metadata
		if result.Metadata == nil {
			t.Error("Metadata should not be nil")
		}
		if _, ok := result.Metadata["total_bytes"]; !ok {
			t.Error("Metadata should contain total_bytes")
		}
		if _, ok := result.Metadata["free_bytes"]; !ok {
			t.Error("Metadata should contain free_bytes")
		}
	})

	t.Run("default path", func(t *testing.T) {
		check := &DiskCheck{}
		result := check.Check(context.Background())

		// Should use / as default
		if result.Metadata["path"] != "/" {
			t.Errorf("Path = %v, want /", result.Metadata["path"])
		}
	})

	t.Run("with impossible free percent", func(t *testing.T) {
		// Require 100% free which is impossible
		check := &DiskCheck{Path: "/", MinFreePercent: 100}
		result := check.Check(context.Background())

		if result.Status != StatusUnhealthy {
			t.Errorf("Status = %v, want %v (can't have 100%% free)", result.Status, StatusUnhealthy)
		}
	})

	t.Run("with reasonable free percent", func(t *testing.T) {
		// Require only 1% free
		check := &DiskCheck{Path: "/", MinFreePercent: 1}
		result := check.Check(context.Background())

		if result.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		check := &DiskCheck{Path: "/nonexistent/path/that/does/not/exist"}
		result := check.Check(context.Background())

		if result.Status != StatusUnhealthy {
			t.Errorf("Status = %v, want %v for invalid path", result.Status, StatusUnhealthy)
		}
	})
}

// =============================================================================
// System Memory Check Tests
// =============================================================================

func TestSystemMemoryCheck(t *testing.T) {
	t.Run("basic check", func(t *testing.T) {
		check := &SystemMemoryCheck{}
		result := check.Check(context.Background())

		if result.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
		}

		// Should have metadata
		if result.Metadata == nil {
			t.Error("Metadata should not be nil")
		}
		if _, ok := result.Metadata["total_bytes"]; !ok {
			t.Error("Metadata should contain total_bytes")
		}
		if _, ok := result.Metadata["usage_percent"]; !ok {
			t.Error("Metadata should contain usage_percent")
		}
	})

	t.Run("with impossible usage limit", func(t *testing.T) {
		// Require less than 1% usage which is nearly impossible
		check := &SystemMemoryCheck{MaxUsagePercent: 0.001}
		result := check.Check(context.Background())

		if result.Status != StatusUnhealthy {
			t.Errorf("Status = %v, want %v (can't have < 0.001%% usage)", result.Status, StatusUnhealthy)
		}
	})

	t.Run("with reasonable usage limit", func(t *testing.T) {
		// Allow up to 99% usage
		check := &SystemMemoryCheck{MaxUsagePercent: 99}
		result := check.Check(context.Background())

		if result.Status != StatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, StatusHealthy)
		}
	})
}
