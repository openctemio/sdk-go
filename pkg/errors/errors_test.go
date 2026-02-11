// Package errors provides custom error types for the OpenCTEM SDK.
package errors

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestKind_String(t *testing.T) {
	tests := []struct {
		kind     Kind
		expected string
	}{
		{KindUnknown, "unknown"},
		{KindInvalidInput, "invalid_input"},
		{KindAuthentication, "authentication"},
		{KindAuthorization, "authorization"},
		{KindNotFound, "not_found"},
		{KindConflict, "conflict"},
		{KindRateLimit, "rate_limit"},
		{KindTimeout, "timeout"},
		{KindNetwork, "network"},
		{KindServer, "server"},
		{KindInternal, "internal"},
		{Kind(99), "unknown"}, // Invalid kind
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.expected {
				t.Errorf("Kind.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name:     "op and message and err",
			err:      &Error{Op: "client.PushFindings", Message: "push failed", Err: fmt.Errorf("connection refused")},
			expected: "client.PushFindings: push failed: connection refused",
		},
		{
			name:     "op and message",
			err:      &Error{Op: "client.PushFindings", Message: "push failed"},
			expected: "client.PushFindings: push failed",
		},
		{
			name:     "message and err",
			err:      &Error{Message: "push failed", Err: fmt.Errorf("connection refused")},
			expected: "push failed: connection refused",
		},
		{
			name:     "message only",
			err:      &Error{Message: "push failed"},
			expected: "push failed",
		},
		{
			name:     "empty error",
			err:      &Error{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	underlying := fmt.Errorf("underlying error")
	err := &Error{Message: "wrapper", Err: underlying}

	unwrapped := err.Unwrap()
	if unwrapped != underlying {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, underlying)
	}

	// Test with nil Err
	err2 := &Error{Message: "no underlying"}
	if err2.Unwrap() != nil {
		t.Errorf("Unwrap() should return nil for error without underlying")
	}
}

func TestError_Is(t *testing.T) {
	err1 := &Error{Kind: KindAuthentication, Message: "auth failed"}
	err2 := &Error{Kind: KindAuthentication, Message: "different message"}
	err3 := &Error{Kind: KindAuthorization, Message: "auth failed"}

	// Same kind should match
	if !err1.Is(err2) {
		t.Error("Errors with same Kind should match")
	}

	// Different kind should not match
	if err1.Is(err3) {
		t.Error("Errors with different Kind should not match")
	}

	// Non-Error type should not match
	if err1.Is(fmt.Errorf("some error")) {
		t.Error("Should not match non-Error type")
	}
}

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		contains string
	}{
		{
			name: "with request ID",
			err: &APIError{
				StatusCode: 401,
				Code:       "UNAUTHORIZED",
				Message:    "Invalid API key",
				RequestID:  "req-123",
			},
			contains: "request_id: req-123",
		},
		{
			name: "without request ID",
			err: &APIError{
				StatusCode: 400,
				Code:       "BAD_REQUEST",
				Message:    "Invalid input",
			},
			contains: "BAD_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if len(got) == 0 {
				t.Error("Error() should not return empty string")
			}
			// Check that error string contains expected parts
			if !containsString(got, tt.contains) {
				t.Errorf("Error() = %q, should contain %q", got, tt.contains)
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestE_Constructor(t *testing.T) {
	// Test with Kind
	err := E(KindAuthentication)
	if e, ok := err.(*Error); ok {
		if e.Kind != KindAuthentication {
			t.Errorf("E(Kind) should set Kind, got %v", e.Kind)
		}
	} else {
		t.Error("E() should return *Error")
	}

	// Test with string (Op first, then Message)
	err = E("client.Push", "failed to push")
	if e, ok := err.(*Error); ok {
		if e.Op != "client.Push" {
			t.Errorf("E(string) should set Op first, got %q", e.Op)
		}
		if e.Message != "failed to push" {
			t.Errorf("E(string, string) should set Message second, got %q", e.Message)
		}
	}

	// Test with error
	underlying := fmt.Errorf("underlying")
	err = E(underlying)
	if e, ok := err.(*Error); ok {
		if e.Err != underlying {
			t.Error("E(error) should set Err")
		}
	}

	// Test with multiple args
	err = E(KindNetwork, "client.Connect", "connection failed", underlying)
	if e, ok := err.(*Error); ok {
		if e.Kind != KindNetwork {
			t.Errorf("Kind = %v, want KindNetwork", e.Kind)
		}
		if e.Op != "client.Connect" {
			t.Errorf("Op = %q, want 'client.Connect'", e.Op)
		}
		if e.Message != "connection failed" {
			t.Errorf("Message = %q, want 'connection failed'", e.Message)
		}
		if e.Err != underlying {
			t.Error("Err should be set")
		}
	}
}

func TestNew(t *testing.T) {
	err := New("simple error")
	if e, ok := err.(*Error); ok {
		if e.Message != "simple error" {
			t.Errorf("New() should set Message, got %q", e.Message)
		}
	} else {
		t.Error("New() should return *Error")
	}
}

func TestWrap(t *testing.T) {
	underlying := fmt.Errorf("underlying error")

	// Normal case
	wrapped := Wrap(underlying, "client.Push")
	if e, ok := wrapped.(*Error); ok {
		if e.Op != "client.Push" {
			t.Errorf("Wrap() should set Op, got %q", e.Op)
		}
		if e.Err != underlying {
			t.Error("Wrap() should set Err")
		}
	}

	// Nil case
	if Wrap(nil, "op") != nil {
		t.Error("Wrap(nil, op) should return nil")
	}
}

func TestWrapWithMessage(t *testing.T) {
	underlying := fmt.Errorf("underlying error")

	wrapped := WrapWithMessage(underlying, "custom message")
	if e, ok := wrapped.(*Error); ok {
		if e.Message != "custom message" {
			t.Errorf("WrapWithMessage() should set Message, got %q", e.Message)
		}
		if e.Err != underlying {
			t.Error("WrapWithMessage() should set Err")
		}
	}

	// Nil case
	if WrapWithMessage(nil, "msg") != nil {
		t.Error("WrapWithMessage(nil, msg) should return nil")
	}
}

func TestGetKind(t *testing.T) {
	// From *Error
	err := &Error{Kind: KindRateLimit}
	if kind := GetKind(err); kind != KindRateLimit {
		t.Errorf("GetKind() = %v, want KindRateLimit", kind)
	}

	// From wrapped error
	wrapped := fmt.Errorf("wrapper: %w", err)
	if kind := GetKind(wrapped); kind != KindRateLimit {
		t.Errorf("GetKind() from wrapped = %v, want KindRateLimit", kind)
	}

	// From non-Error
	if kind := GetKind(fmt.Errorf("plain error")); kind != KindUnknown {
		t.Errorf("GetKind() from plain error = %v, want KindUnknown", kind)
	}
}

func TestIsAPIError(t *testing.T) {
	apiErr := &APIError{StatusCode: 400, Code: "BAD_REQUEST", Message: "Invalid"}

	// Direct APIError
	if got, ok := IsAPIError(apiErr); !ok || got != apiErr {
		t.Error("IsAPIError should recognize *APIError")
	}

	// Wrapped APIError
	wrapped := fmt.Errorf("wrapper: %w", apiErr)
	if got, ok := IsAPIError(wrapped); !ok || got != apiErr {
		t.Error("IsAPIError should recognize wrapped *APIError")
	}

	// Non-APIError
	if _, ok := IsAPIError(fmt.Errorf("plain error")); ok {
		t.Error("IsAPIError should return false for non-APIError")
	}
}

func TestIsRateLimitError(t *testing.T) {
	// From Kind
	err := &Error{Kind: KindRateLimit}
	if !IsRateLimitError(err) {
		t.Error("Should recognize KindRateLimit")
	}

	// From APIError with 429
	apiErr := &APIError{StatusCode: http.StatusTooManyRequests}
	if !IsRateLimitError(apiErr) {
		t.Error("Should recognize 429 status")
	}

	// Not rate limit
	if IsRateLimitError(fmt.Errorf("plain error")) {
		t.Error("Should not match plain error")
	}
}

func TestIsAuthenticationError(t *testing.T) {
	// From Kind
	err := &Error{Kind: KindAuthentication}
	if !IsAuthenticationError(err) {
		t.Error("Should recognize KindAuthentication")
	}

	// From APIError with 401
	apiErr := &APIError{StatusCode: http.StatusUnauthorized}
	if !IsAuthenticationError(apiErr) {
		t.Error("Should recognize 401 status")
	}

	// Not authentication error
	if IsAuthenticationError(fmt.Errorf("plain error")) {
		t.Error("Should not match plain error")
	}
}

func TestIsAuthorizationError(t *testing.T) {
	// From Kind
	err := &Error{Kind: KindAuthorization}
	if !IsAuthorizationError(err) {
		t.Error("Should recognize KindAuthorization")
	}

	// From APIError with 403
	apiErr := &APIError{StatusCode: http.StatusForbidden}
	if !IsAuthorizationError(apiErr) {
		t.Error("Should recognize 403 status")
	}
}

func TestIsNotFoundError(t *testing.T) {
	// From Kind
	err := &Error{Kind: KindNotFound}
	if !IsNotFoundError(err) {
		t.Error("Should recognize KindNotFound")
	}

	// From APIError with 404
	apiErr := &APIError{StatusCode: http.StatusNotFound}
	if !IsNotFoundError(apiErr) {
		t.Error("Should recognize 404 status")
	}
}

func TestIsNetworkError(t *testing.T) {
	err := &Error{Kind: KindNetwork}
	if !IsNetworkError(err) {
		t.Error("Should recognize KindNetwork")
	}

	if IsNetworkError(&Error{Kind: KindTimeout}) {
		t.Error("Should not match non-network error")
	}
}

func TestIsTimeoutError(t *testing.T) {
	err := &Error{Kind: KindTimeout}
	if !IsTimeoutError(err) {
		t.Error("Should recognize KindTimeout")
	}

	if IsTimeoutError(&Error{Kind: KindNetwork}) {
		t.Error("Should not match non-timeout error")
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{"rate limit", &Error{Kind: KindRateLimit}, true},
		{"network", &Error{Kind: KindNetwork}, true},
		{"timeout", &Error{Kind: KindTimeout}, true},
		{"500 server error", &APIError{StatusCode: 500}, true},
		{"502 bad gateway", &APIError{StatusCode: 502}, true},
		{"503 service unavailable", &APIError{StatusCode: 503}, true},
		{"504 gateway timeout", &APIError{StatusCode: 504}, true},
		{"501 not implemented", &APIError{StatusCode: 501}, false}, // Not retryable
		{"400 bad request", &APIError{StatusCode: 400}, false},
		{"401 unauthorized", &APIError{StatusCode: 401}, false},
		{"403 forbidden", &APIError{StatusCode: 403}, false},
		{"404 not found", &APIError{StatusCode: 404}, false},
		{"authentication error", &Error{Kind: KindAuthentication}, false},
		{"authorization error", &Error{Kind: KindAuthorization}, false},
		{"invalid input", &Error{Kind: KindInvalidInput}, false},
		{"plain error", fmt.Errorf("some error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.retryable {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.retryable)
			}
		})
	}
}

func TestCommonErrors(t *testing.T) {
	// Test that common errors have correct kinds
	tests := []struct {
		name string
		err  *Error
		kind Kind
	}{
		{"ErrNotConnected", ErrNotConnected, KindNetwork},
		{"ErrTimeout", ErrTimeout, KindTimeout},
		{"ErrRateLimited", ErrRateLimited, KindRateLimit},
		{"ErrInvalidConfig", ErrInvalidConfig, KindInvalidInput},
		{"ErrMissingAPIKey", ErrMissingAPIKey, KindAuthentication},
		{"ErrMissingAgentID", ErrMissingAgentID, KindInvalidInput},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Kind != tt.kind {
				t.Errorf("%s.Kind = %v, want %v", tt.name, tt.err.Kind, tt.kind)
			}
		})
	}
}

func TestErrorChaining(t *testing.T) {
	// Test that errors can be chained with standard library
	base := fmt.Errorf("base error")
	wrapped := &Error{Kind: KindNetwork, Message: "network failure", Err: base}

	// Test errors.Is with standard error
	if !errors.Is(wrapped, base) {
		t.Error("errors.Is should find base error through Unwrap")
	}

	// Test errors.As
	var sdkErr *Error
	if !errors.As(wrapped, &sdkErr) {
		t.Error("errors.As should find *Error")
	}
	if sdkErr.Kind != KindNetwork {
		t.Error("errors.As should return the correct error")
	}
}

// Benchmark tests
func BenchmarkE(b *testing.B) {
	underlying := fmt.Errorf("underlying")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = E(KindNetwork, "op", "message", underlying)
	}
}

func BenchmarkIsRetryable(b *testing.B) {
	err := &APIError{StatusCode: 503}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsRetryable(err)
	}
}

func BenchmarkGetKind(b *testing.B) {
	err := &Error{Kind: KindRateLimit}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetKind(err)
	}
}
