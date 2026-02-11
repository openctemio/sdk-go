// Package errors provides custom error types for the OpenCTEM SDK.
// It follows industry best practices (HashiCorp, AWS SDK) for error handling.
package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// =============================================================================
// Base Error Types
// =============================================================================

// Error is the base error type for all SDK errors.
type Error struct {
	// Kind indicates the category of error
	Kind Kind

	// Op is the operation being performed (e.g., "client.PushFindings")
	Op string

	// Message is a human-readable description
	Message string

	// Err is the underlying error
	Err error
}

// Kind represents the kind/category of error.
type Kind uint8

const (
	KindUnknown Kind = iota
	KindInvalidInput
	KindAuthentication
	KindAuthorization
	KindNotFound
	KindConflict
	KindRateLimit
	KindTimeout
	KindNetwork
	KindServer
	KindInternal
)

func (k Kind) String() string {
	switch k {
	case KindInvalidInput:
		return "invalid_input"
	case KindAuthentication:
		return "authentication"
	case KindAuthorization:
		return "authorization"
	case KindNotFound:
		return "not_found"
	case KindConflict:
		return "conflict"
	case KindRateLimit:
		return "rate_limit"
	case KindTimeout:
		return "timeout"
	case KindNetwork:
		return "network"
	case KindServer:
		return "server"
	case KindInternal:
		return "internal"
	default:
		return "unknown"
	}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Op != "" {
		if e.Err != nil {
			return fmt.Sprintf("%s: %s: %v", e.Op, e.Message, e.Err)
		}
		return fmt.Sprintf("%s: %s", e.Op, e.Message)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Err
}

// Is reports whether the error matches the target.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// =============================================================================
// API Error
// =============================================================================

// APIError represents an error returned by the OpenCTEM API.
type APIError struct {
	// StatusCode is the HTTP status code
	StatusCode int `json:"status_code"`

	// Code is an API-specific error code
	Code string `json:"code"`

	// Message is the error message from the API
	Message string `json:"message"`

	// RequestID is the request ID for debugging
	RequestID string `json:"request_id,omitempty"`

	// Details contains additional error context
	Details map[string]any `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("[%s] %s: %s (request_id: %s)", e.Code, http.StatusText(e.StatusCode), e.Message, e.RequestID)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Code, http.StatusText(e.StatusCode), e.Message)
}

// =============================================================================
// Constructors
// =============================================================================

// E constructs an Error from the given arguments.
// Arguments can be: Kind, string (Op or Message), error.
func E(args ...interface{}) error {
	e := &Error{}
	for _, arg := range args {
		switch a := arg.(type) {
		case Kind:
			e.Kind = a
		case string:
			if e.Op == "" {
				e.Op = a
			} else {
				e.Message = a
			}
		case error:
			e.Err = a
		}
	}
	return e
}

// New creates a new simple error.
func New(message string) error {
	return &Error{Message: message}
}

// Wrap wraps an error with additional context.
func Wrap(err error, op string) error {
	if err == nil {
		return nil
	}
	return &Error{Op: op, Err: err}
}

// WrapWithMessage wraps an error with a message.
func WrapWithMessage(err error, message string) error {
	if err == nil {
		return nil
	}
	return &Error{Message: message, Err: err}
}

// =============================================================================
// Error Checkers
// =============================================================================

// GetKind returns the Kind of the error, or KindUnknown.
func GetKind(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindUnknown
}

// IsAPIError checks if err is an APIError and returns it.
func IsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// IsRateLimitError checks if the error is a rate limit error.
func IsRateLimitError(err error) bool {
	// Check Kind
	if GetKind(err) == KindRateLimit {
		return true
	}
	// Check APIError
	if apiErr, ok := IsAPIError(err); ok {
		return apiErr.StatusCode == http.StatusTooManyRequests
	}
	return false
}

// IsAuthenticationError checks if the error is an authentication error.
func IsAuthenticationError(err error) bool {
	if GetKind(err) == KindAuthentication {
		return true
	}
	if apiErr, ok := IsAPIError(err); ok {
		return apiErr.StatusCode == http.StatusUnauthorized
	}
	return false
}

// IsAuthorizationError checks if the error is an authorization error.
func IsAuthorizationError(err error) bool {
	if GetKind(err) == KindAuthorization {
		return true
	}
	if apiErr, ok := IsAPIError(err); ok {
		return apiErr.StatusCode == http.StatusForbidden
	}
	return false
}

// IsNotFoundError checks if the error is a not found error.
func IsNotFoundError(err error) bool {
	if GetKind(err) == KindNotFound {
		return true
	}
	if apiErr, ok := IsAPIError(err); ok {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// IsNetworkError checks if the error is a network error.
func IsNetworkError(err error) bool {
	return GetKind(err) == KindNetwork
}

// IsTimeoutError checks if the error is a timeout error.
func IsTimeoutError(err error) bool {
	return GetKind(err) == KindTimeout
}

// IsRetryable checks if the error is retryable.
func IsRetryable(err error) bool {
	if IsRateLimitError(err) || IsNetworkError(err) || IsTimeoutError(err) {
		return true
	}
	if apiErr, ok := IsAPIError(err); ok {
		// Retry on 5xx errors (except 501 Not Implemented)
		return apiErr.StatusCode >= 500 && apiErr.StatusCode != 501
	}
	return false
}

// =============================================================================
// Common Errors
// =============================================================================

var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = &Error{Kind: KindNetwork, Message: "not connected"}

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = &Error{Kind: KindTimeout, Message: "operation timed out"}

	// ErrRateLimited is returned when rate limited.
	ErrRateLimited = &Error{Kind: KindRateLimit, Message: "rate limited"}

	// ErrInvalidConfig is returned for invalid configuration.
	ErrInvalidConfig = &Error{Kind: KindInvalidInput, Message: "invalid configuration"}

	// ErrMissingAPIKey is returned when API key is missing.
	ErrMissingAPIKey = &Error{Kind: KindAuthentication, Message: "API key is required"}

	// ErrMissingAgentID is returned when agent ID is missing.
	ErrMissingAgentID = &Error{Kind: KindInvalidInput, Message: "agent ID is required"}
)
