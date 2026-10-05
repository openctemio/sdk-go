package tool

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrorClass categorizes an error, so the platform can tell a retry from a
// refusal from a broken tool.
type ErrorClass string

// Error classes a tool may return.
const (
	// InvalidInput: the configuration or targets are wrong; not retried.
	InvalidInput ErrorClass = "invalid_input"
	// TargetUnreachable: a target did not answer; retried on the next run.
	TargetUnreachable ErrorClass = "target_unreachable"
	// RefusedByPolicy: the scope or the local policy refused it; the job
	// goes back to the queue for another sensor.
	RefusedByPolicy ErrorClass = "refused_by_policy"
	// Transient: retry with back-off.
	Transient ErrorClass = "transient"
	// RateLimited: retry after RetryAfter.
	RateLimited ErrorClass = "rate_limited"
	// AuthFailed: a connector's credentials were refused.
	AuthFailed ErrorClass = "auth_failed"
	// PermissionDenied: the credentials lack a permission.
	PermissionDenied ErrorClass = "permission_denied"
	// NotFound: the resource does not exist.
	NotFound ErrorClass = "not_found"
	// ToolError: the tool failed; not retried by default. A plain error
	// returned from Run is a ToolError.
	ToolError ErrorClass = "tool_error"
)

// Error classes set by the runtime only; a tool that returns one gets
// ToolError instead.
const (
	Timeout           ErrorClass = "timeout"
	Canceled          ErrorClass = "canceled"
	ResourceExhausted ErrorClass = "resource_exhausted"
	OutputRejected    ErrorClass = "output_rejected"
	ToolCrashed       ErrorClass = "tool_crashed"
)

var toolClasses = map[ErrorClass]bool{
	InvalidInput: true, TargetUnreachable: true, RefusedByPolicy: true, Transient: true,
	RateLimited: true, AuthFailed: true, PermissionDenied: true, NotFound: true, ToolError: true,
}

var runtimeClasses = map[ErrorClass]bool{
	Timeout: true, Canceled: true, ResourceExhausted: true, OutputRejected: true, ToolCrashed: true,
}

// Valid reports whether c is a class a tool may return.
func (c ErrorClass) Valid() bool { return toolClasses[c] }

// RuntimeOnly reports whether c is set by the runtime only.
func (c ErrorClass) RuntimeOnly() bool { return runtimeClasses[c] }

// Retryable is the class's default retry verdict.
func (c ErrorClass) Retryable() bool {
	switch c {
	case TargetUnreachable, Transient, RateLimited, Timeout, ResourceExhausted, ToolCrashed:
		return true
	}
	return false
}

// MaxErrorDetail bounds Error.Detail on the wire.
const MaxErrorDetail = 256

// Error is a categorized tool error.
type Error struct {
	Class ErrorClass
	// Retryable defaults from Class; a tool may only turn it off.
	Retryable  bool
	RetryAfter time.Duration
	// Detail is a short, human description. The runtime redacts it and
	// caps it at MaxErrorDetail bytes before it leaves the sensor.
	Detail string
	// Err is the cause, for local logs only; it is never sent.
	Err error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(string(e.Class))
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Err != nil && (e.Detail == "" || !strings.Contains(e.Detail, e.Err.Error())) {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

func newError(c ErrorClass, detail string, err error) *Error {
	return &Error{Class: c, Retryable: c.Retryable(), Detail: detail, Err: err}
}

func detailOf(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Unreachable reports that a target did not answer (retried next run).
func Unreachable(err error) error { return newError(TargetUnreachable, detailOf(err), err) }

// Retry reports a transient failure (retried with back-off).
func Retry(err error) error { return newError(Transient, detailOf(err), err) }

// RateLimit reports that the far side asked to slow down.
func RateLimit(after time.Duration, err error) error {
	e := newError(RateLimited, detailOf(err), err)
	e.RetryAfter = after
	return e
}

// Refused reports a refusal by scope or policy.
func Refused(reason string) error { return newError(RefusedByPolicy, reason, nil) }

// Invalid reports invalid configuration or targets (not retried).
func Invalid(format string, args ...any) error {
	return newError(InvalidInput, fmt.Sprintf(format, args...), nil)
}

// AuthFailure reports refused credentials.
func AuthFailure(err error) error { return newError(AuthFailed, detailOf(err), err) }

// Failed reports that the tool itself failed (not retried by default).
func Failed(err error) error { return newError(ToolError, detailOf(err), err) }

// AsError returns err as an *Error: an *Error in its chain as it is (a
// runtime-only class claimed by a tool becomes ToolError), a context error
// as Canceled or Timeout, anything else as ToolError. nil stays nil.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var te *Error
	if errors.As(err, &te) {
		out := *te
		if !out.Class.Valid() {
			out.Class = ToolError
			out.Retryable = false
		}
		return &out
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return newError(Timeout, "deadline exceeded", err)
	case errors.Is(err, context.Canceled):
		return newError(Canceled, "canceled", err)
	}
	return newError(ToolError, err.Error(), err)
}

// ClassOf is AsError(err).Class ("" for nil).
func ClassOf(err error) ErrorClass {
	if e := AsError(err); e != nil {
		return e.Class
	}
	return ""
}

// CapDetail cuts s to MaxErrorDetail bytes on a rune boundary.
func CapDetail(s string) string {
	if len(s) <= MaxErrorDetail {
		return s
	}
	s = s[:MaxErrorDetail]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// Errors the emitter returns.
var (
	// ErrUndeclaredOutput: the record's kind is not in Manifest.Produces.
	// The record is quarantined (not delivered).
	ErrUndeclaredOutput = errors.New("undeclared output type")
	// ErrOutputLimit: the task reached Resources.MaxRecords or
	// MaxOutputBytes. The tool should stop; the task ends partial.
	ErrOutputLimit = errors.New("output limit reached")
	// ErrInvalidRecord: the record is not valid CTIS.
	ErrInvalidRecord = errors.New("invalid CTIS record")
	// ErrUndeclaredCredential: the tool asked for a credential its manifest
	// does not declare, or one the operator did not store.
	ErrUndeclaredCredential = errors.New("credential not declared or not granted")
)
