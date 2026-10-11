package adapt

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
)

// FailureReason classifies a network error toward a target as a failure
// signal (ReasonTimeout, ReasonRefused, ReasonReset), or "" when it says
// nothing about the target (the task was canceled, or the error is not a
// network one).
func FailureReason(err error) string {
	switch {
	case err == nil, errors.Is(err, context.Canceled):
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return ReasonRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, io.ErrUnexpectedEOF):
		return ReasonReset
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ReasonTimeout
	}
	return ""
}
