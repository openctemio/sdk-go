package tool

import (
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// FailureClass maps the tool contract's error class to the failure class the
// sensor reports to the platform (core.ClassifyFailure reads it through
// core.FailureClassifier). The second value refines the class. A class the
// contract has no failure for (a plain tool error, a cancel) is "unknown".
func (e *Error) FailureClass() (class, reason string) {
	detail := strings.ToLower(e.Detail)
	// Attempts, Pressure and StartFailure are the runtime's own (a tool
	// cannot set them), so a tool cannot pass its failure off as the
	// host's.
	switch {
	case e.Pressure != "":
		// The start failed under host pressure, also after one more
		// attempt (research/318): a fact about the host.
		switch e.StartFailure {
		case "slow_start":
			return string(core.FailureHostPressure), core.ReasonSlowStart
		case "oom_kill":
			return string(core.FailureHostPressure), core.ReasonOOMHost
		case "start_eagain":
			return string(core.FailureHostPressure), core.ReasonStartEAGAIN
		}
		return string(core.FailureHostPressure), core.ReasonNoHandshake
	case e.StartFailure == "oom_kill", e.StartFailure == "oom_envelope":
		return string(core.FailureMemory), ""
	}
	switch e.Class {
	case ToolCrashed:
		switch {
		case strings.Contains(detail, "no handshake"), strings.Contains(detail, "first message"):
			return string(core.FailureToolCrashed), core.ReasonNoHandshake
		case strings.Contains(detail, "exited without a result"):
			return string(core.FailureToolCrashed), core.ReasonExitedWithoutResult
		case strings.Contains(detail, "protocol"):
			return string(core.FailureToolUnavailable), core.ReasonToolVersion
		}
		return string(core.FailureToolCrashed), ""
	case ResourceExhausted:
		if strings.Contains(detail, "output") {
			return string(core.FailureOutputLimit), core.ReasonOutputLimit
		}
		return string(core.FailureMemory), ""
	case Timeout:
		return string(core.FailureBudgetExceeded), ""
	case TargetUnreachable:
		return string(core.FailureTargetUnreachable), ""
	case RateLimited:
		return string(core.FailureTargetRateLimited), ""
	case Transient:
		return string(core.FailureTransient), ""
	case InvalidInput:
		return string(core.FailureConfigInvalid), ""
	case AuthFailed:
		return string(core.FailureConfigAuth), ""
	case PermissionDenied:
		return string(core.FailureConfigPermission), ""
	}
	return string(core.FailureUnknown), ""
}

// FailureStart is how many times the runtime started the task and the
// host's pressure level when it failed (core.ClassifyFailure puts them in
// the failure's evidence).
func (e *Error) FailureStart() (attempts int, pressure string) { return e.Attempts, e.Pressure }

// FailureRetryAfter is the tool's retry hint (core.ClassifyFailure sends it
// as a hint the platform may ignore).
func (e *Error) FailureRetryAfter() time.Duration { return e.RetryAfter }
