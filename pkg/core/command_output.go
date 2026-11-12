package core

import (
	"context"
	"encoding/json"
	"fmt"
)

// MaxCommandOutputBytes caps a command's typed output
// (CommandExecutionResult.Output). A larger output fails the command with
// ErrorCodeOutputTooLarge.
const MaxCommandOutputBytes = 256 << 10

// Error codes of a command whose typed output cannot be reported.
const (
	// ErrorCodeOutputTooLarge: the output is over MaxCommandOutputBytes.
	ErrorCodeOutputTooLarge = "output_too_large"
	// ErrorCodeOutputInvalid: the output is not one JSON value.
	ErrorCodeOutputInvalid = "output_invalid"
)

// commandOutput returns the typed output as it is reported: out in the
// form encoding/json writes a json.RawMessage (no whitespace between
// tokens; <, > and & as <, > and &). Every later encoding
// of the result (the complete body, the outbox, its replay) leaves these
// bytes as they are; key order, number formats and string escapes are the
// handler's own. It fails with ErrorCodeOutputInvalid or
// ErrorCodeOutputTooLarge.
func commandOutput(out json.RawMessage) (json.RawMessage, string, error) {
	if len(out) == 0 {
		return nil, "", nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, ErrorCodeOutputInvalid, fmt.Errorf("the command's output is not valid JSON: %w", err)
	}
	if len(b) > MaxCommandOutputBytes {
		return nil, ErrorCodeOutputTooLarge, fmt.Errorf("the command's output is %d bytes, over the %d-byte limit", len(b), MaxCommandOutputBytes)
	}
	return b, "", nil
}

// setCommandOutput puts a completed command's typed output on its result,
// or fails the command when the output cannot be reported.
func setCommandOutput(r *CommandResult, out json.RawMessage) {
	b, code, err := commandOutput(out)
	if err != nil {
		r.Status = "failed"
		r.Error = err.Error()
		r.ErrorCode = code
		return
	}
	r.Output = b
}

type jobVerifiedKey struct{}

// withJobVerified returns a context that says the command under it came
// with a signed job the JobGuard verified.
func withJobVerified(ctx context.Context, verified bool) context.Context {
	if !verified {
		return ctx
	}
	return context.WithValue(ctx, jobVerifiedKey{}, true)
}

// JobVerifiedFromContext reports whether the command an executor runs
// under ctx came with a signed job that the JobGuard verified against a
// pinned key (type, organization, sensor, command, lease and payload). It
// is false for an unsigned command, and on a sensor without pinned keys.
// A handler that must run only verified jobs checks it first.
func JobVerifiedFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(jobVerifiedKey{}).(bool)
	return v
}
