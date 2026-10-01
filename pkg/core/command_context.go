package core

import "context"

type commandIDKey struct{}

// WithCommandID returns a context that says the work done under it belongs to
// the platform command cmdID. The CommandPoller sets it around every command,
// so a Pusher can bind the results it pushes to that command (protocol v2's
// command-bound resource) and report the command only after them.
func WithCommandID(ctx context.Context, cmdID string) context.Context {
	if cmdID == "" {
		return ctx
	}
	return context.WithValue(ctx, commandIDKey{}, cmdID)
}

// CommandIDFromContext returns the command id set by WithCommandID, or "".
func CommandIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(commandIDKey{}).(string)
	return id
}
