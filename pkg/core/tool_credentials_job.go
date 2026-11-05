package core

import (
	"context"
	"errors"
)

// Third-party source keys of a dispatched job: a tool whose manifest
// declares credentials (subfinder's passive sources, for one) may receive
// the keys the job's organization stored on the platform. The executor puts
// a fetch bound to the command on the job's context (WithToolCredentials);
// the tool host calls it once per task of such a tool, under the command's
// lease, merges the answer with the operator's stored credentials
// (MergeToolCredentials) and delivers only the names the manifest declares,
// inside the task's run message. Nothing is cached across tasks, nothing is
// logged, nothing reaches the job's payload, outbox or result.

// ToolCredentialSet is what the platform gave one task of a tool.
type ToolCredentialSet struct {
	// Values are the organization's credentials by the names the tool's
	// manifest declares.
	Values map[string]string
	// LocalFallback says whether the credentials the sensor's operator
	// stored may fill the names the organization left unset: true on the
	// organization's own sensor, false on a shared sensor, whose
	// operator's keys are never spent on an organization's task.
	LocalFallback bool
}

// JobToolCredentials fetches the credentials of a command's tool from the
// platform (client.ToolCredentials).
type JobToolCredentials interface {
	ToolCredentials(ctx context.Context, cmdID, tool string) (*ToolCredentialSet, error)
}

// ErrToolCredentialsUnsupported is the fetch's error when the platform does
// not deliver tool credentials (a platform older than the route): the task
// keeps the sensor's own credentials, as before.
var ErrToolCredentialsUnsupported = errors.New("the platform does not deliver tool credentials")

type toolCredentialsBox struct{ c JobToolCredentials }

// SetToolCredentials wires the fetch of a job's tool credentials; without
// it tools receive only the operator's stored credentials.
func (e *DefaultCommandExecutor) SetToolCredentials(c JobToolCredentials) {
	if c == nil {
		e.toolCreds.Store(nil)
		return
	}
	e.toolCreds.Store(&toolCredentialsBox{c: c})
}

// withJobToolCredentials puts the fetch of command cmdID on ctx, when the
// executor has one.
func (e *DefaultCommandExecutor) withJobToolCredentials(ctx context.Context, cmdID string) context.Context {
	box := e.toolCreds.Load()
	if box == nil || cmdID == "" {
		return ctx
	}
	return WithToolCredentials(ctx, func(ctx context.Context, tool string) (*ToolCredentialSet, error) {
		return box.c.ToolCredentials(ctx, cmdID, tool)
	})
}

// ToolCredentialsFetch fetches, for one task, the credentials of tool for
// the job it runs in.
type ToolCredentialsFetch func(ctx context.Context, tool string) (*ToolCredentialSet, error)

type toolCredentialsKey struct{}

// WithToolCredentials returns ctx carrying the job's credential fetch.
func WithToolCredentials(ctx context.Context, f ToolCredentialsFetch) context.Context {
	if f == nil {
		return ctx
	}
	return context.WithValue(ctx, toolCredentialsKey{}, f)
}

// ToolCredentialsFrom is the job's credential fetch on ctx (nil: the task
// is not part of a platform job).
func ToolCredentialsFrom(ctx context.Context) ToolCredentialsFetch {
	f, _ := ctx.Value(toolCredentialsKey{}).(ToolCredentialsFetch)
	return f
}

// MergeToolCredentials is one task's credentials, per name: the
// organization's value (job) wins; the operator's stored value (local)
// fills a name the organization left unset only when job allows it. A nil
// job (no platform job, or a platform that does not deliver credentials)
// keeps local as is.
func MergeToolCredentials(job *ToolCredentialSet, local map[string]string) map[string]string {
	if job == nil {
		return local
	}
	out := make(map[string]string, len(job.Values)+len(local))
	if job.LocalFallback {
		for k, v := range local {
			if v != "" {
				out[k] = v
			}
		}
	}
	for k, v := range job.Values {
		if v != "" {
			out[k] = v
		}
	}
	return out
}
