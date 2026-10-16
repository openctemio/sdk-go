package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrJobNotHeld is a result for a command this sensor does not hold (it
// never claimed it, or the command already ended), or a report with no
// command at all, refused by a JobLedger before anything is stored or sent.
var ErrJobNotHeld = errors.New("the sensor does not hold this job")

// JobLedger binds the results of a shared sensor (api RFC-100 §8) to the
// jobs it holds. The CommandPoller holds a command for as long as it runs it
// (its result included), with the organization its verified signed job
// names; the client asks the ledger before it stores or sends anything:
//
//   - a report (findings, assets) must belong to a held command whose
//     organization is known; it is tagged with that organization;
//   - a command result or log batch must belong to a held command;
//   - anything else (an unsolicited push, a result for a command already
//     finished or never claimed) is refused locally.
//
// The platform binds results to the command as well (it accepts a result
// only for a command the sensor holds under its lease); the ledger keeps a
// compromised or confused job on the sensor from even trying another
// organization's command.
type JobLedger struct {
	mu   sync.Mutex
	held map[string]string // command id -> organization ("" while unknown)
}

// NewJobLedger returns an empty ledger.
func NewJobLedger() *JobLedger { return &JobLedger{held: map[string]string{}} }

// Hold records that the sensor runs command id for organization tenant
// ("" when no verified job names one: its result may still be reported,
// never a report).
func (l *JobLedger) Hold(id, tenant string) {
	if l == nil || id == "" {
		return
	}
	l.mu.Lock()
	l.held[id] = tenant
	l.mu.Unlock()
}

// Release ends the hold of command id.
func (l *JobLedger) Release(id string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.held, id)
	l.mu.Unlock()
}

// Result checks a command result or log batch of command id.
func (l *JobLedger) Result(id string) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	_, ok := l.held[id]
	l.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: command %q", ErrJobNotHeld, id)
	}
	return nil
}

// Report checks a report of command id and returns the organization it
// belongs to.
func (l *JobLedger) Report(id string) (string, error) {
	if l == nil {
		return "", nil
	}
	if id == "" {
		return "", fmt.Errorf("%w: a report with no job (a shared sensor never pushes unsolicited results)", ErrJobNotHeld)
	}
	l.mu.Lock()
	tenant, ok := l.held[id]
	l.mu.Unlock()
	switch {
	case !ok:
		return "", fmt.Errorf("%w: command %q", ErrJobNotHeld, id)
	case tenant == "":
		return "", fmt.Errorf("%w: command %q names no organization", ErrJobNotHeld, id)
	}
	return tenant, nil
}

type jobTenantKey struct{}

// WithJobTenant returns a context that says the work under it belongs to
// organization tenant (a shared sensor's job: the tenant its verified
// signed job names).
func WithJobTenant(ctx context.Context, tenant string) context.Context {
	if tenant == "" {
		return ctx
	}
	return context.WithValue(ctx, jobTenantKey{}, tenant)
}

// JobTenantFromContext returns the organization set by WithJobTenant, or "".
func JobTenantFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	t, _ := ctx.Value(jobTenantKey{}).(string)
	return t
}
