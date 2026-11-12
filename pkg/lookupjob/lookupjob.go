// Package lookupjob is the sensor side of lookup jobs: the platform, which
// makes no outbound request itself, asks a platform-owned (shared) sensor a
// passive question on behalf of one organization and gets a typed answer
// back. The first capability is lookup.ct@1 (contract package ctlookup).
//
// The sensor polls the platform for the next job, verifies its signed
// statement (command type lookup, the instance scope, this sensor, the job
// id, the payload exactly as received; the statement's tenant id is the
// organization the answer is for), checks the payload against its own
// rules, runs the capability's handler and reports the answer. A job that
// fails verification is reported refused and nothing is asked upstream.
//
// What bounds the sensor, whatever the platform asks:
//   - only a shared sensor with a pinned job-signing key or root runs a job;
//   - only the capabilities this sensor serves, each by its own tool;
//   - one target per job, which the handler checks against the input;
//   - an answer is bounded by the capability's contract before it is sent.
//
// Stability: Beta (docs/STABILITY.md).
package lookupjob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// Paths below the sensor API prefix (/api/v2/sensor).
const (
	NextPath = "/lookups/next"
	JobPath  = "/lookups/" // + {id}/done
)

// Limits.
const (
	// MaxJobBody caps the next-job response (payload and signed job).
	MaxJobBody = 64 << 10
	// MaxResultBody caps the done request.
	MaxResultBody = 9 << 20
	// MaxIDLength caps a job id.
	MaxIDLength = 64
)

// Job is what GET next returns.
type Job struct {
	ID        string          `json:"id"`
	Payload   json.RawMessage `json:"payload"`
	SignedJob json.RawMessage `json:"signed_job"`
}

// Payload is a job's signed payload. Scanner and Targets are what the
// statement names (the signer checked them); Capability picks the handler.
type Payload struct {
	Scanner    string          `json:"scanner"`
	Targets    []string        `json:"targets"`
	Capability string          `json:"capability"`
	Input      json.RawMessage `json:"input"`
}

// Result is the body of POST done: the answer, or why there is none.
type Result struct {
	Output json.RawMessage `json:"output,omitempty"`
	// Refused: the job was not run (bad signature, a capability this
	// sensor does not serve, a payload outside its rules).
	Refused string `json:"refused,omitempty"`
	// Error: the handler could not answer (a short code, never upstream
	// text).
	Error string `json:"error,omitempty"`
}

// Platform is the sensor's connection to the platform (pkg/client.Client).
type Platform interface {
	// NextLookup returns the next job, or nil and the platform's
	// Retry-After (0: none) when there is none.
	NextLookup(ctx context.Context) (*Job, time.Duration, error)
	// LookupDone reports a job's result.
	LookupDone(ctx context.Context, id string, r Result) error
}

// Verifier verifies a job's signed statement (core.JobGuard of a shared
// sensor).
type Verifier interface {
	VerifyLookup(ctx context.Context, jobID string, payload, signedJob []byte) (*jobsig.Statement, error)
}

// Handler answers one job of a capability for tenantID. target is the
// job's one target (the statement's, already verified); the handler checks
// that input asks about it. An error is reported as Result.Error.
type Handler func(ctx context.Context, tenantID, target string, input json.RawMessage) (any, error)

// Service is one capability this sensor serves.
type Service struct {
	// Tool is the tool name the payload must name (Payload.Scanner).
	Tool string
	// Run answers a job.
	Run Handler
	// Timeout bounds one job (default 100 s).
	Timeout time.Duration
}

// Config configures a Runner.
type Config struct {
	Platform Platform
	Verifier Verifier
	// Services by capability ("lookup.ct@1").
	Services map[string]Service
	// Interval between polls when there is no job (default 5 s).
	Interval time.Duration
	// Logf logs one line (nil: discarded).
	Logf func(format string, args ...any)
}

// Runner polls for jobs and serves them, one at a time.
type Runner struct{ cfg Config }

// New checks the configuration.
func New(cfg Config) (*Runner, error) {
	if cfg.Platform == nil || cfg.Verifier == nil {
		return nil, errors.New("lookupjob: a platform connection and a verifier are required")
	}
	if len(cfg.Services) == 0 {
		return nil, errors.New("lookupjob: no capability to serve")
	}
	for c, s := range cfg.Services {
		if s.Tool == "" || s.Run == nil {
			return nil, fmt.Errorf("lookupjob: capability %s needs a tool and a handler", c)
		}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Runner{cfg: cfg}, nil
}

// Poll bounds.
const (
	maxPoll     = 10 * time.Minute
	refusedPoll = 15 * time.Minute
)

type retryAfter interface{ RetryAfterHint() time.Duration }
type statusCoder interface{ HTTPStatusCode() int }

// Run polls until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		served, wait, err := r.runOnce(ctx)
		if err != nil && ctx.Err() == nil {
			r.cfg.Logf("lookup jobs: %v", err)
		}
		t.Reset(r.nextPoll(served, wait, err))
	}
}

// nextPoll: at once after a served job (more may be queued), else the
// platform's Retry-After, else the interval; a refused sensor waits long.
func (r *Runner) nextPoll(served bool, wait time.Duration, err error) time.Duration {
	var ra retryAfter
	var sc statusCoder
	switch {
	case errors.As(err, &ra) && ra.RetryAfterHint() > 0:
		wait = ra.RetryAfterHint()
	case errors.As(err, &sc) && sc.HTTPStatusCode() == http.StatusForbidden:
		wait = refusedPoll
	case err != nil:
		wait = r.cfg.Interval
	case served:
		return 0
	}
	if wait <= 0 {
		return r.cfg.Interval
	}
	return min(wait, maxPoll)
}

// RunOnce asks for one job and serves it; served reports whether a job was
// handled (answered, failed or refused).
func (r *Runner) RunOnce(ctx context.Context) (served bool, err error) {
	served, _, err = r.runOnce(ctx)
	return served, err
}

func (r *Runner) runOnce(ctx context.Context) (bool, time.Duration, error) {
	job, wait, err := r.cfg.Platform.NextLookup(ctx)
	if err != nil || job == nil {
		return false, wait, err
	}
	res := r.serve(ctx, job)
	if ctx.Err() != nil {
		return true, 0, ctx.Err()
	}
	return true, 0, r.cfg.Platform.LookupDone(ctx, job.ID, res)
}

func (r *Runner) serve(ctx context.Context, job *Job) Result {
	tenant, p, svc, err := r.admit(ctx, job)
	if err != nil {
		code := "refused"
		if reason := jobsig.ReasonOf(err); reason != "" {
			code = "signature_" + reason
		}
		r.cfg.Logf("lookup job %s refused: %v", clip(job.ID), err)
		return Result{Refused: code}
	}
	timeout := svc.Timeout
	if timeout <= 0 {
		timeout = 100 * time.Second
	}
	jctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ans, err := svc.Run(jctx, tenant, p.Targets[0], p.Input)
	if err != nil {
		r.cfg.Logf("lookup job %s (%s) failed: %v", clip(job.ID), p.Capability, err)
		code := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			code = "timeout"
		}
		return Result{Error: code}
	}
	b, err := json.Marshal(ans)
	if err != nil || len(b) > MaxResultBody-1024 {
		return Result{Error: "answer_too_large"}
	}
	return Result{Output: b}
}

// admit verifies the job's statement and checks its payload against the
// services this sensor runs. It returns the tenant id the answer is for.
func (r *Runner) admit(ctx context.Context, job *Job) (string, *Payload, Service, error) {
	if job.ID == "" || len(job.ID) > MaxIDLength {
		return "", nil, Service{}, errors.New("job id missing or too long")
	}
	st, err := r.cfg.Verifier.VerifyLookup(ctx, job.ID, job.Payload, job.SignedJob)
	if err != nil {
		return "", nil, Service{}, err
	}
	if st == nil || st.TenantID == "" || st.TenantID == jobsig.PlatformTenantID {
		return "", nil, Service{}, errors.New("the statement names no organization")
	}
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(job.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return "", nil, Service{}, fmt.Errorf("payload: %w", err)
	}
	svc, ok := r.cfg.Services[p.Capability]
	switch {
	case !ok:
		return "", nil, Service{}, fmt.Errorf("capability %q is not served by this sensor", clip(p.Capability))
	case p.Scanner != svc.Tool:
		return "", nil, Service{}, fmt.Errorf("capability %s runs tool %s, the payload names %q", p.Capability, svc.Tool, clip(p.Scanner))
	case len(p.Targets) != 1:
		return "", nil, Service{}, errors.New("a lookup job has exactly one target")
	}
	return st.TenantID, &p, svc, nil
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}
