package core

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

func TestJobLedger(t *testing.T) {
	l := NewJobLedger()
	if _, err := l.Report(""); !errors.Is(err, ErrJobNotHeld) {
		t.Fatalf("unsolicited report: %v", err)
	}
	if err := l.Result("c1"); !errors.Is(err, ErrJobNotHeld) {
		t.Fatalf("result of a command not held: %v", err)
	}
	l.Hold("c1", "")
	if err := l.Result("c1"); err != nil {
		t.Fatalf("result of a held command: %v", err)
	}
	if _, err := l.Report("c1"); !errors.Is(err, ErrJobNotHeld) {
		t.Fatalf("report of a command with no organization: %v", err)
	}
	l.Hold("c2", jsTenant)
	if tenant, err := l.Report("c2"); err != nil || tenant != jsTenant {
		t.Fatalf("report: %q %v", tenant, err)
	}
	l.Release("c2")
	if _, err := l.Report("c2"); !errors.Is(err, ErrJobNotHeld) {
		t.Fatalf("report after release: %v", err)
	}
	var nilLedger *JobLedger
	if _, err := nilLedger.Report(""); err != nil {
		t.Fatal("a nil ledger refuses")
	}
}

// tenantExecutor records the job's organization as the executor sees it,
// and whether a report of the command would be accepted while it runs.
type tenantExecutor struct {
	mu     sync.Mutex
	l      *JobLedger
	tenant string
	report string
	ran    int
}

func (e *tenantExecutor) Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ran++
	e.tenant = JobTenantFromContext(ctx)
	e.report, _ = e.l.Report(cmd.ID)
	return &CommandExecutionResult{}, nil
}

func sharedPollerFixture(t *testing.T) (*jobSigner, *signedClient, *tenantExecutor, *CommandPoller, *JobLedger) {
	t.Helper()
	s := newJobSigner()
	keys, err := jobsig.NewKeys(s.pub())
	if err != nil {
		t.Fatal(err)
	}
	v, err := jobsig.NewVerifier(jobsig.Config{Keys: keys, StateFile: filepath.Join(t.TempDir(), "seq.json")})
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewSharedJobGuard(v, jsSensor)
	if err != nil {
		t.Fatal(err)
	}
	l := NewJobLedger()
	c := &signedClient{answers: map[string]*Command{}}
	e := &tenantExecutor{l: l}
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 2, AllowedTypes: []string{"scan"}, Ledger: l})
	p.SetJobGuard(g)
	return s, c, e, p, l
}

// SECURITY: a shared sensor runs an instance-scope job of any organization
// and binds its results to that organization while it holds the command;
// once the command ended, nothing more is accepted for it.
func TestSharedPollerBindsResultsToTheJobsTenant(t *testing.T) {
	const tenant = "aaaaaaaa-0000-4000-8000-0000000000aa" // not the sensor's (it has none)
	s, c, e, p, l := sharedPollerFixture(t)
	env := s.sign(t, jsCmd, 2, jsPayload, func(st *jobsig.Statement) {
		st.SensorScope, st.TenantID = jobsig.SensorScopeInstance, tenant
	})
	c.list = append(c.list, &Command{ID: jsCmd, Type: "scan", Payload: jsPayload, LeaseEpoch: 1})
	c.answers[jsCmd] = &Command{ID: jsCmd, Type: "scan", Payload: jsPayload, LeaseEpoch: 2, SignedJob: env}
	p.pollAndExecute(context.Background())
	p.activeCmds.Wait()
	if e.ran != 1 || e.tenant != tenant || e.report != tenant {
		t.Fatalf("ran %d, context tenant %q, report bound to %q; want 1, %q, %q (result %+v)", e.ran, e.tenant, e.report, tenant, tenant, c.results[jsCmd])
	}
	if r := c.results[jsCmd]; r == nil || r.Status != "completed" {
		t.Fatalf("result %+v", r)
	}
	if err := l.Result(jsCmd); !errors.Is(err, ErrJobNotHeld) {
		t.Fatalf("the command is still held after it ended: %v", err)
	}
}

// SECURITY: a shared sensor refuses, without running it, a job signed for
// an organization's sensor or not signed at all.
func TestSharedPollerRefusesOrganizationAndUnsignedJobs(t *testing.T) {
	for name, env := range map[string]func(s *jobSigner) []byte{
		"organization job": func(s *jobSigner) []byte { return s.sign(t, jsCmd, 2, jsPayload, nil) },
		"unsigned":         func(*jobSigner) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			s, c, e, p, _ := sharedPollerFixture(t)
			c.list = append(c.list, &Command{ID: jsCmd, Type: "scan", Payload: jsPayload, LeaseEpoch: 1})
			c.answers[jsCmd] = &Command{ID: jsCmd, Type: "scan", Payload: jsPayload, LeaseEpoch: 2, SignedJob: env(s)}
			p.pollAndExecute(context.Background())
			p.activeCmds.Wait()
			if e.ran != 0 {
				t.Fatal("the job ran")
			}
			if r := c.results[jsCmd]; r == nil || r.Status != "failed" || r.Refusal == nil || r.Refusal.Rule != RefusalRuleJobSignature {
				t.Fatalf("result %+v, want a job_signature refusal", r)
			}
		})
	}
}

func TestNewSharedJobGuard(t *testing.T) {
	if _, err := NewSharedJobGuard(nil, jsSensor); err == nil {
		t.Fatal("a shared guard without a pinned key")
	}
}
