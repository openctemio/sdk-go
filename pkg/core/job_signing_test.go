package core

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

const (
	jsTenant = "aaaaaaaa-0000-4000-8000-000000000001"
	jsSensor = "bbbbbbbb-0000-4000-8000-000000000002"
	jsCmd    = "cccccccc-0000-4000-8000-000000000003"
)

var jsPayload = json.RawMessage(`{"scanner":"nuclei","targets":["203.0.113.10"]}`)

// jobSigner signs statements the way the platform's signer does.
type jobSigner struct {
	priv ed25519.PrivateKey
	seq  uint64
}

func newJobSigner() *jobSigner {
	return &jobSigner{priv: ed25519.NewKeyFromSeed(make([]byte, 32))}
}

func (s *jobSigner) pub() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

func (s *jobSigner) sign(t *testing.T, cmdID string, epoch int, payload []byte, mutate func(*jobsig.Statement)) json.RawMessage {
	t.Helper()
	s.seq++
	nonce := make([]byte, jobsig.NonceBytes)
	nonce[0] = byte(s.seq)
	now := time.Now().UTC().Truncate(time.Second)
	st := jobsig.Statement{Kind: jobsig.Kind, TenantID: jsTenant, SensorID: jsSensor, CommandID: cmdID,
		CommandType: "scan", Tool: jobsig.PayloadTool(payload), PayloadSHA256: jobsig.PayloadDigest(payload),
		Targets: jobsig.PayloadTargets(payload), LeaseEpoch: epoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		Seq: s.seq, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Signer: &jobsig.SignerRef{KeyID: jobsig.KeyID(s.pub())}}
	if mutate != nil {
		mutate(&st)
	}
	p, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(jobsig.Envelope{PayloadType: jobsig.PayloadType, Payload: p,
		Signatures: []jobsig.Signature{{KeyID: jobsig.KeyID(s.pub()), Sig: ed25519.Sign(s.priv, jobsig.PreAuthEncoding(jobsig.PayloadType, p))}}})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// signedClient is a platform whose listing poll carries no signed job and
// whose claim answers the command with one (protocol v2 without claim-N).
type signedClient struct {
	mu      sync.Mutex
	list    []*Command
	answers map[string]*Command // claim answers
	acks    []string
	started []string
	results map[string]*CommandResult
}

func (c *signedClient) GetCommands(context.Context) (*GetCommandsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.list
	c.list = nil
	return &GetCommandsResponse{Commands: out}, nil
}

func (c *signedClient) AcknowledgeCommand(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acks = append(c.acks, id)
	return nil
}

func (c *signedClient) ClaimCommand(_ context.Context, id string) (*Command, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acks = append(c.acks, id)
	a, ok := c.answers[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *a
	return &cp, nil
}

func (c *signedClient) StartCommand(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started = append(c.started, id)
	return nil
}

func (c *signedClient) ReportCommandResult(_ context.Context, id string, r *CommandResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.results == nil {
		c.results = map[string]*CommandResult{}
	}
	c.results[id] = r
	return nil
}

func (c *signedClient) ReportCommandProgress(context.Context, string, int, string) error { return nil }

// spyExecutor records the commands it ran and, at each run, the sequence
// number the verifier had accepted by then.
type spyExecutor struct {
	mu      sync.Mutex
	ran     []*Command
	seqSeen []uint64
	v       *jobsig.Verifier
	keyID   string
}

func (e *spyExecutor) Execute(_ context.Context, cmd *Command) (*CommandExecutionResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := *cmd
	e.ran = append(e.ran, &cp)
	if e.v != nil {
		e.seqSeen = append(e.seqSeen, e.v.LastSeq(e.keyID))
	}
	return &CommandExecutionResult{}, nil
}

type jobPollerFixture struct {
	signer *jobSigner
	client *signedClient
	exec   *spyExecutor
	poller *CommandPoller
	v      *jobsig.Verifier
}

func newJobPollerFixture(t *testing.T, required bool, pinned bool) *jobPollerFixture {
	t.Helper()
	f := &jobPollerFixture{signer: newJobSigner(), client: &signedClient{answers: map[string]*Command{}}}
	if pinned {
		keys, err := jobsig.NewKeys(f.signer.pub())
		if err != nil {
			t.Fatal(err)
		}
		f.v, err = jobsig.NewVerifier(jobsig.Config{Keys: keys, StateFile: filepath.Join(t.TempDir(), "seq.json")})
		if err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewJobGuard(f.v, required, jsTenant, jsSensor)
	if err != nil {
		t.Fatal(err)
	}
	f.exec = &spyExecutor{v: f.v, keyID: jobsig.KeyID(f.signer.pub())}
	f.poller = NewCommandPoller(f.client, f.exec, &CommandPollerConfig{MaxConcurrent: 2, AllowedTypes: []string{"scan"}})
	f.poller.SetJobGuard(g)
	return f
}

// offer lists cmdID (epoch 1 on the listing) and answers its claim with
// epoch 2 and env.
func (f *jobPollerFixture) offer(cmdID string, payload json.RawMessage, env json.RawMessage) {
	f.client.list = append(f.client.list, &Command{ID: cmdID, Type: "scan", Payload: payload, LeaseEpoch: 1})
	f.client.answers[cmdID] = &Command{ID: cmdID, Type: "scan", Payload: payload, LeaseEpoch: 2, SignedJob: env}
}

func (f *jobPollerFixture) run() {
	f.poller.pollAndExecute(context.Background())
	f.poller.activeCmds.Wait()
}

func (f *jobPollerFixture) refusal(t *testing.T, id string) *CommandResult {
	t.Helper()
	r := f.client.results[id]
	if r == nil {
		t.Fatalf("no result for %s", id)
	}
	if r.Status != "failed" || r.Refusal == nil || r.Refusal.Rule != RefusalRuleJobSignature || r.Refusal.Layer != RefusalLayerBuiltin {
		t.Fatalf("result = %+v (refusal %+v), want a job_signature refusal", r, r.Refusal)
	}
	return r
}

func TestPollerRunsAVerifiedJobWithTheClaimAnswer(t *testing.T) {
	f := newJobPollerFixture(t, true, true)
	f.offer(jsCmd, jsPayload, f.signer.sign(t, jsCmd, 2, jsPayload, nil))
	f.run()
	if len(f.exec.ran) != 1 {
		t.Fatalf("executor ran %d commands, want 1 (result %+v)", len(f.exec.ran), f.client.results[jsCmd])
	}
	// Verified (and its sequence number recorded) before the executor saw it.
	if f.exec.seqSeen[0] != 1 {
		t.Fatalf("executor ran before the job was accepted (seq seen %d)", f.exec.seqSeen[0])
	}
	if got := f.exec.ran[0]; got.LeaseEpoch != 2 || string(got.Payload) != string(jsPayload) {
		t.Fatalf("executor got %+v, want the claim answer", got)
	}
	if r := f.client.results[jsCmd]; r == nil || r.Status != "completed" {
		t.Fatalf("result = %+v", r)
	}
}

func TestPollerRefusesBadJobSignaturesBeforeStart(t *testing.T) {
	cases := map[string]func(f *jobPollerFixture) json.RawMessage{
		"tampered payload": func(f *jobPollerFixture) json.RawMessage {
			env := f.signer.sign(t, jsCmd, 2, jsPayload, nil)
			f.offer(jsCmd, json.RawMessage(`{"scanner":"nuclei","targets":["198.51.100.1"]}`), env)
			return env
		},
		"other sensor": func(f *jobPollerFixture) json.RawMessage {
			return f.signer.sign(t, jsCmd, 2, jsPayload, func(st *jobsig.Statement) { st.SensorID = "bbbbbbbb-0000-4000-8000-0000000000ff" })
		},
		"other tenant": func(f *jobPollerFixture) json.RawMessage {
			return f.signer.sign(t, jsCmd, 2, jsPayload, func(st *jobsig.Statement) { st.TenantID = "aaaaaaaa-0000-4000-8000-0000000000ff" })
		},
		"other command": func(f *jobPollerFixture) json.RawMessage {
			return f.signer.sign(t, "cccccccc-0000-4000-8000-0000000000ff", 2, jsPayload, nil)
		},
		"lease epoch of the listing": func(f *jobPollerFixture) json.RawMessage {
			return f.signer.sign(t, jsCmd, 1, jsPayload, nil)
		},
		"expired": func(f *jobPollerFixture) json.RawMessage {
			return f.signer.sign(t, jsCmd, 2, jsPayload, func(st *jobsig.Statement) {
				st.IssuedAt = time.Now().Add(-time.Minute)
				st.ExpiresAt = time.Now().Add(-time.Second)
			})
		},
		"untrusted signer": func(f *jobPollerFixture) json.RawMessage {
			f.signer.priv = ed25519.NewKeyFromSeed(append([]byte{1}, make([]byte, 31)...))
			return f.signer.sign(t, jsCmd, 2, jsPayload, nil)
		},
		"unsigned": func(*jobPollerFixture) json.RawMessage { return nil },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newJobPollerFixture(t, true, true)
			env := mk(f)
			if _, offered := f.client.answers[jsCmd]; !offered {
				f.offer(jsCmd, jsPayload, env)
			}
			f.run()
			if len(f.exec.ran) != 0 {
				t.Fatal("a job that failed verification ran")
			}
			if len(f.client.started) != 0 {
				t.Fatal("a job that failed verification was started")
			}
			f.refusal(t, jsCmd)
		})
	}
}

func TestPollerRefusesAReplayedJob(t *testing.T) {
	f := newJobPollerFixture(t, true, true)
	env := f.signer.sign(t, jsCmd, 2, jsPayload, nil)
	f.offer(jsCmd, jsPayload, env)
	f.run()
	if len(f.exec.ran) != 1 {
		t.Fatalf("first delivery: ran %d", len(f.exec.ran))
	}
	f.offer(jsCmd, jsPayload, env) // the same envelope again
	f.run()
	if len(f.exec.ran) != 1 {
		t.Fatal("a replayed signed job ran")
	}
	if r := f.refusal(t, jsCmd); !strings.Contains(r.Error, "replay") {
		t.Fatalf("refusal = %q", r.Error)
	}
}

func TestPollerUnsignedJobs(t *testing.T) {
	// Not required, no key pinned (a legacy install): unsigned jobs run
	// through the plain acknowledge, as before.
	f := newJobPollerFixture(t, false, false)
	f.offer(jsCmd, jsPayload, nil)
	f.run()
	if len(f.exec.ran) != 1 {
		t.Fatalf("legacy unsigned job: ran %d (result %+v)", len(f.exec.ran), f.client.results[jsCmd])
	}
	// Not required, key pinned: unsigned runs, a signed one is verified.
	f = newJobPollerFixture(t, false, true)
	f.offer(jsCmd, jsPayload, nil)
	f.run()
	if len(f.exec.ran) != 1 {
		t.Fatalf("unsigned job with keys pinned, not required: ran %d", len(f.exec.ran))
	}
	f.offer(jsCmd, jsPayload, f.signer.sign(t, jsCmd, 1, jsPayload, nil)) // wrong epoch
	f.run()
	if len(f.exec.ran) != 1 {
		t.Fatal("a signed job that does not verify ran on a sensor that does not require signatures")
	}
	f.refusal(t, jsCmd)
	// Required: unsigned is refused.
	f = newJobPollerFixture(t, true, true)
	f.offer(jsCmd, jsPayload, nil)
	f.run()
	if len(f.exec.ran) != 0 {
		t.Fatal("an unsigned job ran on a sensor that requires signed jobs")
	}
	if r := f.refusal(t, jsCmd); !strings.Contains(r.Error, "not signed") {
		t.Fatalf("refusal = %q", r.Error)
	}
}

func TestRunClaimedChecksTheJobSignature(t *testing.T) {
	f := newJobPollerFixture(t, true, true)
	cmd := &Command{ID: jsCmd, Type: "scan", Payload: jsPayload, LeaseEpoch: 2, Claimed: true,
		SignedJob: f.signer.sign(t, jsCmd, 2, json.RawMessage(`{"scanner":"nuclei","targets":["198.51.100.1"]}`), nil)}
	if err := f.poller.RunClaimed(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if len(f.exec.ran) != 0 || len(f.client.started) != 0 {
		t.Fatal("RunClaimed ran a job whose signature does not match its payload")
	}
	f.refusal(t, jsCmd)

	ok := &Command{ID: jsCmd, Type: "scan", Payload: jsPayload, LeaseEpoch: 2, Claimed: true,
		SignedJob: f.signer.sign(t, jsCmd, 2, jsPayload, nil)}
	if err := f.poller.RunClaimed(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	if len(f.exec.ran) != 1 {
		t.Fatal("RunClaimed did not run a verified job")
	}
}

func TestNewJobGuard(t *testing.T) {
	if _, err := NewJobGuard(nil, true, jsTenant, jsSensor); err == nil {
		t.Fatal("required without a key accepted")
	}
	keys, _ := jobsig.NewKeys(newJobSigner().pub())
	v, _ := jobsig.NewVerifier(jobsig.Config{Keys: keys})
	if _, err := NewJobGuard(v, false, "", jsSensor); err == nil {
		t.Fatal("a verifying guard without the tenant id accepted")
	}
	for _, tc := range []struct {
		v        *jobsig.Verifier
		required bool
		want     string
	}{{nil, false, JobsSignedOff}, {v, false, JobsSignedVerifiedWhenPresent}, {v, true, JobsSignedRequired}} {
		g, err := NewJobGuard(tc.v, tc.required, jsTenant, jsSensor)
		if err != nil || g.Posture() != tc.want {
			t.Fatalf("posture = %v %v, want %s", g.Posture(), err, tc.want)
		}
	}
	for _, tc := range []struct {
		env      string
		required bool
		set      bool
		bad      bool
	}{{"", false, false, false}, {"true", true, true, false}, {"0", false, true, false}, {"maybe", false, false, true}} {
		req, set, err := RequireSignedJobsFromEnv(func(string) (string, bool) { return tc.env, tc.env != "" })
		if req != tc.required || set != tc.set || (err != nil) != tc.bad {
			t.Fatalf("%q: %v %v %v", tc.env, req, set, err)
		}
	}
}
