package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/contract/secretref"
)

// Task secrets (contract secretref). When a sensor claims a job, the
// platform lists in the job's payload (member "secrets") the secret refs
// the job may use: ids, kinds, the stored value each names, the tool slot
// it fills, where its value may be sent and whether the sensor's own local
// value may stand in. The list is part of the signed job. Values are
// pulled per task (client.Secrets), sealed to a single-use key, and never
// logged, stored or cached across tasks.
//
// The poller reads the list only from a job whose signature the JobGuard
// verified (JobSecretsFor) and puts it on the job's context
// (WithJobSecrets): the tool host fetches the refs of the slots a task's
// tool declares, the egress setup fetches the job's proxy pool credentials
// once. A job that lists no refs, or whose list is not verified, gets no
// platform values. A shared sensor never uses a local value for a slot,
// whatever the job says.

// Refusal rules of task secrets.
const (
	// RefusalRuleSecretKindUnsupported: the job requires a secret of a
	// kind this sensor does not know (secretref.RefusalKindUnsupported).
	RefusalRuleSecretKindUnsupported = secretref.RefusalKindUnsupported
	// RefusalRuleSecretsInvalid: the job's signed secret list is not a
	// valid secretref.Set.
	RefusalRuleSecretsInvalid = "secrets_invalid"
	// RefusalRuleSecretsUnverified: the job requires platform secrets and
	// its signature was not verified (the sensor pins no job signer, or the
	// job is unsigned). The secret list is honored only from a verified
	// signed job, so the job could only run without its credentials.
	RefusalRuleSecretsUnverified = "secrets_unverified"
)

// SecretsFetcher fetches the values of a job's refs for one task (the
// platform client: client.Secrets). It returns an answer checked against
// set (secretref.Answer.Check): a value it returns answers a ref the
// request asked for.
type SecretsFetcher interface {
	Secrets(ctx context.Context, cmdID, task string, set secretref.Set, refs []string) (*secretref.Answer, error)
}

// ErrNoSecretsFetch is the fetch's error when the job has no verified ref
// list or the sensor has no way to ask the platform: no platform values.
var ErrNoSecretsFetch = errors.New("the job's secrets cannot be fetched from the platform")

// JobSecrets is one job's secret refs and how to fetch their values.
type JobSecrets struct {
	cmdID  string
	set    *secretref.Set
	shared bool
	fetch  SecretsFetcher
	// ignored counts the optional refs of an unverified job's list: not
	// used, and said so in the job's log (IgnoredOptional).
	ignored int
}

// IgnoredOptional is the number of optional secret refs the job listed
// that are not used because its signature was not verified.
func (j *JobSecrets) IgnoredOptional() int {
	if j == nil {
		return 0
	}
	return j.ignored
}

// NewJobSecrets returns the secrets of command cmdID: set is the job's
// verified, validated list (nil: none), shared is this sensor's identity,
// fetch asks the platform (nil: values cannot be fetched). For a caller
// that verified the job itself; the poller uses JobSecretsFor.
func NewJobSecrets(cmdID string, set *secretref.Set, shared bool, fetch SecretsFetcher) *JobSecrets {
	return &JobSecrets{cmdID: cmdID, set: set, shared: shared, fetch: fetch}
}

// Shared reports whether the sensor is a shared sensor (no local value
// ever fills a slot).
func (j *JobSecrets) Shared() bool { return j != nil && j.shared }

// Set returns the job's verified ref list (false: none).
func (j *JobSecrets) Set() (secretref.Set, bool) {
	if j == nil || j.set == nil {
		return secretref.Set{}, false
	}
	return *j.set, true
}

// LocalPolicy is the local policy of a tool slot: secretref.LocalNever on
// a shared sensor whatever the job says, else the policy of the ref that
// fills the slot, else the set's, else (a job with no list)
// secretref.LocalAllow.
func (j *JobSecrets) LocalPolicy(slot string) string {
	return LocalSecretPolicy(j, slot, false)
}

// LocalSecretPolicy is JobSecrets.LocalPolicy with the host's own view of
// whether it is shared (shared: never, also without a job). A nil j is a
// task outside a platform job: allow, unless shared.
func LocalSecretPolicy(j *JobSecrets, slot string, shared bool) string {
	if shared || j.Shared() {
		return secretref.LocalNever
	}
	set, ok := j.Set()
	if !ok {
		return secretref.LocalAllow
	}
	if r, ok := set.ForSlot(slot); ok {
		return r.Local
	}
	return set.Local
}

// Fetch asks the platform for the values of ids for task. Every id must be
// a ref of the job's list. The answer's values are the caller's to use and
// forget; nothing is kept here.
func (j *JobSecrets) Fetch(ctx context.Context, task string, ids []string) (*secretref.Answer, error) {
	set, ok := j.Set()
	if !ok || j.fetch == nil {
		return nil, ErrNoSecretsFetch
	}
	if len(ids) == 0 {
		return nil, errors.New("secrets: no ref asked")
	}
	for _, id := range ids {
		if _, ok := set.Lookup(id); !ok {
			return nil, fmt.Errorf("secrets: %s is not a ref of the job", id)
		}
	}
	return j.fetch.Secrets(ctx, j.cmdID, task, set, ids)
}

// ForwarderRef returns the job's egress proxy ref for pool poolID.
func (j *JobSecrets) ForwarderRef(poolID string) (secretref.Ref, bool) {
	set, ok := j.Set()
	if !ok {
		return secretref.Ref{}, false
	}
	for _, r := range set.Refs {
		if r.Kind == secretref.KindEgressProxy && r.Consumer == secretref.ConsumerForwarder && r.Ref == poolID {
			return r, true
		}
	}
	return secretref.Ref{}, false
}

// JobSecretsFor reads the secret refs of cmd. Only a job whose signature
// the JobGuard verified carries a list: an unverified payload's "secrets"
// member gives no platform values. An unverified job whose list requires a
// secret is refused (RefusalRuleSecretsUnverified), so it neither runs
// without its credentials nor fails later with a vaguer reason; its
// optional refs are left out and counted (IgnoredOptional); a list that is
// present but cannot be read refuses it too. A list that is
// not valid, or that requires a kind this sensor does not know, refuses a
// verified job (a *LocalPolicyError); an unknown kind on an optional ref is
// skipped by every consumer.
func JobSecretsFor(cmd *Command, shared bool, fetch SecretsFetcher) (*JobSecrets, error) {
	js := &JobSecrets{cmdID: cmd.ID, shared: shared, fetch: fetch}
	if !cmd.jobVerified {
		return js, unverifiedSecrets(cmd.Payload, js)
	}
	set, err := secretSetOf(cmd.Payload)
	if err != nil || set == nil {
		return js, err
	}
	js.set = set
	return js, nil
}

// unverifiedSecrets refuses an unverified job whose (unused) secret list
// requires a value and counts its optional refs in js. A list that is
// present but cannot be read is refused the same way: the sensor cannot
// tell whether it requires a secret, so the job must not run without the
// credentials it may need.
func unverifiedSecrets(payload json.RawMessage, js *JobSecrets) error {
	set, err := secretListOf(payload)
	if err != nil {
		return &LocalPolicyError{Layer: RefusalLayerBuiltin, Rule: RefusalRuleSecretsUnverified,
			Detail: "the job carries a platform secret list that cannot be read, which this sensor uses only from a verified signed job, " +
				"and the job's signature was not verified (no job signer pinned: pair the sensor again, or set SENSOR_JOB_SIGNING_ROOT)"}
	}
	if set == nil {
		return nil
	}
	for _, r := range set.Refs {
		if r.Required {
			return &LocalPolicyError{Layer: RefusalLayerBuiltin, Rule: RefusalRuleSecretsUnverified,
				Detail: fmt.Sprintf("the job requires platform secret %s (%s), which this sensor uses only from a verified signed job, "+
					"and the job's signature was not verified (no job signer pinned: pair the sensor again, or set SENSOR_JOB_SIGNING_ROOT)", r.ID, r.Kind)}
		}
	}
	js.ignored = len(set.Refs)
	return nil
}

// secretListOf decodes and validates the payload's secrets member (nil:
// none).
func secretListOf(payload json.RawMessage) (*secretref.Set, error) {
	var p map[string]json.RawMessage
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		// Not an object: the executor reports the payload itself.
		return nil, nil //nolint:nilerr // the payload's own decoder reports it
	}
	raw, ok := p[secretref.PayloadField]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var set secretref.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, &LocalPolicyError{Layer: RefusalLayerBuiltin, Rule: RefusalRuleSecretsInvalid,
			Detail: "the job's secret list cannot be read"}
	}
	if err := set.Validate(); err != nil {
		return nil, &LocalPolicyError{Layer: RefusalLayerBuiltin, Rule: RefusalRuleSecretsInvalid,
			Detail: "the job's secret list is not valid: " + err.Error()}
	}
	return &set, nil
}

// secretSetOf decodes and checks the payload's secrets member (nil: none):
// secretListOf, and a required ref of a kind this sensor does not know
// refuses the job.
func secretSetOf(payload json.RawMessage) (*secretref.Set, error) {
	set, err := secretListOf(payload)
	if err != nil || set == nil {
		return nil, err
	}
	for _, r := range set.Refs {
		if r.Required && !secretref.KnownKind(r.Kind) {
			return nil, &LocalPolicyError{Layer: RefusalLayerBuiltin, Rule: RefusalRuleSecretKindUnsupported,
				Detail: fmt.Sprintf("the job requires secret %s of kind %q, which this sensor does not support", r.ID, r.Kind)}
		}
	}
	return set, nil
}

type jobSecretsKey struct{}

// WithJobSecrets returns ctx carrying the job's secrets.
func WithJobSecrets(ctx context.Context, j *JobSecrets) context.Context {
	if j == nil {
		return ctx
	}
	return context.WithValue(ctx, jobSecretsKey{}, j)
}

// JobSecretsFrom is the job's secrets on ctx (nil: the task is not part of
// a platform job).
func JobSecretsFrom(ctx context.Context) *JobSecrets {
	j, _ := ctx.Value(jobSecretsKey{}).(*JobSecrets)
	return j
}

// SetSecretsFetcher wires the fetch of a job's secret values (the
// platform client); without it no task receives a platform value.
func (p *CommandPoller) SetSecretsFetcher(f SecretsFetcher) {
	if f == nil {
		p.secrets.Store(nil)
		return
	}
	p.secrets.Store(&f)
}

func (p *CommandPoller) secretsFetcher() SecretsFetcher {
	if f := p.secrets.Load(); f != nil {
		return *f
	}
	return nil
}

// sharedSensor reports whether this poller serves a shared sensor (a job
// ledger, or a shared job guard).
func (p *CommandPoller) sharedSensor() bool {
	if p.ledger != nil {
		return true
	}
	g := p.jobs.Load()
	return g != nil && g.shared
}

// ZeroAnswer overwrites the value bytes of an answer (best effort: a value
// decoded into a string elsewhere is not reached). Call it once the values
// were delivered or refused.
func ZeroAnswer(a *secretref.Answer) {
	if a == nil {
		return
	}
	for i := range a.Secrets {
		clear(a.Secrets[i].Value)
		a.Secrets[i].Value = nil
	}
	a.Secrets = nil
}
