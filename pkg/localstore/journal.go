package localstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The job journal (openctem research 194 §5.4 (2)): one sealed record per
// job the sensor holds, rewritten at every step change. After a crash or a
// kill the next start finds the records of the previous boot: every such
// job was interrupted. The SDK reports it as interrupted (the platform
// decides whether another sensor retries it) and keeps the record as a
// tombstone, so a step marked non-repeatable (an active validation, a
// state-changing request) that had started is never started again for the
// same command, even if the platform hands the command back.

// Journal namespace and retention.
const (
	journalNamespace = "journal"
	// DefaultJournalRetention is how long a finished-by-interruption
	// record is kept as a tombstone.
	DefaultJournalRetention = 7 * 24 * time.Hour
)

// StepState is the state of one journaled step.
type StepState string

// Step states.
const (
	StepStarted StepState = "started"
	StepDone    StepState = "done"
)

// Step is one step of a job.
type Step struct {
	Name  string    `json:"name"`
	State StepState `json:"state"`
	// Repeatable: running the step again has no effect beyond the first
	// run (a read-only scan). A step that is not repeatable is never
	// started twice for one command.
	Repeatable bool      `json:"repeatable"`
	At         time.Time `json:"at"`
}

// JobRecord is the journal record of one held job.
type JobRecord struct {
	CommandID  string `json:"command_id"`
	Tenant     string `json:"tenant"`
	LeaseEpoch int    `json:"lease_epoch,omitempty"`
	// StatementDigest is the sha256 of the job's verified signed
	// statement, when it had one.
	StatementDigest string `json:"statement_digest,omitempty"`
	// ExpiresAt is the signed statement's expiry: a job past it is never
	// resumed.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	StartedAt time.Time `json:"started_at"`
	Steps     []Step    `json:"steps,omitempty"`
	// Boot is the store's boot generation when the job began.
	Boot uint64 `json:"boot"`
	// Interrupted is set once the job was found interrupted and reported;
	// the record then stays as a tombstone until its retention passes.
	Interrupted   bool      `json:"interrupted,omitempty"`
	InterruptedAt time.Time `json:"interrupted_at,omitzero"`
}

// Interruption is a job of an earlier boot found by Recover.
type Interruption struct {
	Record JobRecord
	// Step is the step that was running (empty: between steps).
	Step string
	// Reason is a one-line explanation for the command result.
	Reason string
}

// ErrStepRefused: the step started before for this command, is not
// repeatable and did not finish.
var ErrStepRefused = errors.New("localstore: a non-repeatable step already started for this command")

// Journal is a tenant's job journal.
type Journal struct {
	s  *Store
	kv *KV
}

// Journal returns the tenant's job journal.
func (s *Store) Journal(tenant string) (*Journal, error) {
	kv, err := s.KV(tenant, journalNamespace)
	if err != nil {
		return nil, err
	}
	return &Journal{s: s, kv: kv}, nil
}

func (j *Journal) load(commandID string) (JobRecord, error) {
	data, err := j.kv.Get(commandID)
	if err != nil {
		return JobRecord{}, err
	}
	var r JobRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return JobRecord{}, fmt.Errorf("localstore: journal %s: %w", commandID, err)
	}
	return r, nil
}

func (j *Journal) save(r JobRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// Journal writes keep the sensor consistent: they go through even on a
	// critically full disk.
	return j.kv.Put(r.CommandID, data, Critical())
}

// Begin records a job the sensor starts. A tombstone of an earlier
// interrupted run of the same command is kept (its started non-repeatable
// steps stay refused); a live record of the same command is replaced only
// by a higher lease epoch.
func (j *Journal) Begin(r JobRecord) error {
	if err := validName(r.CommandID); err != nil {
		return err
	}
	r.Tenant = j.kv.tenant
	r.Boot = j.s.Stats().Boot
	if r.StartedAt.IsZero() {
		r.StartedAt = j.s.opts.now().UTC()
	}
	prev, err := j.load(r.CommandID)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return err
	default:
		if !prev.Interrupted && prev.Boot == r.Boot && r.LeaseEpoch <= prev.LeaseEpoch {
			return fmt.Errorf("localstore: job %s already journaled for lease epoch %d", r.CommandID, prev.LeaseEpoch)
		}
		// Carry the steps that must never run again.
		for _, st := range prev.Steps {
			if st.State == StepStarted && !st.Repeatable {
				r.Steps = append(r.Steps, st)
			}
		}
	}
	r.Interrupted = false
	r.InterruptedAt = time.Time{}
	return j.save(r)
}

// StepStarted records that a step begins. It returns ErrStepRefused when
// the step is not repeatable and already started for this command without
// finishing (in this or an earlier run).
func (j *Journal) StepStarted(commandID, step string, repeatable bool) error {
	r, err := j.load(commandID)
	if err != nil {
		return err
	}
	now := j.s.opts.now().UTC()
	for i, st := range r.Steps {
		if st.Name != step {
			continue
		}
		if st.State == StepStarted && (!st.Repeatable || !repeatable) {
			return fmt.Errorf("%w: %s of %s", ErrStepRefused, step, commandID)
		}
		r.Steps[i] = Step{Name: step, State: StepStarted, Repeatable: repeatable, At: now}
		return j.save(r)
	}
	r.Steps = append(r.Steps, Step{Name: step, State: StepStarted, Repeatable: repeatable, At: now})
	return j.save(r)
}

// StepDone records that a step finished.
func (j *Journal) StepDone(commandID, step string) error {
	r, err := j.load(commandID)
	if err != nil {
		return err
	}
	for i, st := range r.Steps {
		if st.Name == step {
			r.Steps[i].State = StepDone
			r.Steps[i].At = j.s.opts.now().UTC()
			return j.save(r)
		}
	}
	return fmt.Errorf("localstore: step %s of %s was never started", step, commandID)
}

// Finish removes the record of a job that completed (its result is queued).
func (j *Journal) Finish(commandID string) error {
	if err := validName(commandID); err != nil {
		return err
	}
	return j.kv.Delete(commandID)
}

// Get returns a job's record.
func (j *Journal) Get(commandID string) (JobRecord, error) { return j.load(commandID) }

// Recover returns the jobs of earlier boots that were never finished
// (every tenant), marks each one interrupted (a tombstone), and removes
// tombstones older than retention (0: DefaultJournalRetention). The caller
// reports each interruption as the command's result through the outbox.
// Records that fail authentication are quarantined and reported by the
// store, and skipped here.
func (s *Store) Recover(retention time.Duration) ([]Interruption, error) {
	if retention <= 0 {
		retention = DefaultJournalRetention
	}
	boot := s.Stats().Boot
	now := s.opts.now().UTC()
	var out []Interruption
	for _, tenant := range s.Tenants() {
		j, err := s.Journal(tenant)
		if err != nil {
			continue
		}
		names, err := j.kv.List()
		if err != nil {
			return out, err
		}
		for _, name := range names {
			r, err := j.load(name)
			if err != nil {
				continue
			}
			if r.Interrupted {
				if now.Sub(r.InterruptedAt) > retention {
					_ = j.kv.Delete(name)
				}
				continue
			}
			if r.Boot >= boot {
				continue // a job of this boot
			}
			it := Interruption{Record: r, Reason: "the sensor stopped while the job was running"}
			for _, st := range r.Steps {
				if st.State == StepStarted {
					it.Step = st.Name
					it.Reason = fmt.Sprintf("the sensor stopped during step %s", st.Name)
				}
			}
			r.Interrupted = true
			r.InterruptedAt = now
			if err := j.save(r); err != nil {
				return out, err
			}
			it.Record = r
			out = append(out, it)
		}
	}
	return out, nil
}
