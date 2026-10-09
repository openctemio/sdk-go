package jobsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Refusal reasons (Error.Reason).
const (
	ReasonMalformed     = "malformed"
	ReasonPayloadType   = "payload_type"
	ReasonUntrustedKey  = "untrusted_key"
	ReasonBadSignature  = "bad_signature"
	ReasonKind          = "kind"
	ReasonSigner        = "signer"
	ReasonTenant        = "tenant"
	ReasonSensor        = "sensor"
	ReasonCommand       = "command"
	ReasonCommandType   = "command_type"
	ReasonClockSkew     = "clock_skew"
	ReasonExpired       = "expired"
	ReasonLeaseEpoch    = "lease_epoch"
	ReasonPayloadDigest = "payload_digest"
	ReasonTool          = "tool"
	ReasonTargets       = "targets"
	ReasonNonce         = "nonce"
	ReasonReplay        = "replay"
	ReasonSeq           = "seq"
	ReasonState         = "state"
)

// Error is a signed job the verifier refused: Reason is one of the
// Reason* constants, Detail says what did not match.
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string { return "signed job refused (" + e.Reason + "): " + e.Detail }

func refusef(reason, format string, args ...any) error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// ReasonOf is the reason of a refusal, "" for another error.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// Binding is what a statement must describe: this sensor and the command
// as the claim response handed it over.
type Binding struct {
	TenantID    string
	SensorID    string
	CommandID   string
	CommandType string
	LeaseEpoch  int
	// Payload is the command's payload bytes exactly as the response
	// carried them (json.RawMessage), never a re-encoding.
	Payload []byte
}

// KeySource returns the signer keys the platform advertises (hello
// "signed_jobs.keys"). The verifier asks it only for a key pinned by id
// whose public key it does not have, and trusts only a listed key whose
// recomputed id is pinned.
type KeySource func(ctx context.Context) ([]PublicKey, error)

// Config configures a Verifier.
type Config struct {
	// Keys are the pinned signer keys; at least one.
	Keys *Keys
	// StateFile keeps the last accepted sequence number per signer key
	// across restarts (written with fsync before a job is accepted). "":
	// in memory only.
	StateFile string
	// KeySource resolves keys pinned by id (optional).
	KeySource KeySource
	// MaxNonces bounds the nonces kept (default 65536); the one closest to
	// expiry is dropped first. The persisted sequence number still refuses
	// a replay of a dropped one.
	MaxNonces int
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Verifier checks signed jobs against pinned keys. It is safe for
// concurrent use; accepting a job (its nonce and sequence number) is
// atomic.
type Verifier struct {
	keys      *Keys
	keySource KeySource
	stateFile string
	maxNonces int
	now       func() time.Time

	mu     sync.Mutex
	last   map[string]uint64    // last accepted seq by signer key id
	nonces map[string]time.Time // nonce -> its statement's expires_at
}

// state is the StateFile's content.
type state struct {
	Version int               `json:"version"`
	LastSeq map[string]uint64 `json:"last_seq"`
}

// NewVerifier returns a verifier for cfg. A state file that exists and
// cannot be read is an error (the sensor refuses to start rather than
// accept old sequence numbers again).
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Keys.Len() == 0 {
		return nil, errors.New("signed jobs: no job-signing key is pinned")
	}
	v := &Verifier{keys: cfg.Keys.clone(), keySource: cfg.KeySource, stateFile: cfg.StateFile,
		maxNonces: cfg.MaxNonces, now: cfg.Now, last: map[string]uint64{}, nonces: map[string]time.Time{}}
	if v.maxNonces <= 0 {
		v.maxNonces = 1 << 16
	}
	if v.now == nil {
		v.now = time.Now
	}
	if v.stateFile != "" {
		b, err := os.ReadFile(v.stateFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("signed jobs: read %s: %w", v.stateFile, err)
		default:
			var st state
			if err := json.Unmarshal(b, &st); err != nil || st.Version != 1 {
				return nil, fmt.Errorf("signed jobs: %s is corrupt; the sensor does not start rather than accept old jobs again (restore it, or remove it only after the platform's signer moved past every job ever issued)", v.stateFile)
			}
			for id, n := range st.LastSeq {
				v.last[id] = n
			}
		}
	}
	return v, nil
}

// KeyIDs are the pinned key ids.
func (v *Verifier) KeyIDs() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.keys.IDs()
}

// LastSeq is the last accepted sequence number of signer key id.
func (v *Verifier) LastSeq(keyID string) uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.last[keyID]
}

// Verify checks envelope (the "signed_job" JSON) against the pinned keys
// and b, and returns the statement. The signature is checked over the exact
// payload bytes before they are parsed; then the statement must be a v1
// job for b's tenant, sensor, command, command type and lease epoch,
// issued within MaxClockSkew of now and not expired, with the SHA-256 of
// b.Payload and the tool and targets b.Payload names; finally its nonce
// must be new and its sequence number above the last one accepted from
// that key, which is persisted before Verify returns.
func (v *Verifier) Verify(ctx context.Context, envelope []byte, b Binding) (*Statement, error) {
	if len(envelope) == 0 {
		return nil, refusef(ReasonMalformed, "no envelope")
	}
	if len(envelope) > MaxEnvelopeBytes {
		return nil, refusef(ReasonMalformed, "envelope of %d bytes is over %d", len(envelope), MaxEnvelopeBytes)
	}
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, refusef(ReasonMalformed, "envelope: %v", err)
	}
	if env.PayloadType != PayloadType {
		return nil, refusef(ReasonPayloadType, "payload type %q, want %q", env.PayloadType, PayloadType)
	}
	if len(env.Payload) == 0 || len(env.Payload) > MaxPayloadBytes {
		return nil, refusef(ReasonMalformed, "statement is empty or over %d bytes", MaxPayloadBytes)
	}
	keyID, err := v.checkSignature(ctx, &env)
	if err != nil {
		return nil, err
	}

	// Only now parse what was signed.
	var st Statement
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, refusef(ReasonMalformed, "statement: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, refusef(ReasonMalformed, "statement: trailing data")
	}
	if err := v.checkStatement(&st, keyID, b); err != nil {
		return nil, err
	}
	if err := v.accept(keyID, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// checkSignature returns the id of the pinned key whose signature verifies
// over the PAE of the payload.
func (v *Verifier) checkSignature(ctx context.Context, env *Envelope) (string, error) {
	pae := PreAuthEncoding(env.PayloadType, env.Payload)
	trusted := false
	for _, s := range env.Signatures {
		pub := v.key(ctx, s.KeyID)
		if pub == nil {
			continue
		}
		trusted = true
		if len(s.Sig) == ed25519.SignatureSize && ed25519.Verify(pub, pae, s.Sig) {
			return s.KeyID, nil
		}
	}
	if !trusted {
		ids := make([]string, 0, len(env.Signatures))
		for _, s := range env.Signatures {
			ids = append(ids, s.KeyID)
		}
		return "", refusef(ReasonUntrustedKey, "signed by %s, none of them pinned on this sensor (%s)",
			orNone(ids), strings.Join(v.KeyIDs(), ", "))
	}
	return "", refusef(ReasonBadSignature, "the signature does not verify with the pinned key")
}

// key is the pinned public key with id, resolving a key pinned by id
// through the KeySource; nil when id is not pinned or cannot be resolved.
// The map key is the recomputed id of the stored key, so a signature's
// keyid only selects a key, it never vouches for one.
func (v *Verifier) key(ctx context.Context, id string) ed25519.PublicKey {
	v.mu.Lock()
	pub := v.keys.pubs[id]
	pinnedID := v.keys.ids[id]
	v.mu.Unlock()
	if pub != nil || !pinnedID || v.keySource == nil {
		return pub
	}
	listed, err := v.keySource(ctx)
	if err != nil {
		return nil
	}
	for _, pk := range listed {
		p, err := pk.Decode()
		if err != nil || KeyID(p) != id {
			continue
		}
		v.mu.Lock()
		v.keys.pubs[id] = p
		v.mu.Unlock()
		return p
	}
	return nil
}

func (v *Verifier) checkStatement(st *Statement, keyID string, b Binding) error {
	if st.Kind != Kind {
		return refusef(ReasonKind, "statement kind %q, want %q", st.Kind, Kind)
	}
	if st.Signer == nil || st.Signer.KeyID != keyID {
		return refusef(ReasonSigner, "the statement does not name the key that signed it")
	}
	if b.TenantID == "" || !strings.EqualFold(st.TenantID, b.TenantID) {
		return refusef(ReasonTenant, "statement is for organization %q, not this sensor's", st.TenantID)
	}
	if b.SensorID == "" || !strings.EqualFold(st.SensorID, b.SensorID) {
		return refusef(ReasonSensor, "statement is for sensor %q, not this sensor %q", st.SensorID, b.SensorID)
	}
	if b.CommandID == "" || !strings.EqualFold(st.CommandID, b.CommandID) {
		return refusef(ReasonCommand, "statement is for command %q, not command %q", st.CommandID, b.CommandID)
	}
	if st.CommandType == "" || st.CommandType != b.CommandType {
		return refusef(ReasonCommandType, "statement is for a %q command, the response says %q", st.CommandType, b.CommandType)
	}
	now := v.now()
	if st.IssuedAt.IsZero() || st.IssuedAt.After(now.Add(MaxClockSkew)) || st.IssuedAt.Before(now.Add(-MaxClockSkew)) {
		return refusef(ReasonClockSkew, "issued at %s, more than %s from this sensor's clock (%s)",
			st.IssuedAt.UTC().Format(time.RFC3339), MaxClockSkew, now.UTC().Format(time.RFC3339))
	}
	if !now.Before(st.ExpiresAt) {
		return refusef(ReasonExpired, "expired at %s", st.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if !st.ExpiresAt.After(st.IssuedAt) || st.ExpiresAt.Sub(st.IssuedAt) > MaxTTL {
		return refusef(ReasonExpired, "validity %s to %s is not within (0, %s]",
			st.IssuedAt.UTC().Format(time.RFC3339), st.ExpiresAt.UTC().Format(time.RFC3339), MaxTTL)
	}
	if st.LeaseEpoch != b.LeaseEpoch {
		return refusef(ReasonLeaseEpoch, "statement is for lease epoch %d, the claim holds epoch %d", st.LeaseEpoch, b.LeaseEpoch)
	}
	if got := PayloadDigest(b.Payload); st.PayloadSHA256 != got {
		return refusef(ReasonPayloadDigest, "the payload received (%s) is not the payload signed (%s)", got, st.PayloadSHA256)
	}
	// The digest binds the payload; the tool and targets the statement
	// names must also be the ones that payload names, so what the signer
	// checked is what runs.
	if got := PayloadTool(b.Payload); st.Tool != got {
		return refusef(ReasonTool, "statement names tool %q, the payload %q", st.Tool, got)
	}
	if got := PayloadTargets(b.Payload); !slices.Equal(st.Targets, got) {
		return refusef(ReasonTargets, "statement names %d target(s), the payload %d, or they differ", len(st.Targets), len(got))
	}
	if raw, err := base64.RawURLEncoding.DecodeString(st.Nonce); err != nil || len(raw) != NonceBytes {
		return refusef(ReasonNonce, "nonce is not %d bytes of base64url", NonceBytes)
	}
	if st.Seq == 0 {
		return refusef(ReasonSeq, "sequence number 0")
	}
	return nil
}

// accept records the nonce and the sequence number of a statement that
// passed every other check: a nonce seen before, or a sequence number not
// above the last accepted from that key, is a replay. The new sequence
// number is on disk before the job is accepted.
func (v *Verifier) accept(keyID string, st *Statement) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if exp, seen := v.nonces[st.Nonce]; seen && now.Before(exp) {
		return refusef(ReasonReplay, "nonce already used (seq %d)", st.Seq)
	}
	if last := v.last[keyID]; st.Seq <= last {
		return refusef(ReasonReplay, "sequence number %d is not above the last accepted %d", st.Seq, last)
	}
	prev, had := v.last[keyID]
	v.last[keyID] = st.Seq
	if err := v.persist(); err != nil {
		if had {
			v.last[keyID] = prev
		} else {
			delete(v.last, keyID)
		}
		return refusef(ReasonState, "cannot record the sequence number: %v", err)
	}
	v.rememberNonce(st.Nonce, st.ExpiresAt, now)
	return nil
}

func (v *Verifier) rememberNonce(nonce string, exp, now time.Time) {
	if len(v.nonces) >= v.maxNonces {
		for n, e := range v.nonces {
			if !now.Before(e) {
				delete(v.nonces, n)
			}
		}
	}
	for len(v.nonces) >= v.maxNonces {
		var oldest string
		var oldestExp time.Time
		for n, e := range v.nonces {
			if oldest == "" || e.Before(oldestExp) {
				oldest, oldestExp = n, e
			}
		}
		delete(v.nonces, oldest)
	}
	v.nonces[nonce] = exp
}

// persist writes the sequence numbers: a temporary file, fsync, rename,
// then the directory fsync'd. Called with mu held.
func (v *Verifier) persist() error {
	if v.stateFile == "" {
		return nil
	}
	b, err := json.Marshal(state{Version: 1, LastSeq: v.last})
	if err != nil {
		return err
	}
	dir := filepath.Dir(v.stateFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(v.stateFile)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, v.stateFile); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func orNone(ids []string) string {
	if len(ids) == 0 {
		return "no key"
	}
	return strings.Join(ids, ", ")
}
