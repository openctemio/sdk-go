package jobsig

// Key sets (api RFC-040 §5.6 point 2): the installation's offline root key
// signs a versioned list of the online signer keys, valid at most 30 days.
// A sensor that pins the root accepts job signatures only from the keys of
// the current key set, so a signer key is rotated or revoked by a new key
// set and no sensor is paired again. Format: api
// docs/architecture/job-signing.md ("Key sets and the offline root").
//
// The rules follow the update model of a root of trust with versioned,
// expiring metadata: the document is verified against the pinned root
// before it is parsed further; it must not have expired; its version may
// never go down (the highest accepted version is kept on disk), and the
// same version must be the same bytes.

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
	"strings"
	"sync"
	"time"
)

// KeySetPayloadType is the DSSE payload type of a key set.
const KeySetPayloadType = "application/vnd.openctem.keyset.v1+json"

// KeySetKind is the key set kind (v1).
const KeySetKind = "openctem.keyset/v1"

// Key set limits, as the platform's signer tooling enforces them.
const (
	// MaxKeySetValidity caps not_after - issued_at.
	MaxKeySetValidity = 30 * 24 * time.Hour
	// MaxKeySetBytes caps a key set envelope (JSON).
	MaxKeySetBytes = 64 << 10
	// MaxKeySetKeys caps the online keys of one key set.
	MaxKeySetKeys = 16
	// KeySetRefreshInterval is the least time between two key set fetches
	// that are not forced by a config_version change.
	KeySetRefreshInterval = 30 * time.Second
)

// ReasonKeySet is the refusal reason of a job that cannot be checked
// because the sensor pins a root and holds no valid key set (none yet,
// expired, or the platform served one that was refused).
const ReasonKeySet = "keyset"

// KeySet is the signed key set document.
type KeySet struct {
	Kind          string      `json:"kind"`
	Version       uint64      `json:"version"`
	IssuedAt      time.Time   `json:"issued_at"`
	NotAfter      time.Time   `json:"not_after"`
	Keys          []PublicKey `json:"keys"`
	RootKeyID     string      `json:"root_keyid"`
	RootPublicKey string      `json:"root_public_key"`
}

// ParseRoot reads a root pin, the form SENSOR_JOB_SIGNING_ROOT takes: the
// root's key id ("SHA256:" + 64 hex digits) or its base64 32-byte Ed25519
// public key. It returns the key id ("" for an empty value).
func ParseRoot(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if h, ok := strings.CutPrefix(s, "SHA256:"); ok {
		id := "SHA256:" + strings.ToLower(h)
		if !validKeyID(id) {
			return "", fmt.Errorf("%q is not SHA256:<64 hex digits>", s)
		}
		return id, nil
	}
	raw, err := decodeBase64Any(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", errors.New("neither SHA256:<hex> nor a base64 32-byte Ed25519 key")
	}
	return KeyID(raw), nil
}

// check validates the document's own fields.
func (ks *KeySet) check() error {
	if ks.Kind != KeySetKind {
		return refusef(ReasonKeySet, "key set kind %q, want %q", ks.Kind, KeySetKind)
	}
	if ks.Version == 0 {
		return refusef(ReasonKeySet, "key set version must be 1 or more")
	}
	if ks.IssuedAt.IsZero() || !ks.NotAfter.After(ks.IssuedAt) || ks.NotAfter.Sub(ks.IssuedAt) > MaxKeySetValidity {
		return refusef(ReasonKeySet, "key set validity is not within (0, %s]", MaxKeySetValidity)
	}
	rootRaw, err := base64.StdEncoding.DecodeString(ks.RootPublicKey)
	if err != nil || len(rootRaw) != ed25519.PublicKeySize || KeyID(rootRaw) != ks.RootKeyID {
		return refusef(ReasonKeySet, "key set root_public_key is not the key of root_keyid")
	}
	if len(ks.Keys) == 0 || len(ks.Keys) > MaxKeySetKeys {
		return refusef(ReasonKeySet, "a key set lists 1 to %d keys, not %d", MaxKeySetKeys, len(ks.Keys))
	}
	seen := map[string]bool{}
	for _, k := range ks.Keys {
		if _, err := k.Decode(); err != nil {
			return refusef(ReasonKeySet, "key set: %v", err)
		}
		if seen[k.KeyID] || k.KeyID == ks.RootKeyID {
			return refusef(ReasonKeySet, "key set lists %s twice, or the root as an online key", k.KeyID)
		}
		seen[k.KeyID] = true
	}
	return nil
}

// parseKeySet checks a key set envelope's form, that it is signed by the
// root it names and that this root is pinnedRoot. The clock is not checked.
func parseKeySet(envelope []byte, pinnedRoot string) (*KeySet, error) {
	if len(envelope) == 0 || len(envelope) > MaxKeySetBytes {
		return nil, refusef(ReasonKeySet, "key set envelope is empty or over %d bytes", MaxKeySetBytes)
	}
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, refusef(ReasonKeySet, "key set envelope: %v", err)
	}
	if env.PayloadType != KeySetPayloadType {
		return nil, refusef(ReasonKeySet, "key set payload type %q, want %q", env.PayloadType, KeySetPayloadType)
	}
	var ks KeySet
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ks); err != nil {
		return nil, refusef(ReasonKeySet, "key set: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, refusef(ReasonKeySet, "key set: trailing data")
	}
	if err := ks.check(); err != nil {
		return nil, err
	}
	if pinnedRoot == "" || ks.RootKeyID != pinnedRoot {
		return nil, refusef(ReasonKeySet, "key set signed by root %s, the pinned root is %s", ks.RootKeyID, orNone([]string{pinnedRoot}))
	}
	rootRaw, _ := base64.StdEncoding.DecodeString(ks.RootPublicKey)
	pae := PreAuthEncoding(env.PayloadType, env.Payload)
	for _, s := range env.Signatures {
		if s.KeyID == ks.RootKeyID && len(s.Sig) == ed25519.SignatureSize && ed25519.Verify(rootRaw, pae, s.Sig) {
			return &ks, nil
		}
	}
	return nil, refusef(ReasonKeySet, "key set is not signed by the pinned root %s", pinnedRoot)
}

// VerifyKeySet checks a key set envelope against the pinned root key id
// and the clock: signed by the pinned root, issued no later than now +
// MaxClockSkew, not_after later than now - MaxClockSkew. Version order is
// KeySetTrust's.
func VerifyKeySet(envelope []byte, pinnedRoot string, now time.Time) (*KeySet, error) {
	ks, err := parseKeySet(envelope, pinnedRoot)
	if err != nil {
		return nil, err
	}
	if err := ks.current(now); err != nil {
		return nil, err
	}
	return ks, nil
}

// TrustOnFirstUse verifies a key set against the root it names, for a
// sensor that pins no root yet (pairing): the key set must be signed by
// that root and current. The caller pins the returned RootKeyID; it is
// only as trustworthy as the channel the key set came over.
func TrustOnFirstUse(envelope []byte, now time.Time) (*KeySet, error) {
	var env Envelope
	if len(envelope) > MaxKeySetBytes || json.Unmarshal(envelope, &env) != nil {
		return nil, refusef(ReasonKeySet, "key set envelope does not decode")
	}
	var named struct {
		RootKeyID string `json:"root_keyid"`
	}
	if err := json.Unmarshal(env.Payload, &named); err != nil || !validKeyID(named.RootKeyID) {
		return nil, refusef(ReasonKeySet, "key set names no valid root")
	}
	return VerifyKeySet(envelope, named.RootKeyID, now)
}

// current reports whether ks is valid at now.
func (ks *KeySet) current(now time.Time) error {
	if ks.IssuedAt.After(now.Add(MaxClockSkew)) {
		return refusef(ReasonKeySet, "key set version %d is issued at %s, after this sensor's clock (%s)",
			ks.Version, ks.IssuedAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if !ks.NotAfter.After(now.Add(-MaxClockSkew)) {
		return refusef(ReasonKeySet, "key set version %d expired at %s; the platform must deploy a new one",
			ks.Version, ks.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// KeySetSource returns the key set the platform serves now (hello
// "signed_jobs.keyset"); nil when it serves none.
type KeySetSource func(ctx context.Context) ([]byte, error)

// KeySetConfig configures a KeySetTrust.
type KeySetConfig struct {
	// Root is the pinned root key id (ParseRoot); required.
	Root string
	// StateFile keeps the accepted key set (and so its version) across
	// restarts; "": in memory only.
	StateFile string
	// Source fetches the platform's key set (optional).
	Source KeySetSource
	// Now is the clock (default time.Now).
	Now func() time.Time
	// OnChange is called after a newer key set was accepted (optional).
	OnChange func(*KeySet)
}

// KeySetTrust holds the current key set of a pinned root: the online keys
// a sensor accepts job signatures from. It is safe for concurrent use.
type KeySetTrust struct {
	root      string
	stateFile string
	source    KeySetSource
	now       func() time.Time
	onChange  func(*KeySet)

	mu        sync.Mutex
	raw       []byte
	ks        *KeySet
	pubs      map[string]ed25519.PublicKey
	lastFetch time.Time
	lastErr   error
}

// keySetState is the StateFile's content.
type keySetState struct {
	Version int             `json:"version"`
	KeySet  json.RawMessage `json:"keyset"`
}

// NewKeySetTrust returns the trust for cfg, with the key set the state
// file holds (an expired one too: it still sets the lowest version
// accepted). A state file that cannot be read, or holds a key set that is
// not the pinned root's, is an error: the sensor does not start rather
// than forget the version it reached.
func NewKeySetTrust(cfg KeySetConfig) (*KeySetTrust, error) {
	if cfg.Root == "" {
		return nil, errors.New("job-signing key set: no root is pinned")
	}
	t := &KeySetTrust{root: cfg.Root, stateFile: cfg.StateFile, source: cfg.Source, now: cfg.Now, onChange: cfg.OnChange}
	if t.now == nil {
		t.now = time.Now
	}
	if t.stateFile == "" {
		return t, nil
	}
	b, err := os.ReadFile(t.stateFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return t, nil
	case err != nil:
		return nil, fmt.Errorf("job-signing key set: read %s: %w", t.stateFile, err)
	}
	var st keySetState
	if err := json.Unmarshal(b, &st); err != nil || st.Version != 1 {
		return nil, fmt.Errorf("job-signing key set: %s is corrupt; restore it (removing it lets an older key set be accepted again)", t.stateFile)
	}
	ks, err := parseKeySet(st.KeySet, t.root)
	if err != nil {
		return nil, fmt.Errorf("job-signing key set: %s holds a key set this sensor does not accept (%v); if the root was replaced on purpose, move the file away", t.stateFile, err)
	}
	t.install(st.KeySet, ks)
	return t, nil
}

// Root is the pinned root key id.
func (t *KeySetTrust) Root() string { return t.root }

// Current is the accepted key set (possibly expired); nil when none.
func (t *KeySetTrust) Current() *KeySet {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ks
}

// Accept checks envelope and makes it the current key set: signed by the
// pinned root and current (VerifyKeySet), and not a rollback: a lower
// version than the current one is refused, and the same version only with
// the same bytes. A newer key set is on disk before it is used. It reports
// whether the key set changed.
func (t *KeySetTrust) Accept(envelope []byte) (bool, error) {
	changed, ks, err := t.accept(bytes.TrimSpace(envelope))
	if changed && t.onChange != nil {
		t.onChange(ks)
	}
	return changed, err
}

func (t *KeySetTrust) accept(envelope []byte) (bool, *KeySet, error) {
	ks, err := VerifyKeySet(envelope, t.root, t.now())
	if err != nil {
		return false, nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur := t.ks; cur != nil {
		switch {
		case ks.Version < cur.Version:
			return false, nil, refusef(ReasonKeySet, "key set version %d is older than the accepted version %d (rollback)", ks.Version, cur.Version)
		case ks.Version == cur.Version && !bytes.Equal(envelope, t.raw):
			return false, nil, refusef(ReasonKeySet, "key set version %d differs from the accepted key set of the same version", ks.Version)
		case ks.Version == cur.Version:
			return false, nil, nil
		}
	}
	if err := t.persist(envelope); err != nil {
		return false, nil, refusef(ReasonKeySet, "cannot record the key set: %v", err)
	}
	t.install(envelope, ks)
	return true, ks, nil
}

// install sets the current key set. Called with mu held (or before use).
func (t *KeySetTrust) install(raw []byte, ks *KeySet) {
	pubs := make(map[string]ed25519.PublicKey, len(ks.Keys))
	for _, k := range ks.Keys {
		if p, err := k.Decode(); err == nil {
			pubs[k.KeyID] = p
		}
	}
	t.raw, t.ks, t.pubs = bytes.Clone(raw), ks, pubs
}

// Refresh fetches the platform's key set and accepts it. Unless force, a
// fetch happens at most every KeySetRefreshInterval. A platform that serves
// none leaves the current key set as it is.
func (t *KeySetTrust) Refresh(ctx context.Context, force bool) error {
	if t.source == nil {
		return nil
	}
	t.mu.Lock()
	now := t.now()
	if !force && !t.lastFetch.IsZero() && now.Sub(t.lastFetch) < KeySetRefreshInterval {
		err := t.lastErr
		t.mu.Unlock()
		return err
	}
	t.lastFetch = now
	t.mu.Unlock()

	raw, err := t.source(ctx)
	if err == nil && len(bytes.TrimSpace(raw)) > 0 {
		_, err = t.Accept(raw)
	}
	t.mu.Lock()
	t.lastErr = err
	t.mu.Unlock()
	return err
}

// key is the public key of id in the current key set. A missing or
// expired key set is a ReasonKeySet refusal; a key the key set does not
// list is (nil, nil).
func (t *KeySetTrust) key(id string) (ed25519.PublicKey, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ks == nil {
		detail := "this sensor pins the job-signing root " + t.root + " and holds no key set yet"
		if t.lastErr != nil {
			detail += " (" + t.lastErr.Error() + ")"
		}
		return nil, refusef(ReasonKeySet, "%s", detail)
	}
	if err := t.ks.current(t.now()); err != nil {
		return nil, err
	}
	return t.pubs[id], nil
}

// persist writes the key set: a temporary file, fsync, rename, then the
// directory fsync'd. Called with mu held.
func (t *KeySetTrust) persist(raw []byte) error {
	if t.stateFile == "" {
		return nil
	}
	b, err := json.Marshal(keySetState{Version: 1, KeySet: raw})
	if err != nil {
		return err
	}
	return writeFileSync(t.stateFile, append(b, '\n'))
}

// writeFileSync replaces path with b durably (0600).
func writeFileSync(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
