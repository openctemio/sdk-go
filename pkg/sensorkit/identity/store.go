// Package identity is a key-bound sensor's identity on disk and the
// interactive pairing that creates it (api RFC-052): the sensor makes its
// own Ed25519 key, pairs with the platform (an administrator compares the
// short authentication string and approves), and from then on signs every
// request with that key. No secret is ever typed, copied or pasted.
//
// On disk, in <state dir>/identity/ (directory 0700):
//
//	signing.key    the Ed25519 private key, PKCS #8 PEM, 0600
//	identity.json  what the platform granted (sensor id, tenant, key id), 0600
//
// Both files and the directory must belong to the user the sensor runs as
// and must not be readable or writable by anyone else; otherwise Load and
// Check refuse with the exact chmod/chown to run (RFC-052 D-7).
//
// Stability: Beta (docs/STABILITY.md).
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// File and directory names inside the state directory.
const (
	DirName      = "identity"
	KeyFile      = "signing.key"
	IdentityFile = "identity.json"

	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600
)

var (
	// ErrNoIdentity: the sensor has not been paired (no identity.json).
	ErrNoIdentity = errors.New("identity: the sensor is not paired")
	// ErrNoKey: there is no signing key yet.
	ErrNoKey = errors.New("identity: no signing key")
)

// Identity is what the platform granted the sensor at pairing.
type Identity struct {
	// PlatformURL is the API URL the sensor paired with.
	PlatformURL string `json:"platform_url"`
	SensorID    string `json:"sensor_id"`
	TenantID    string `json:"tenant_id"`
	TenantName  string `json:"tenant_name,omitempty"`
	Name        string `json:"name"`
	// KeyID is the RFC 7638 thumbprint of the signing key; it must match
	// signing.key.
	KeyID string `json:"key_id"`
	// PlatformKey is the platform's pairing key (base64url), kept so a
	// later re-pair can be checked against it.
	PlatformKey string    `json:"platform_key,omitempty"`
	PairedAt    time.Time `json:"paired_at"`
	// RequireLocalPolicy is true for an identity paired by an SDK that
	// fails closed without a sensor-local policy: such a sensor refuses
	// every job with network targets until one is installed
	// (core.LocalPolicy.Required; SENSOR_REQUIRE_LOCAL_POLICY overrides
	// it). An identity written by an older SDK has no such field and is a
	// legacy install that keeps its behavior.
	RequireLocalPolicy bool `json:"require_local_policy,omitempty"`
	// PlatformTLSPin is the platform's TLS identity pinned at pairing,
	// "sha256:<64 hex digits>", and PlatformTLSPinElement what it is the
	// fingerprint of: httpsec.PinElementAnchorSPKI (the SubjectPublicKeyInfo
	// of the trust anchor the pairing connection verified) or
	// httpsec.PinElementCACert (a CA certificate, SENSOR_CA_FINGERPRINT at
	// pairing). Every platform client enforces it (SENSOR_CA_FINGERPRINT
	// overrides it). Empty: an identity paired over plain http or by an
	// older SDK, which keeps trusting the trust store (posture pin none).
	PlatformTLSPin        string `json:"platform_tls_pin,omitempty"`
	PlatformTLSPinElement string `json:"platform_tls_pin_element,omitempty"`
	// JobSigningKeys are the platform job signer's keys the hello listed
	// right after pairing (trust on first use, over the pinned and signed
	// pairing connection; api RFC-040 §5.6). A sensor whose identity pins
	// them requires signed jobs (SENSOR_REQUIRE_SIGNED_JOBS overrides it).
	// Empty: paired by an older SDK or with a platform that does not sign
	// jobs; such a sensor runs unsigned jobs as before.
	JobSigningKeys []jobsig.PublicKey `json:"job_signing_keys,omitempty"`
	// JobSigningRoot is the key id of the installation's offline
	// job-signing root, taken at pairing from the key set the hello served
	// (trust on first use, like JobSigningKeys). With a root, job
	// signatures are accepted from the keys of its current key set, and
	// JobSigningKeys are not used: rotating or revoking a signer key is a
	// new key set, not a new pairing. SENSOR_JOB_SIGNING_ROOT overrides it.
	JobSigningRoot string `json:"job_signing_root,omitempty"`
}

// TLSPin parses the platform TLS pin: the element and the SHA-256
// fingerprint, or "" and nil when the identity has none. A malformed pin is
// an error (the sensor refuses to start rather than run unpinned).
func (id *Identity) TLSPin() (string, []byte, error) {
	if id.PlatformTLSPin == "" && id.PlatformTLSPinElement == "" {
		return "", nil, nil
	}
	switch id.PlatformTLSPinElement {
	case httpsec.PinElementAnchorSPKI, httpsec.PinElementCACert:
	default:
		return "", nil, fmt.Errorf("identity: platform_tls_pin_element %q is not %s or %s; pair again",
			id.PlatformTLSPinElement, httpsec.PinElementAnchorSPKI, httpsec.PinElementCACert)
	}
	if !strings.HasPrefix(id.PlatformTLSPin, "sha256:") {
		return "", nil, errors.New("identity: platform_tls_pin must be sha256:<64 hex digits>; pair again")
	}
	fp, err := httpsec.ParseCAFingerprint(id.PlatformTLSPin)
	if err != nil {
		return "", nil, fmt.Errorf("identity: platform_tls_pin: %w; pair again", err)
	}
	return id.PlatformTLSPinElement, fp, nil
}

// Store is the identity directory under a state directory.
type Store struct {
	dir string
}

// NewStore returns the store of stateDir (the identity lives in
// stateDir/identity).
func NewStore(stateDir string) *Store { return &Store{dir: filepath.Join(stateDir, DirName)} }

// Dir is the identity directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) keyPath() string      { return filepath.Join(s.dir, KeyFile) }
func (s *Store) identityPath() string { return filepath.Join(s.dir, IdentityFile) }

// PermissionError is an identity file or directory with looser permissions
// or another owner than allowed. Fix is the command that repairs it.
type PermissionError struct {
	Path   string
	Reason string
	Fix    string
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("identity: %s %s; the sensor refuses to start until it is fixed: %s", e.Path, e.Reason, e.Fix)
}

// Check verifies the directory and every file in it that exists: owned by
// the current user, the directory 0700 at most, the files 0600 at most, no
// symbolic links. A missing directory is not an error.
func (s *Store) Check() error {
	if err := checkPath(s.dir, true); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, f := range []string{s.keyPath(), s.identityPath()} {
		if err := checkPath(f, false); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func checkPath(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return &PermissionError{Path: path, Reason: "is a symbolic link", Fix: "replace it with a regular " + kind(dir)}
	}
	if dir != fi.IsDir() {
		return &PermissionError{Path: path, Reason: "is not a " + kind(dir), Fix: "remove it and pair again"}
	}
	return checkAccess(path, fi, dir)
}

func kind(dir bool) string {
	if dir {
		return "directory"
	}
	return "file"
}

// ensureDir creates the directory (0700) or checks the existing one.
func (s *Store) ensureDir() error {
	if err := os.MkdirAll(s.dir, dirMode); err != nil {
		return fmt.Errorf("identity: create %s: %w", s.dir, err)
	}
	return checkPath(s.dir, true)
}

// LoadKey reads the signing key. ErrNoKey when there is none.
func (s *Store) LoadKey() (*sensorsig.Signer, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.keyPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, fmt.Errorf("identity: read key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("identity: %s is not a PKCS #8 PEM private key", s.keyPath())
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parse key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity: %s is not an Ed25519 key", s.keyPath())
	}
	return sensorsig.NewSigner(priv)
}

// EnsureKey returns the signing key, creating it (0600, in a 0700
// directory) when there is none. A key survives restarts, so a sensor
// waiting for approval keeps the key the administrator compares.
func (s *Store) EnsureKey() (*sensorsig.Signer, error) {
	sg, err := s.LoadKey()
	if !errors.Is(err, ErrNoKey) {
		return sg, err
	}
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(s.keyPath(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return s.LoadKey() // another process made it first
		}
		return nil, err
	}
	return sensorsig.NewSigner(priv)
}

// RotateKey replaces the signing key with a new one and removes the
// identity (re-pair: the old key is lost or suspected stolen). The old key
// file is overwritten atomically.
func (s *Store) RotateKey() (*sensorsig.Signer, error) {
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(s.keyPath(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	if err := os.Remove(s.identityPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return sensorsig.NewSigner(priv)
}

// Load returns the identity and its signing key. ErrNoIdentity when the
// sensor is not paired; an error when the identity does not belong to the
// key on disk.
func (s *Store) Load() (*Identity, *sensorsig.Signer, error) {
	if err := s.Check(); err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(s.identityPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ErrNoIdentity
	}
	if err != nil {
		return nil, nil, fmt.Errorf("identity: read: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, nil, fmt.Errorf("identity: %s: %w", s.identityPath(), err)
	}
	if id.SensorID == "" || id.KeyID == "" {
		return nil, nil, fmt.Errorf("identity: %s is incomplete; pair again", s.identityPath())
	}
	sg, err := s.LoadKey()
	if errors.Is(err, ErrNoKey) {
		return nil, nil, fmt.Errorf("identity: %s exists but %s is missing; pair again", s.identityPath(), s.keyPath())
	}
	if err != nil {
		return nil, nil, err
	}
	if sg.KeyID() != id.KeyID {
		return nil, nil, fmt.Errorf("identity: %s names key %s but %s holds key %s; pair again",
			s.identityPath(), id.KeyID, s.keyPath(), sg.KeyID())
	}
	return &id, sg, nil
}

// Save writes the identity (0600, atomically).
func (s *Store) Save(id *Identity) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.identityPath(), append(b, '\n'))
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	return os.Rename(name, path)
}
