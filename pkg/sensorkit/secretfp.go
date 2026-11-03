package sensorkit

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/openctemio/ctis/v2/fingerprint"
)

// SecretFingerprintKeyFile keeps, in the state directory, the sensor's HMAC
// key for secret fingerprints (CTIS recipe ctis-fp/2: the secret enters a
// fingerprint only as HMAC-SHA256(key, secret)). It is created once, 32
// random bytes, mode 0600, and never leaves the sensor: one key per
// installation, so two installations cannot confirm each other's secrets,
// and stable, so a secret keeps its fingerprint across restarts.
const SecretFingerprintKeyFile = "secret-fingerprint.key"

const secretFingerprintKeyBytes = 32

// loadSecretFingerprintKey returns the key in stateDir, creating it on
// first use. Without a state directory there is no key (secret findings
// then carry no fingerprint; the platform computes its own).
func loadSecretFingerprintKey(stateDir string) ([]byte, error) {
	if stateDir == "" {
		return nil, nil
	}
	path := filepath.Join(stateDir, SecretFingerprintKeyFile)
	key, err := os.ReadFile(path) //nolint:gosec // a fixed name in the sensor's own state directory
	switch {
	case err == nil:
		if len(key) < fingerprint.MinSecretKeyBytes {
			return nil, fmt.Errorf("%s: %d bytes, at least %d", path, len(key), fingerprint.MinSecretKeyBytes)
		}
		return key, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	key = make([]byte, secretFingerprintKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(stateDir, ".secret-fingerprint-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	// Link, not rename: a key another process created first wins, and both
	// then read the same one.
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return loadSecretFingerprintKey(stateDir)
		}
		return nil, err
	}
	return key, nil
}

// secretFingerprintKey is the kit's key (nil when it has no state directory
// or the key cannot be read; the reason is logged once).
func (k *Kit) secretFingerprintKey() []byte {
	k.secretKeyOnce.Do(func() {
		key, err := loadSecretFingerprintKey(k.s.stateDir)
		if err != nil {
			_, _ = fmt.Fprintf(k.errw, "secret fingerprints are off: %v\n", err)
			return
		}
		k.secretKey = key
	})
	return k.secretKey
}
