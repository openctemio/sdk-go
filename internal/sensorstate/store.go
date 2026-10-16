package sensorstate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SensorCredentials is the format of the credentials file
// (FileCredentialStore). The sensor id is written as "sensor_id"; files
// written before the agent -> sensor rename carry "agent_id" and are still
// read (see UnmarshalJSON).
type SensorCredentials struct {
	SensorID  string `json:"sensor_id"`
	APIKey    string `json:"api_key"`
	APIPrefix string `json:"api_prefix"`
	// ExpiresAt is the key's expiry when known (from a key renewal). Pass it
	// to KeyRenewConfig.CurrentKeyExpiresAt on startup so the renewer does
	// not rotate a still-valid key immediately.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// ConfiguredKeyFingerprint is the salted PBKDF2 fingerprint
	// (KeyFingerprint) of the configured key APIKey was renewed from. When
	// the configured key no longer matches it, an administrator issued a new
	// key and the operator configured it: ChooseAPIKey then uses the
	// configured key. Empty in files written before it existed.
	ConfiguredKeyFingerprint string `json:"configured_key_fingerprint,omitempty"`
	// NeverExpires records that the server issued APIKey without an expiry
	// (its key TTL is off), as opposed to an expiry that is not known. Pass it
	// to KeyRenewConfig.CurrentKeyNeverExpires so a restart does not rotate
	// the key again just to learn that.
	NeverExpires bool `json:"never_expires,omitempty"`
}

// FileCredentialStore stores credentials in a file.
type FileCredentialStore struct {
	Path string
}

// NewFileCredentialStore creates a new file-based credential store.
func NewFileCredentialStore(path string) *FileCredentialStore {
	return &FileCredentialStore{Path: path}
}

// Save saves credentials to the file.
//
// The write is atomic and owner-only: the JSON goes to a 0600 temp file in
// the same directory, is fsynced, then renamed over Path. A crash or full
// disk mid-write therefore never leaves a truncated credentials file (which
// would lose the only copy of a rotated key), and a pre-existing file with
// looser permissions is replaced by a 0600 one rather than rewritten in
// place with its old mode.
func (s *FileCredentialStore) Save(creds *SensorCredentials) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	if err := writeFileAtomic(s.Path, data); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to path via temp file + fsync + rename, with
// mode 0600. The parent directory is created 0700 if missing.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp already uses 0600; Chmod makes it explicit and independent
	// of platform defaults.
	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	// Persist the rename itself. Best effort: not supported on every OS.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Load loads credentials from the file.
func (s *FileCredentialStore) Load() (*SensorCredentials, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}
	var creds SensorCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}
	return &creds, nil
}

// Exists checks if the credentials file exists.
func (s *FileCredentialStore) Exists() bool {
	_, err := os.Stat(s.Path)
	return err == nil
}
