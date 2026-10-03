package core

// The sensor's stored settings document (api RFC-038,
// docs/rfcs/RFC-038-sensor-tool-settings.md): the last settings the platform
// issued and the sensor accepted, kept on the state volume so a restart or an
// offline period runs with them.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SettingsDocumentKind is the kind of a settings document.
const SettingsDocumentKind = "openctem.sensor.settings/v1"

// SettingsFileName is the file a FileSettingsStore keeps in its directory.
const SettingsFileName = "tool-settings.json"

// MaxSettingsDocumentBytes bounds a stored settings document.
const MaxSettingsDocumentBytes = 4 << 20

// ErrSettingsVersionNotNewer is returned by SettingsStore.Save for a
// document whose version is not above the stored one: settings only move
// forward, so a replayed or reordered older document is refused.
var ErrSettingsVersionNotNewer = errors.New("settings document is not newer than the stored one")

// SensorSettings is a settings document: per tool, the values the
// platform validated against the schema with SchemaDigest.
type SensorSettings struct {
	Kind     string                       `json:"kind"`
	SensorID string                       `json:"sensor_id"`
	TenantID string                       `json:"tenant_id,omitempty"`
	Version  int64                        `json:"version"`
	IssuedAt time.Time                    `json:"issued_at"`
	Tools    map[string]ToolSettingsBlock `json:"tools"`
	// Signature is the platform's signature over the document, when it
	// signs (not verified by the store).
	Signature *SettingsSignature `json:"signature,omitempty"`
}

// ToolSettingsBlock is one tool's part of a settings document.
type ToolSettingsBlock struct {
	SchemaDigest string         `json:"schema_digest"`
	Values       map[string]any `json:"values"`
	// SealedSecrets are the tool's secret values sealed to the sensor's
	// key; kept sealed on disk.
	SealedSecrets string `json:"sealed_secrets,omitempty"`
}

// SettingsSignature is a detached signature over a settings document.
type SettingsSignature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Check verifies the document's shape: kind, a positive version, and a
// schema digest for every tool block. It does not validate the values (that
// needs the tools' schemas: ValidateAgainst).
func (d *SensorSettings) Check() error {
	if d == nil {
		return errors.New("settings document: nil")
	}
	if d.Kind != SettingsDocumentKind {
		return fmt.Errorf("settings document: kind %q, want %q", d.Kind, SettingsDocumentKind)
	}
	if d.Version <= 0 {
		return errors.New("settings document: version must be positive")
	}
	for tool, b := range d.Tools {
		if b.SchemaDigest == "" {
			return fmt.Errorf("settings document: tool %q has no schema digest", tool)
		}
	}
	return nil
}

// ValidateAgainst checks each tool block against the schema this sensor
// declares for the tool: the digests must match and the values must be
// valid. It returns the error of every rejected tool by name; tools not in
// the returned map are acceptable. A tool this sensor has no schema for is
// rejected.
func (d *SensorSettings) ValidateAgainst(schemas map[string]*SettingsSchema) map[string]error {
	out := map[string]error{}
	if d == nil {
		return out
	}
	for tool, b := range d.Tools {
		s := schemas[tool]
		switch {
		case s == nil:
			out[tool] = errors.New("this sensor has no settings for the tool")
		case s.Digest() != b.SchemaDigest:
			out[tool] = fmt.Errorf("schema mismatch: document has %s, this sensor declares %s", b.SchemaDigest, s.Digest())
		default:
			if err := s.Validate(b.Values); err != nil {
				out[tool] = err
			}
		}
	}
	return out
}

// SettingsStore keeps the sensor's settings document.
type SettingsStore interface {
	// Load returns the stored document, or nil when there is none.
	Load() (*SensorSettings, error)
	// Save stores a document atomically. It refuses a document that fails
	// Check or whose version is not above the stored one
	// (ErrSettingsVersionNotNewer).
	Save(*SensorSettings) error
}

// FileSettingsStore keeps the document as SettingsFileName in a directory:
// the directory 0700, the file 0600, written to a temporary file, synced
// and renamed into place.
type FileSettingsStore struct {
	dir string
	mu  sync.Mutex
}

// NewFileSettingsStore returns a store in dir (created 0700 on the first
// Save).
func NewFileSettingsStore(dir string) *FileSettingsStore {
	return &FileSettingsStore{dir: dir}
}

// Path is the document's file.
func (s *FileSettingsStore) Path() string { return filepath.Join(s.dir, SettingsFileName) }

// Load implements SettingsStore.
func (s *FileSettingsStore) Load() (*SensorSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *FileSettingsStore) loadLocked() (*SensorSettings, error) {
	f, err := os.Open(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("settings store: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxSettingsDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("settings store: %w", err)
	}
	if len(raw) > MaxSettingsDocumentBytes {
		return nil, fmt.Errorf("settings store: %s is larger than %d bytes", s.Path(), MaxSettingsDocumentBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var d SensorSettings
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("settings store: decode %s: %w", s.Path(), err)
	}
	if err := d.Check(); err != nil {
		return nil, fmt.Errorf("settings store: %s: %w", s.Path(), err)
	}
	return &d, nil
}

// Save implements SettingsStore.
func (s *FileSettingsStore) Save(d *SensorSettings) error {
	if err := d.Check(); err != nil {
		return err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("settings store: encode: %w", err)
	}
	if len(raw) > MaxSettingsDocumentBytes {
		return fmt.Errorf("settings store: document larger than %d bytes", MaxSettingsDocumentBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.loadLocked()
	if err != nil {
		return err
	}
	if cur != nil && d.Version <= cur.Version {
		return fmt.Errorf("%w (stored %d, got %d)", ErrSettingsVersionNotNewer, cur.Version, d.Version)
	}
	return writeSettingsFileAtomic(s.Path(), raw)
}

// writeSettingsFileAtomic writes data to path through a temporary file in
// the same directory (0600), synced and renamed; the directory is created
// 0700.
func writeSettingsFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("settings store: create directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("settings store: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("settings store: chmod temp file: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("settings store: write temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("settings store: sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("settings store: close temp file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("settings store: rename temp file: %w", err)
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
