package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// Pending is the pairing request in flight, kept in pairing.json so a
// restart (a Ctrl-C, a crash, a container restart) resumes it instead of
// starting a request the platform would have to supersede. It holds nothing
// secret: the platform's public key, the short authentication string and
// the code the console shows are all displayed to the operator anyway.
type Pending struct {
	PairingID string    `json:"pairing_id"`
	ExpiresAt time.Time `json:"expires_at"`
	SAS       string    `json:"sas"`
	// KeyID is the thumbprint of the key the request was made with.
	KeyID string `json:"key_thumbprint"`
	// CodeUsed: the request carried a pairing code (single use, spent with
	// the request); CodePrefix is the first 4 characters of it, to tell it
	// from a new code the operator configured since.
	CodeUsed   bool   `json:"code_used"`
	CodePrefix string `json:"code_prefix,omitempty"`
	// Repair: the request re-pairs an existing registration.
	Repair bool `json:"repair"`
	// UserCode is the code the console asks for (a request without a code).
	UserCode string `json:"user_code,omitempty"`
	// Link is the page to approve the request on (already checked by
	// safeLink when it was saved).
	Link string `json:"link,omitempty"`
	// PlatformURL and PlatformKey bind the request to the platform that
	// made it, so it is never resumed against another one.
	PlatformURL string `json:"platform_url"`
	PlatformKey string `json:"platform_key"`
	PollSeconds int    `json:"poll_seconds,omitempty"`
	// SpentCodePrefix: a code (first 4 characters) whose request ended
	// before this one; it is not sent again.
	SpentCodePrefix string `json:"spent_code_prefix,omitempty"`
}

// LoadPending returns the pairing request in flight, or nil when there is
// none. An unreadable or malformed file is an error only when its
// permissions are wrong; a malformed one is treated as absent (the request
// it described cannot be resumed anyway).
func (s *Store) LoadPending() (*Pending, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.pairingPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", s.pairingPath(), err)
	}
	var p Pending
	if json.Unmarshal(b, &p) != nil || p.PairingID == "" || p.KeyID == "" || p.PlatformKey == "" {
		return nil, nil
	}
	return &p, nil
}

// SavePending records the request in flight (0600, atomically).
func (s *Store) SavePending(p *Pending) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.pairingPath(), append(b, '\n'))
}

// ClearPending removes the request in flight.
func (s *Store) ClearPending() {
	_ = os.Remove(s.pairingPath())
}
