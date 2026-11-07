package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HoldFile keeps a pairing stop in the state directory (research/468 D8):
// a refused enrollment token, an answer without a valid platform signature,
// or a platform that does not sign pairing answers. A restart honors it, so
// a sensor in a restart loop does not call the platform again before it
// ends.
const HoldFile = "pairing-hold.json"

// The hold after the first stop, doubling with each stop in a row up to
// holdMax.
const (
	holdMin = 15 * time.Minute
	holdMax = 6 * time.Hour
)

// Hold is a pairing stop kept across restarts.
type Hold struct {
	// Until is when pairing may be tried again.
	Until time.Time `json:"until"`
	// Reason is the stop, as printed to the operator (no secret: the
	// errors name no token or key).
	Reason string `json:"reason"`
	// Inputs identifies the settings the stop happened with (a digest of
	// the platform URL, the enrollment token and the pairing code, never
	// the values): new settings start pairing at once.
	Inputs string `json:"inputs"`
	// Stops is the number of stops in a row (the next hold doubles).
	Stops int `json:"stops"`
}

func (s *Store) holdPath() string { return filepath.Join(s.dir, HoldFile) }

// LoadHold returns the pairing hold, or nil when there is none (a
// malformed file is treated as absent).
func (s *Store) LoadHold() (*Hold, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.holdPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", s.holdPath(), err)
	}
	var h Hold
	if json.Unmarshal(b, &h) != nil || h.Until.IsZero() {
		return nil, nil
	}
	return &h, nil
}

// SaveHold records the hold (0600, atomically).
func (s *Store) SaveHold(h *Hold) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.holdPath(), append(b, '\n'))
}

// ClearHold removes the hold.
func (s *Store) ClearHold() {
	_ = os.Remove(s.holdPath())
}

// holdInputs is the digest of the settings a stop happened with.
func holdInputs(o *PairOptions) string {
	h := sha256.New()
	for _, v := range []string{"openctem/pairing-hold/v1", strings.TrimRight(o.BaseURL, "/"), o.EnrollmentToken, o.Code, o.RepairSensorID} {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// holdable reports whether err is a stop that holds pairing: retrying
// soon cannot change it, and a restart loop would only hammer the
// platform.
func holdable(err error) bool {
	return errors.Is(err, ErrEnrollmentRefused) || errors.Is(err, errGrant) || errors.Is(err, ErrTLSAnchorMismatch) ||
		errors.Is(err, ErrPlatformUnsignedPairing)
}

// nextHold is the hold after a stop: holdMin, doubled for each earlier stop
// with the same settings, up to holdMax.
func nextHold(prev *Hold, inputs string, now time.Time, reason string) *Hold {
	stops := 1
	if prev != nil && prev.Inputs == inputs {
		stops = prev.Stops + 1
	}
	d := holdMin
	for i := 1; i < stops && d < holdMax; i++ {
		d *= 2
	}
	return &Hold{Until: now.Add(min(d, holdMax)), Reason: reason, Inputs: inputs, Stops: stops}
}

// waitHold waits out a hold kept by an earlier run with the same settings,
// without calling the platform. A hold for other settings is removed.
func waitHold(ctx context.Context, o *PairOptions) error {
	h, err := o.Store.LoadHold()
	if err != nil || h == nil {
		return err
	}
	if h.Inputs != holdInputs(o) {
		o.Store.ClearHold()
		return nil
	}
	left := time.Until(h.Until)
	if left <= 0 {
		return nil
	}
	_, _ = fmt.Fprintf(o.Out, "Pairing is on hold until %s: %s\nA restart does not try sooner. Fix the cause, then change the setting "+
		"(a new enrollment token or pairing code) to try at once, or remove %s.\n",
		h.Until.UTC().Format(time.RFC3339), h.Reason, filepath.Join(o.Store.Dir(), HoldFile))
	return o.sleep(ctx, left)
}
