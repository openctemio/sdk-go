package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// DefaultCredentialsFile is where a sensor keeps its credentials when no path
// is configured: ~/.openctem/sensor-credentials.json.
func DefaultCredentialsFile() (string, error) {
	return homeFile(legacyv1.CredentialsFileName)
}

// LegacyCredentialsFile is the default credentials path of sensors from
// before the agent -> sensor rename: ~/.openctem/agent-credentials.json.
func LegacyCredentialsFile() (string, error) {
	return homeFile(legacyv1.LegacyCredentialsFileName)
}

func homeFile(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for the credentials file: %w", err)
	}
	return filepath.Join(home, ".openctem", name), nil
}

// ErrCredentialsFileNotMoved is returned by MigrateCredentialsFile when the
// old file is valid but could not be moved (a read-only volume, a Kubernetes
// Secret, a single bind-mounted file). Nothing was changed.
var ErrCredentialsFileNotMoved = errors.New("credentials file not moved")

// ResolveCredentialsFile returns the credentials file a sensor should use.
// An explicit path is returned as is. With an empty path it returns
// DefaultCredentialsFile, after moving a pre-rename credentials file there
// (MigrateCredentialsFile), so an upgraded sensor keeps its identity and API
// key without registering again. When the old file cannot be moved (see
// ErrCredentialsFileNotMoved) it is used where it is, with a warning, so a
// deployment that mounts it read-only keeps starting exactly as before.
func ResolveCredentialsFile(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	path, err := DefaultCredentialsFile()
	if err != nil {
		return "", err
	}
	legacy, err := LegacyCredentialsFile()
	if err != nil {
		return "", err
	}
	if _, err := MigrateCredentialsFile(legacy, path); err != nil {
		if errors.Is(err, ErrCredentialsFileNotMoved) {
			slog.Warn("cannot move the credentials file to its new name; using it at its old path",
				"path", legacy, "new_name", path, "reason", err.Error())
			return legacy, nil
		}
		return "", err
	}
	return path, nil
}

// MigrateCredentialsFile moves the credentials file at from to to, without
// ever leaving the sensor with no readable credentials:
//
//  1. from is read and parsed (an unreadable or invalid file is an error, not
//     a reason to register a second sensor);
//  2. the credentials are written to to atomically — temp file with mode
//     0600, fsync, rename, directory fsync;
//  3. to is read back and compared with what was read from from;
//  4. only then is from removed.
//
// An interruption at any step leaves from in place, and the next start
// migrates again. If writing to, verifying it or removing from fails, to is
// removed again and the error wraps ErrCredentialsFileNotMoved: the state is
// exactly as before. When to already exists it wins: from is left untouched
// and a warning names both files. When from does not exist there is nothing
// to do. It reports whether a file was moved.
func MigrateCredentialsFile(from, to string) (moved bool, err error) {
	return migrateCredentialsFile(from, to, true)
}

// migrateCredentialsFile is MigrateCredentialsFile; requireSensorID refuses
// a file without a sensor id (a daemon that renews its key may not know its
// id, so the move into the state directory does not require one).
func migrateCredentialsFile(from, to string, requireSensorID bool) (moved bool, err error) {
	if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("stat %s: %w", from, err)
	}
	if _, err := os.Lstat(to); err == nil {
		slog.Warn("both the old and the new credentials file exist; using the new one and leaving the old one in place (remove it once the sensor runs)",
			"used", to, "ignored", from)
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("stat %s: %w", to, err)
	}

	old := NewFileCredentialStore(from)
	creds, err := old.Load()
	if err != nil {
		return false, fmt.Errorf("migrate credentials from %s: %w", from, err)
	}
	if (requireSensorID && creds.SensorID == "") || creds.APIKey == "" {
		return false, fmt.Errorf("migrate credentials from %s: the file has no sensor id or API key", from)
	}

	store := NewFileCredentialStore(to)
	undo := func(cause error) (bool, error) {
		_ = os.Remove(to)
		return false, fmt.Errorf("%w from %s to %s: %w", ErrCredentialsFileNotMoved, from, to, cause)
	}
	if err := store.Save(creds); err != nil {
		return undo(err)
	}
	back, err := store.Load()
	if err != nil {
		return undo(fmt.Errorf("read back: %w", err))
	}
	if !sameCredentials(creds, back) {
		return undo(errors.New("the new file does not read back as written"))
	}
	if err := os.Remove(from); err != nil {
		return undo(fmt.Errorf("remove the old file: %w", err))
	}
	syncDir(filepath.Dir(from))
	slog.Warn("moved the credentials file to its new name (sensor rename)", "from", from, "to", to)
	return true, nil
}

func sameCredentials(a, b *SensorCredentials) bool {
	if a.SensorID != b.SensorID || a.APIKey != b.APIKey || a.APIPrefix != b.APIPrefix ||
		a.ConfiguredKeyFingerprint != b.ConfiguredKeyFingerprint || a.NeverExpires != b.NeverExpires {
		return false
	}
	if (a.ExpiresAt == nil) != (b.ExpiresAt == nil) {
		return false
	}
	return a.ExpiresAt == nil || a.ExpiresAt.Equal(*b.ExpiresAt)
}

// syncDir persists a rename or removal in dir. Best effort: not supported on
// every OS.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { //nolint:gosec // the credentials directory
		_ = d.Sync()
		_ = d.Close()
	}
}

// UnmarshalJSON reads both the current "sensor_id" key and the "agent_id"
// key credentials files written before the agent -> sensor rename carry.
// Both present with different values is an error: the file has been edited
// by hand and the sensor's identity is ambiguous.
func (c *SensorCredentials) UnmarshalJSON(data []byte) error {
	type plain SensorCredentials
	var v struct {
		plain
		LegacySensorID string `json:"agent_id"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if v.LegacySensorID != "" {
		if v.SensorID != "" && v.SensorID != v.LegacySensorID {
			return fmt.Errorf("credentials: %q and %q are both set to different values", "sensor_id", legacyv1.FieldSensorID)
		}
		v.SensorID = v.LegacySensorID
	}
	*c = SensorCredentials(v.plain)
	return nil
}
