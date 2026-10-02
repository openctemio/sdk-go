package platform

// The sensor's state directory and the API key kept in it (api RFC-032
// Phase 0, "renewal that survives a restart").
//
// A sensor that renews its own key (KeyRenewManager) must find the renewed
// key again after a restart: the server retires the key the sensor was
// installed with shortly after the renewal, so a container recreated with
// only its original API_KEY would come back with a dead key. The renewed key
// therefore lives in a credentials file in the state directory, which the
// install snippets and the Helm chart mount on a persistent volume, and it is
// preferred over the configured key on start (ChooseAPIKey).

import (
	"bufio"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// State directory defaults.
const (
	// DefaultStateDir is where a sensor keeps its state when nothing else is
	// configured and the directory is usable. The images create it for the
	// sensor user; the install snippets mount a volume on it.
	DefaultStateDir = "/var/lib/openctem/state"
	// EnvStateDir overrides the state directory.
	EnvStateDir = "SENSOR_STATE_DIR"
)

// ResolveStateDir returns the sensor's state directory: explicit, else
// $SENSOR_STATE_DIR, else DefaultStateDir when it exists or can be created
// and is writable, else ~/.openctem (a sensor binary run by a user without
// /var/lib/openctem). The returned directory may not exist yet only in the
// last case.
func ResolveStateDir(explicit string) string {
	if d := strings.TrimSpace(explicit); d != "" {
		return d
	}
	if d := strings.TrimSpace(os.Getenv(EnvStateDir)); d != "" {
		return d
	}
	if dirWritable(DefaultStateDir) {
		return DefaultStateDir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".openctem")
	}
	return DefaultStateDir
}

// dirWritable creates dir (0700) when missing and reports whether a file
// can be created in it.
func dirWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// StateCredentialsFile is the credentials file in a state directory.
func StateCredentialsFile(stateDir string) string {
	return filepath.Join(stateDir, legacyv1.CredentialsFileName)
}

// ResolveStateCredentialsFile returns the credentials file a sensor should
// use. An explicit path is returned as is. Otherwise it is the file in
// stateDir; a credentials file an earlier version kept in the home directory
// (~/.openctem/sensor-credentials.json, or the pre-rename
// agent-credentials.json) is moved there first (MigrateCredentialsFile), so
// an upgraded sensor keeps the key it renewed. When that file cannot be
// moved it is used where it is, with a warning.
func ResolveStateCredentialsFile(explicit, stateDir string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	target := StateCredentialsFile(stateDir)
	old, err := ResolveCredentialsFile("")
	if err != nil {
		// No home directory: nothing to migrate from.
		return target, nil //nolint:nilerr // the home file is optional
	}
	if filepath.Clean(old) == filepath.Clean(target) {
		return target, nil
	}
	if _, err := migrateCredentialsFile(old, target, false); err != nil {
		if errors.Is(err, ErrCredentialsFileNotMoved) {
			slog.Warn("cannot move the credentials file into the state directory; using it where it is",
				"path", old, "state_dir", stateDir, "reason", err.Error())
			return old, nil
		}
		// An unreadable or empty old file holds no key worth keeping: start
		// from the state directory and leave the old file alone.
		slog.Warn("ignoring an unusable credentials file", "path", old, "reason", err.Error())
	}
	return target, nil
}

// keyFingerprintIter is the PBKDF2 work factor (the OWASP 2023 figure for
// PBKDF2-HMAC-SHA256). The fingerprint is computed once per start and once
// per renewal, so the cost is paid rarely.
const keyFingerprintIter = 600_000

const keyFingerprintScheme = "pbkdf2-sha256"

// KeyFingerprint returns a salted PBKDF2-SHA256 fingerprint of an API key,
// "pbkdf2-sha256$<iterations>$<salt>$<hash>" (base64url, no padding). The
// credentials file keeps the fingerprint of the configured key its renewed
// key descends from, never the configured key itself; a fresh salt makes
// each fingerprint different, so compare with KeyFingerprintMatches.
func KeyFingerprint(key string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand does not fail on supported platforms; without a salt
		// there is no fingerprint, and ChooseAPIKey treats that as unknown.
		return ""
	}
	sum, err := pbkdf2.Key(sha256.New, key, salt, keyFingerprintIter, sha256.Size)
	if err != nil {
		return ""
	}
	enc := base64.RawURLEncoding
	return fmt.Sprintf("%s$%d$%s$%s", keyFingerprintScheme, keyFingerprintIter, enc.EncodeToString(salt), enc.EncodeToString(sum))
}

// KeyFingerprintMatches reports whether key has the fingerprint fp
// (KeyFingerprint). ok is false when fp is not a fingerprint this SDK can
// check (empty, malformed, another scheme), so the caller can treat it as
// unknown rather than as a different key.
func KeyFingerprintMatches(fp, key string) (match, ok bool) {
	parts := strings.Split(fp, "$")
	if len(parts) != 4 || parts[0] != keyFingerprintScheme {
		return false, false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false, false
	}
	enc := base64.RawURLEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) == 0 || len(want) != sha256.Size {
		return false, false
	}
	got, err := pbkdf2.Key(sha256.New, key, salt, iter, sha256.Size)
	if err != nil {
		return false, false
	}
	return subtle.ConstantTimeCompare(got, want) == 1, true
}

// KeyChoice is the API key a sensor starts with.
type KeyChoice struct {
	// APIKey is the key to use.
	APIKey string
	// ExpiresAt is its expiry when known (pass it to
	// KeyRenewConfig.CurrentKeyExpiresAt).
	ExpiresAt *time.Time
	// NeverExpires is true when the server said the key has no expiry (pass
	// it to KeyRenewConfig.CurrentKeyNeverExpires). False when unknown.
	NeverExpires bool
	// FromStateFile is true when the key is a renewed key read from the
	// credentials file rather than the configured one.
	FromStateFile bool
	// Reason explains the choice, for the sensor's log.
	Reason string
}

// ChooseAPIKey picks the key a sensor starts with, from its configured key
// (API_KEY, a flag, a config file) and the credentials file. The renewed key
// in the file wins, because a renewal retires the configured key, except:
//
//   - the file is missing, unreadable or empty, or belongs to another sensor
//     (sensorID set and different): the configured key;
//   - the configured key is not the one the file's key descends from (an
//     administrator regenerated the key and the operator configured the new
//     one): the configured key. The file is replaced on the next renewal.
//
// A file written before fingerprints existed has no fingerprint; its key
// wins, as it did before. With no configured key the file's key is used.
func ChooseAPIKey(store *FileCredentialStore, configuredKey, sensorID string) KeyChoice {
	configured := KeyChoice{APIKey: configuredKey, Reason: "configured key"}
	if store == nil || !store.Exists() {
		configured.Reason = "configured key (no credentials file)"
		return configured
	}
	creds, err := store.Load()
	if err != nil || creds == nil || creds.APIKey == "" {
		configured.Reason = "configured key (the credentials file has no usable key)"
		return configured
	}
	if sensorID != "" && creds.SensorID != "" && creds.SensorID != sensorID {
		configured.Reason = "configured key (the credentials file belongs to another sensor)"
		return configured
	}
	fromFile := KeyChoice{APIKey: creds.APIKey, ExpiresAt: creds.ExpiresAt, NeverExpires: creds.NeverExpires,
		FromStateFile: true, Reason: "renewed key from " + store.Path}
	switch {
	case configuredKey == "":
		return fromFile
	case creds.APIKey == configuredKey:
		configured.ExpiresAt, configured.NeverExpires = creds.ExpiresAt, creds.NeverExpires
		return configured
	case configuredKeyChanged(creds.ConfiguredKeyFingerprint, configuredKey):
		configured.Reason = "configured key (it changed since the credentials file was written; the file is replaced on the next renewal)"
		return configured
	default:
		return fromFile
	}
}

// configuredKeyChanged reports whether the configured key is not the one the
// file's key was renewed from. A missing or unreadable fingerprint is unknown,
// not a change: the file's key wins, as it did before fingerprints existed.
func configuredKeyChanged(fp, configuredKey string) bool {
	match, ok := KeyFingerprintMatches(fp, configuredKey)
	return ok && !match
}

// RotatedKeySaver returns a KeyRenewConfig.OnRotated that saves each renewed
// key, its expiry (or that it has none) and the fingerprint of configuredKey
// (the key the sensor was installed with) to the credentials file,
// atomically and 0600 (FileCredentialStore.Save).
func RotatedKeySaver(store *FileCredentialStore, configuredKey, sensorID string) func(newKey string, expiresAt *time.Time) error {
	var seed string
	if configuredKey != "" {
		seed = KeyFingerprint(configuredKey)
	}
	return func(newKey string, expiresAt *time.Time) error {
		prefix := newKey
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		if err := store.Save(&SensorCredentials{
			SensorID:                 sensorID,
			APIKey:                   newKey,
			APIPrefix:                prefix,
			ExpiresAt:                expiresAt,
			NeverExpires:             expiresAt == nil,
			ConfiguredKeyFingerprint: seed,
		}); err != nil {
			return fmt.Errorf("save the renewed key: %w", err)
		}
		return nil
	}
}

// StatePersistence says whether a state directory survives the sensor being
// recreated.
type StatePersistence struct {
	Persistent bool
	// Reason explains the verdict, for the sensor's log.
	Reason string
}

// Container and mount detection, replaceable in tests.
var (
	inContainerFunc  = inContainer
	mountInfoPath    = "/proc/self/mountinfo"
	errNoMountTables = errors.New("no mount table")
)

// CheckStatePersistence reports whether dir survives the sensor being
// recreated. Outside a container the host filesystem persists. Inside one,
// dir must be on a mounted volume (a Docker volume, a bind mount, a
// Kubernetes volume) that is not a tmpfs: the container's writable layer is
// lost when the container is recreated. A Kubernetes emptyDir looks like a
// volume and is lost with the pod; the Helm chart therefore decides key
// renewal explicitly instead of relying on this check.
func CheckStatePersistence(dir string) StatePersistence {
	if !inContainerFunc() {
		return StatePersistence{Persistent: true, Reason: "not in a container: the host filesystem persists"}
	}
	mountPoint, fsType, err := mountOf(dir)
	if err != nil {
		return StatePersistence{Reason: fmt.Sprintf("in a container and the mount table is unreadable (%v)", err)}
	}
	switch {
	case mountPoint == "/":
		return StatePersistence{Reason: dir + " is not on a mounted volume: the container's own filesystem is lost when the container is recreated"}
	case fsType == "tmpfs" || fsType == "ramfs":
		return StatePersistence{Reason: dir + " is on a " + fsType + " (memory)"}
	default:
		return StatePersistence{Persistent: true, Reason: dir + " is on a mounted volume (" + mountPoint + ")"}
	}
}

// DecideKeyAutoRenew turns a renewal setting into a decision: "true" / "on"
// / "1" renews, "false" / "off" / "0" does not, and "" or "auto" renews only
// when the state directory persists (a renewed key that is lost on restart
// locks the sensor out).
func DecideKeyAutoRenew(setting string, p StatePersistence) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(setting)) {
	case "true", "on", "1", "yes":
		return true, "enabled by configuration"
	case "false", "off", "0", "no":
		return false, "disabled by configuration"
	}
	if p.Persistent {
		return true, "state persists: " + p.Reason
	}
	return false, "off because the renewed key would not survive a restart: " + p.Reason
}

// inContainer reports whether this process runs in a container.
func inContainer() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(data)
	return strings.Contains(s, "docker") || strings.Contains(s, "kubepods") ||
		strings.Contains(s, "containerd") || strings.Contains(s, "libpod")
}

// mountOf returns the mount point dir is on and its filesystem type, from
// the mount table (the longest mount point that is a prefix of dir).
func mountOf(dir string) (mountPoint, fsType string, err error) {
	path := existingAncestor(dir)
	f, err := os.Open(mountInfoPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", "", errNoMountTables
		}
		return "", "", err
	}
	defer func() { _ = f.Close() }()
	best, bestType := "", ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		mp, typ, ok := parseMountInfoLine(sc.Text())
		if !ok || !underMount(path, mp) {
			continue
		}
		if len(mp) >= len(best) {
			best, bestType = mp, typ
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", err
	}
	if best == "" {
		return "", "", errNoMountTables
	}
	return best, bestType, nil
}

// parseMountInfoLine reads the mount point (field 5) and the filesystem type
// (the first field after " - ") of a /proc/self/mountinfo line.
func parseMountInfoLine(line string) (mountPoint, fsType string, ok bool) {
	pre, post, found := strings.Cut(line, " - ")
	if !found {
		return "", "", false
	}
	fields := strings.Fields(pre)
	postFields := strings.Fields(post)
	if len(fields) < 5 || len(postFields) < 1 {
		return "", "", false
	}
	return unescapeMount(fields[4]), postFields[0], true
}

// unescapeMount decodes the octal escapes (\040 for a space) of mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v byte
			okOctal := true
			for _, c := range []byte(s[i+1 : i+4]) {
				if c < '0' || c > '7' {
					okOctal = false
					break
				}
				v = v*8 + (c - '0')
			}
			if okOctal {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// underMount reports whether path is mp or below it.
func underMount(path, mp string) bool {
	if mp == "/" {
		return true
	}
	return path == mp || strings.HasPrefix(path, mp+"/")
}

// existingAncestor is dir cleaned and made absolute, with the symlinks of
// its existing part resolved; a part that does not exist yet (a state
// directory not created yet) is kept as written, so the path is judged by
// the mount it would be created on.
func existingAncestor(dir string) string {
	p := filepath.Clean(dir)
	if !filepath.IsAbs(p) {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	rest := ""
	for {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return filepath.Join(p, rest)
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}
