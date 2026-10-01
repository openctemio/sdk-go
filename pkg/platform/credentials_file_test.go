package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// legacyCredentials is a credentials file exactly as an SDK from before the
// agent -> sensor rename wrote it.
const legacyCredentials = `{
  "agent_id": "11111111-2222-3333-4444-555555555555",
  "api_key": "rda_legacy_key",
  "api_prefix": "rda_leg",
  "expires_at": "2027-01-01T00:00:00Z"
}`

func writeLegacy(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(legacyCredentials), mode); err != nil {
		t.Fatal(err)
	}
}

func TestSensorCredentialsReadsLegacyKey(t *testing.T) {
	var c SensorCredentials
	if err := json.Unmarshal([]byte(legacyCredentials), &c); err != nil {
		t.Fatal(err)
	}
	if c.SensorID != "11111111-2222-3333-4444-555555555555" || c.APIKey != "rda_legacy_key" || c.ExpiresAt == nil {
		t.Fatalf("legacy file decoded as %+v", c)
	}
	out, _ := json.Marshal(&c)
	if !strings.Contains(string(out), `"sensor_id"`) || strings.Contains(string(out), `"agent_id"`) {
		t.Fatalf("credentials are written with the new key only, got %s", out)
	}
	if err := json.Unmarshal([]byte(`{"sensor_id":"a","agent_id":"b","api_key":"k"}`), &c); err == nil {
		t.Fatal("different sensor_id and agent_id must be refused")
	}
	if err := json.Unmarshal([]byte(`{"sensor_id":"a","agent_id":"a","api_key":"k"}`), &c); err != nil || c.SensorID != "a" {
		t.Fatalf("equal keys: %+v %v", c, err)
	}
}

func TestMigrateCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "agent-credentials.json")
	to := filepath.Join(dir, "sensor-credentials.json")
	writeLegacy(t, from, 0o644) // a loose mode must not be carried over

	moved, err := MigrateCredentialsFile(from, to)
	if err != nil || !moved {
		t.Fatalf("MigrateCredentialsFile = %v, %v", moved, err)
	}
	if _, err := os.Stat(from); !os.IsNotExist(err) {
		t.Fatalf("old file must be removed after the move, stat err = %v", err)
	}
	st, err := os.Stat(to)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode = %o, want 600", st.Mode().Perm())
	}
	creds, err := NewFileCredentialStore(to).Load()
	if err != nil {
		t.Fatal(err)
	}
	if creds.SensorID != "11111111-2222-3333-4444-555555555555" || creds.APIKey != "rda_legacy_key" ||
		creds.APIPrefix != "rda_leg" || creds.ExpiresAt == nil || !creds.ExpiresAt.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("identity or key changed in the move: %+v", creds)
	}
	raw, _ := os.ReadFile(to)
	if !strings.Contains(string(raw), `"sensor_id"`) {
		t.Fatalf("new file must use the new key: %s", raw)
	}

	// Idempotent: a second run has nothing to move.
	if moved, err := MigrateCredentialsFile(from, to); err != nil || moved {
		t.Fatalf("second run = %v, %v; want no-op", moved, err)
	}
}

func TestMigrateCredentialsFileBothExistNewWins(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "agent-credentials.json")
	to := filepath.Join(dir, "sensor-credentials.json")
	writeLegacy(t, from, 0o600)
	if err := NewFileCredentialStore(to).Save(&SensorCredentials{SensorID: "new-id", APIKey: "rda_new"}); err != nil {
		t.Fatal(err)
	}
	moved, err := MigrateCredentialsFile(from, to)
	if err != nil || moved {
		t.Fatalf("= %v, %v; want new file kept, nothing moved", moved, err)
	}
	creds, _ := NewFileCredentialStore(to).Load()
	if creds.SensorID != "new-id" {
		t.Fatalf("new file was overwritten: %+v", creds)
	}
	if _, err := os.Stat(from); err != nil {
		t.Fatalf("old file must be left in place when both exist: %v", err)
	}
}

func TestMigrateCredentialsFileInvalidOldIsKept(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "agent-credentials.json")
	to := filepath.Join(dir, "sensor-credentials.json")
	if err := os.WriteFile(from, []byte(`{"agent_id": "x", "api_key"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateCredentialsFile(from, to); err == nil {
		t.Fatal("a truncated old file must be an error, not a silent re-registration")
	}
	if _, err := os.Stat(from); err != nil {
		t.Fatalf("old file must be kept: %v", err)
	}
	if _, err := os.Stat(to); !os.IsNotExist(err) {
		t.Fatalf("no new file may be written from an invalid old one: %v", err)
	}
}

func TestResolveCredentialsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	explicit := filepath.Join(home, "elsewhere", "agent-credentials.json")
	writeLegacy(t, explicit, 0o600)
	got, err := ResolveCredentialsFile(explicit)
	if err != nil || got != explicit {
		t.Fatalf("explicit path = %q, %v; want it used as is", got, err)
	}
	if _, err := os.Stat(explicit); err != nil {
		t.Fatal("an explicit path must never be moved")
	}

	legacy := filepath.Join(home, ".openctem", "agent-credentials.json")
	writeLegacy(t, legacy, 0o600)
	got, err = ResolveCredentialsFile("")
	want := filepath.Join(home, ".openctem", "sensor-credentials.json")
	if err != nil || got != want {
		t.Fatalf("default = %q, %v; want %q", got, err, want)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("the default legacy file must have been moved")
	}
}

// An upgraded sensor keeps its identity: EnsureRegistered with the default
// path loads the moved credentials and never calls the registration endpoint,
// even with a bootstrap token configured.
func TestEnsureRegisteredMigratesWithoutRegistering(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeLegacy(t, filepath.Join(home, ".openctem", "agent-credentials.json"), 0o600)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &EnsureRegisteredConfig{
		BaseURL:        srv.URL,
		BootstrapToken: "bt_unused",
		Registration:   &RegistrationRequest{Name: "s", Capabilities: []string{"dast"}},
	}
	creds, err := EnsureRegistered(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if creds.SensorID != "11111111-2222-3333-4444-555555555555" || creds.APIKey != "rda_legacy_key" {
		t.Fatalf("identity not kept: %+v", creds)
	}
	if calls.Load() != 0 {
		t.Fatalf("registration endpoint called %d times; an upgraded sensor must not re-register", calls.Load())
	}
	if want := filepath.Join(home, ".openctem", "sensor-credentials.json"); cfg.CredentialsFile != want {
		t.Fatalf("CredentialsFile = %q, want %q", cfg.CredentialsFile, want)
	}
}
