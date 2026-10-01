package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAPIURL(t *testing.T) {
	got, err := apiURL("https://api.example.com/", "/api/v1/platform/jobs/%s/ack", "../../admin?x=1#f")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://api.example.com/api/v1/platform/jobs/..%2F..%2Fadmin%3Fx=1%23f/ack"
	if got != want {
		t.Errorf("apiURL = %q, want %q", got, want)
	}
	for _, bad := range []string{"", "ftp://x", "https://u:p@api.example.com", "api.example.com"} {
		if _, err := apiURL(bad, "/api/v1/platform/poll"); err == nil {
			t.Errorf("base URL %q accepted", bad)
		}
	}
	if _, err := apiURL("https://api.example.com", "/api/v1/platform/jobs/%s/ack", ""); err == nil {
		t.Error("empty job ID accepted")
	}
}

// Job IDs from the server are escaped on the wire.
func TestJobClient_EscapesJobID(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	jc := NewHTTPJobClient(srv.URL, "k", "sensor-1", time.Second)
	if err := jc.AcknowledgeJob(context.Background(), "x/../../lease"); err != nil {
		t.Fatal(err)
	}
	if want := "/api/v1/platform/jobs/x%2F..%2F..%2Flease/ack"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

// Platform clients carry the sensor key and must not follow redirects.
func TestPlatformClient_RefusesRedirect(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		_, _ = w.Write([]byte(`{"api_key":"stolen"}`))
	}))
	defer target.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer api.Close()

	c := NewPlatformClient(&ClientConfig{BaseURL: api.URL, APIKey: "rda_secret", SensorID: "a"})
	if _, err := c.RenewKey(context.Background()); err == nil {
		t.Fatal("redirect followed")
	}
	if leaked.Load() {
		t.Fatal("API key forwarded to redirect target")
	}
}

func TestFileCredentialStore_SaveAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	// Pre-existing world-readable file from an older version.
	if err := os.WriteFile(path, []byte(`{"api_key":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	store := NewFileCredentialStore(path)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := store.Save(&SensorCredentials{SensorID: "a", APIKey: "new", ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("credentials mode = %o, want 600", perm)
		}
	}
	got, err := store.Load()
	if err != nil || got.APIKey != "new" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}

	// A failed save must leave the previous file intact (no truncation).
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0o700) //nolint:errcheck
		if err := store.Save(&SensorCredentials{APIKey: "newer"}); err == nil {
			t.Fatal("save into read-only dir succeeded")
		}
		got, err := store.Load()
		if err != nil || got.APIKey != "new" {
			t.Fatalf("previous credentials damaged by failed save: %+v, %v", got, err)
		}
	}
}

// A failed persist is an error: it is reported, retried, and the manager
// does not rotate again on top of an unsaved key.
func TestKeyRenewManager_PersistFailureRetriesWithoutRerotating(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	f := &fakeRenewer{responses: []*RenewKeyResponse{{APIKey: "k1", ExpiresAt: &exp}}}
	var persistAttempts, persistErrors atomic.Int32
	m := NewKeyRenewManager(f, &KeyRenewConfig{
		RetryInterval: 5 * time.Millisecond,
		OnRotated: func(string, *time.Time) error {
			if persistAttempts.Add(1) < 3 {
				return errors.New("disk full")
			}
			return nil
		},
		OnPersistError: func(error) { persistErrors.Add(1) },
	})

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		next, keep := m.renewOnce(ctx)
		if !keep {
			t.Fatalf("iteration %d: loop stopped", i)
		}
		if i < 2 && next != m.config.RetryInterval {
			t.Fatalf("iteration %d: persist failure should retry after RetryInterval, got %v", i, next)
		}
	}
	if f.calls() != 1 {
		t.Fatalf("RenewKey called %d times; must not rotate again while a key is unsaved", f.calls())
	}
	if persistAttempts.Load() != 3 || persistErrors.Load() != 2 {
		t.Fatalf("persist attempts=%d errors=%d, want 3 and 2", persistAttempts.Load(), persistErrors.Load())
	}
	if m.unpersisted != nil {
		t.Fatal("unpersisted key not cleared after successful save")
	}
}

func TestKeyRenewManager_KnownExpiryPosture(t *testing.T) {
	t.Run("never expires: no rotation", func(t *testing.T) {
		f := &fakeRenewer{}
		m := NewKeyRenewManager(f, &KeyRenewConfig{CurrentKeyNeverExpires: true})
		if err := m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		m.Stop()
		if f.calls() != 0 {
			t.Fatalf("key rotated %d times although it never expires", f.calls())
		}
	})

	t.Run("known future expiry: no immediate rotation", func(t *testing.T) {
		f := &fakeRenewer{}
		exp := time.Now().Add(time.Hour)
		m := NewKeyRenewManager(f, &KeyRenewConfig{CurrentKeyExpiresAt: &exp})
		if err := m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		m.Stop()
		if f.calls() != 0 {
			t.Fatalf("still-valid key rotated at startup (%d calls)", f.calls())
		}
	})

	t.Run("unknown posture: discovery rotation kept", func(t *testing.T) {
		f := &fakeRenewer{}
		m := NewKeyRenewManager(f, &KeyRenewConfig{})
		if err := m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for f.calls() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		m.Stop()
		if f.calls() != 1 {
			t.Fatalf("expected one discovery renewal, got %d", f.calls())
		}
	})
}
