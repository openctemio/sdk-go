package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeRenewer records calls and returns scripted responses.
type fakeRenewer struct {
	mu        sync.Mutex
	responses []*RenewKeyResponse
	errs      []error
	call      int
	setKeys   []string
}

func (f *fakeRenewer) RenewKey(_ context.Context) (*RenewKeyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.call
	f.call++
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	if i < len(f.responses) {
		return f.responses[i], nil
	}
	return &RenewKeyResponse{APIKey: "fallback"}, nil
}

func (f *fakeRenewer) SetAPIKey(key string) {
	f.mu.Lock()
	f.setKeys = append(f.setKeys, key)
	f.mu.Unlock()
}

func (f *fakeRenewer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.call
}

// A nil expiry (server TTL disabled) rotates once then stops the loop.
func TestKeyRenewManager_NilExpiryStops(t *testing.T) {
	fake := &fakeRenewer{responses: []*RenewKeyResponse{{APIKey: "new-key", ExpiresAt: nil}}}
	var rotated string
	m := NewKeyRenewManager(fake, &KeyRenewConfig{
		OnRotated: func(k string, _ *time.Time) error { rotated = k; return nil },
	})

	next, keepGoing := m.renewOnce(context.Background())
	if keepGoing {
		t.Error("expected loop to stop on nil expiry (no server TTL)")
	}
	if next != 0 {
		t.Errorf("expected next=0 on stop, got %v", next)
	}
	if rotated != "new-key" {
		t.Errorf("expected OnRotated with new-key, got %q", rotated)
	}
	if len(fake.setKeys) != 1 || fake.setKeys[0] != "new-key" {
		t.Errorf("expected SetAPIKey(new-key), got %v", fake.setKeys)
	}
}

// A future expiry schedules the next renewal at RenewFraction of the remaining
// lifetime and keeps the loop going.
func TestKeyRenewManager_FutureExpirySchedules(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour)
	fake := &fakeRenewer{responses: []*RenewKeyResponse{{APIKey: "k", ExpiresAt: &exp}}}
	m := NewKeyRenewManager(fake, &KeyRenewConfig{RenewFraction: 0.5, MinInterval: time.Minute})

	next, keepGoing := m.renewOnce(context.Background())
	if !keepGoing {
		t.Fatal("expected loop to keep going on future expiry")
	}
	// ~30m (half of 1h). Allow slack for test timing.
	if next < 29*time.Minute || next > 31*time.Minute {
		t.Errorf("expected next ~30m, got %v", next)
	}
}

// A renewal error keeps the loop alive and retries after RetryInterval.
func TestKeyRenewManager_ErrorRetries(t *testing.T) {
	fake := &fakeRenewer{errs: []error{errors.New("network down")}}
	m := NewKeyRenewManager(fake, &KeyRenewConfig{RetryInterval: 7 * time.Second})

	next, keepGoing := m.renewOnce(context.Background())
	if !keepGoing {
		t.Error("expected loop to keep going after a renewal error")
	}
	if next != 7*time.Second {
		t.Errorf("expected retry interval 7s, got %v", next)
	}
	if len(fake.setKeys) != 0 {
		t.Error("expected no key swap on error")
	}
}

// scheduleFor floors at MinInterval and handles already-expired keys.
func TestKeyRenewManager_ScheduleFor(t *testing.T) {
	m := NewKeyRenewManager(&fakeRenewer{}, &KeyRenewConfig{RenewFraction: 0.5, MinInterval: 2 * time.Minute})

	// Half of 10m = 5m (above floor).
	if got := m.scheduleFor(time.Now().Add(10 * time.Minute)); got < 4*time.Minute || got > 6*time.Minute {
		t.Errorf("expected ~5m, got %v", got)
	}
	// Half of 1m = 30s, floored to 2m.
	if got := m.scheduleFor(time.Now().Add(1 * time.Minute)); got != 2*time.Minute {
		t.Errorf("expected floor 2m, got %v", got)
	}
	// Already expired → floor.
	if got := m.scheduleFor(time.Now().Add(-time.Hour)); got != 2*time.Minute {
		t.Errorf("expected floor 2m for expired, got %v", got)
	}
}

// The loop stops promptly on Stop().
func TestKeyRenewManager_StartStop(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour)
	fake := &fakeRenewer{responses: []*RenewKeyResponse{{APIKey: "k", ExpiresAt: &exp}}}
	m := NewKeyRenewManager(fake, &KeyRenewConfig{})

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Starting again must error.
	if err := m.Start(context.Background()); err == nil {
		t.Error("expected error starting an already-running manager")
	}
	m.Stop()
	if fake.calls() < 1 {
		t.Error("expected at least the discovery renewal to run")
	}
}

// PlatformClient.RenewKey uses protocol v2 (POST /api/v2/sensor/keys, 201),
// identifies the sensor by its key alone and parses the answer.
func TestPlatformClient_RenewKeyV2(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	var paths []string
	var gotAuth, gotSensor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		gotAuth, gotSensor = r.Header.Get("Authorization"), r.Header.Get("X-Agent-ID")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"api_key":"rda_fresh","expires_at":"` + exp.Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()

	c := NewPlatformClient(&ClientConfig{BaseURL: srv.URL, APIKey: "rda_old", SensorID: "sensor-1"})
	out, err := c.RenewKey(context.Background())
	if err != nil {
		t.Fatalf("RenewKey: %v", err)
	}
	if out.APIKey != "rda_fresh" || out.ExpiresAt == nil || !out.ExpiresAt.Equal(exp) {
		t.Errorf("renewal %+v", out)
	}
	if len(paths) != 1 || paths[0] != "POST /api/v2/sensor/keys" {
		t.Errorf("requests %v, want one POST /api/v2/sensor/keys", paths)
	}
	if gotAuth != "Bearer rda_old" || gotSensor != "" {
		t.Errorf("Authorization %q, X-Agent-ID %q (v2 identifies by the key only)", gotAuth, gotSensor)
	}
}

// Against a platform without the v2 route (404, not a problem document) the
// renewal uses protocol v1, with X-Agent-ID as v1 expects.
func TestPlatformClient_RenewKeyFallsBackToV1(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	var paths []string
	var gotSensor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/api/v1/agent/renew" {
			http.NotFound(w, r)
			return
		}
		gotSensor = r.Header.Get("X-Agent-ID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api_key":"rda_fresh","expires_at":"` + exp.Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()

	c := NewPlatformClient(&ClientConfig{BaseURL: srv.URL, APIKey: "rda_old", SensorID: "sensor-1"})
	out, err := c.RenewKey(context.Background())
	if err != nil {
		t.Fatalf("RenewKey: %v", err)
	}
	if out.APIKey != "rda_fresh" {
		t.Errorf("expected rda_fresh, got %q", out.APIKey)
	}
	if len(paths) != 2 || paths[0] != "/api/v2/sensor/keys" || paths[1] != "/api/v1/agent/renew" {
		t.Errorf("requests %v", paths)
	}
	if gotSensor != "sensor-1" {
		t.Errorf("expected X-Agent-ID sensor-1 on v1, got %q", gotSensor)
	}
}

// A refused v2 renewal (a problem document) does not fall back: v1 would
// refuse the same key, and without a TTL a second renewal is never safe.
func TestPlatformClient_RenewKeyRefusedDoesNotFallBack(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"https://openctem.io/problems/sensor/renewal-refused","status":403}`))
	}))
	defer srv.Close()
	c := NewPlatformClient(&ClientConfig{BaseURL: srv.URL, APIKey: "rda_old", SensorID: "sensor-1"})
	_, err := c.RenewKey(context.Background())
	var re *RenewError
	if !errors.As(err, &re) || re.HTTPStatusCode() != http.StatusForbidden || n != 1 {
		t.Fatalf("err %v after %d requests", err, n)
	}
}

// SetAPIKey swaps the key used by both the lease and job sub-clients.
func TestPlatformClient_SetAPIKey_FansOut(t *testing.T) {
	c := NewPlatformClient(&ClientConfig{BaseURL: "http://x", APIKey: "old", SensorID: "a"})
	if c.httpLease == nil || c.httpJob == nil {
		t.Fatal("expected concrete sub-client refs to be captured")
	}
	c.SetAPIKey("new")
	if c.httpLease.getAPIKey() != "new" {
		t.Errorf("lease client key not swapped: %q", c.httpLease.getAPIKey())
	}
	if c.httpJob.getAPIKey() != "new" {
		t.Errorf("job client key not swapped: %q", c.httpJob.getAPIKey())
	}
	if c.currentAPIKey() != "new" {
		t.Errorf("currentAPIKey stale: %q", c.currentAPIKey())
	}
}

// Concurrent readers and a rotator must not race (run with -race). Mirrors the
// live pattern: poll/lease goroutines read the key while the renew loop swaps it.
func TestPlatformClient_ConcurrentKeyRotation(t *testing.T) {
	c := NewPlatformClient(&ClientConfig{BaseURL: "http://x", APIKey: "k0", SensorID: "a"})
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = c.httpLease.getAPIKey()
					_ = c.httpJob.getAPIKey()
					_ = c.currentAPIKey()
				}
			}
		})
	}
	// Rotator
	wg.Go(func() {
		for i := range 1000 {
			c.SetAPIKey("k" + string(rune('a'+i%26)))
		}
		close(stop)
	})

	wg.Wait()
}

// A non-200 renew response surfaces an error (e.g. expired/revoked key → 401).
func TestPlatformClient_RenewKey_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewPlatformClient(&ClientConfig{BaseURL: srv.URL, APIKey: "old", SensorID: "a"})
	if _, err := c.RenewKey(context.Background()); err == nil {
		t.Error("expected an error on non-200 renew response")
	}
}

// RenewNow renews at once, even for a key the manager would not renew on its
// own (never expires), and a second request right after a rotation is ignored.
func TestKeyRenewManager_RenewNow(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	fake := &fakeRenewer{responses: []*RenewKeyResponse{{APIKey: "k1", ExpiresAt: &exp}, {APIKey: "k2", ExpiresAt: &exp}}}
	rotated := make(chan string, 4)
	m := NewKeyRenewManager(fake, &KeyRenewConfig{
		CurrentKeyNeverExpires: true,
		MinInterval:            time.Hour,
		OnRotated:              func(k string, _ *time.Time) error { rotated <- k; return nil },
	})
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	time.Sleep(50 * time.Millisecond)
	if fake.calls() != 0 {
		t.Fatal("a never-expiring key must not be renewed unasked")
	}
	m.RenewNow()
	select {
	case k := <-rotated:
		if k != "k1" {
			t.Fatalf("rotated to %q", k)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RenewNow did not renew")
	}
	m.RenewNow() // within MinInterval of the rotation
	time.Sleep(100 * time.Millisecond)
	if fake.calls() != 1 {
		t.Fatalf("renewals %d, want 1 (second request debounced)", fake.calls())
	}
}

// RenewNow also cuts short a scheduled wait.
func TestKeyRenewManager_RenewNowBeforeSchedule(t *testing.T) {
	exp := time.Now().Add(10 * time.Hour)
	fake := &fakeRenewer{responses: []*RenewKeyResponse{{APIKey: "k1", ExpiresAt: &exp}}}
	m := NewKeyRenewManager(fake, &KeyRenewConfig{CurrentKeyExpiresAt: &exp})
	m.RenewNow() // pending before Start is kept
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for fake.calls() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fake.calls() != 1 {
		t.Fatalf("renewals %d, want 1", fake.calls())
	}
}
