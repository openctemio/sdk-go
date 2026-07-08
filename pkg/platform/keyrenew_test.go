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

// PlatformClient.RenewKey parses the API response and sends the current key.
func TestPlatformClient_RenewKey(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	var gotAuth, gotAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAgent = r.Header.Get("X-Agent-ID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api_key":"rda_fresh","expires_at":"` + exp.Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()

	c := NewPlatformClient(&ClientConfig{BaseURL: srv.URL, APIKey: "rda_old", AgentID: "agent-1"})
	out, err := c.RenewKey(context.Background())
	if err != nil {
		t.Fatalf("RenewKey: %v", err)
	}
	if out.APIKey != "rda_fresh" {
		t.Errorf("expected rda_fresh, got %q", out.APIKey)
	}
	if out.ExpiresAt == nil || !out.ExpiresAt.Equal(exp) {
		t.Errorf("expected expiry %v, got %v", exp, out.ExpiresAt)
	}
	if gotAuth != "Bearer rda_old" {
		t.Errorf("expected the current key in Authorization, got %q", gotAuth)
	}
	if gotAgent != "agent-1" {
		t.Errorf("expected X-Agent-ID agent-1, got %q", gotAgent)
	}
}

// SetAPIKey swaps the key used by both the lease and job sub-clients.
func TestPlatformClient_SetAPIKey_FansOut(t *testing.T) {
	c := NewPlatformClient(&ClientConfig{BaseURL: "http://x", APIKey: "old", AgentID: "a"})
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
	c := NewPlatformClient(&ClientConfig{BaseURL: "http://x", APIKey: "k0", AgentID: "a"})
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

	c := NewPlatformClient(&ClientConfig{BaseURL: srv.URL, APIKey: "old", AgentID: "a"})
	if _, err := c.RenewKey(context.Background()); err == nil {
		t.Error("expected an error on non-200 renew response")
	}
}
