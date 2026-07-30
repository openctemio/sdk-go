package platform

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateHolderIdentity(t *testing.T) {
	t.Run("secure identity enabled (default)", func(t *testing.T) {
		config := &LeaseConfig{}
		identity := generateHolderIdentity(config)

		// Should have format: agent-hostname-pid-nonce
		parts := strings.Split(identity, "-")
		if len(parts) < 4 {
			t.Errorf("generateHolderIdentity() with secure=true should have at least 4 parts, got %d: %s", len(parts), identity)
		}

		// First part should be default prefix
		if parts[0] != "agent" {
			t.Errorf("generateHolderIdentity() first part should be 'agent', got %q", parts[0])
		}

		// Last part should be hex nonce (32 chars for 16 bytes)
		lastPart := parts[len(parts)-1]
		if len(lastPart) != 32 {
			t.Errorf("generateHolderIdentity() nonce should be 32 chars, got %d: %s", len(lastPart), lastPart)
		}
	})

	t.Run("secure identity disabled", func(t *testing.T) {
		useSecure := false
		config := &LeaseConfig{UseSecureIdentity: &useSecure}
		identity := generateHolderIdentity(config)

		// Should have format: agent-hostname-pid (no nonce)
		parts := strings.Split(identity, "-")
		if len(parts) != 3 {
			t.Errorf("generateHolderIdentity() with secure=false should have 3 parts, got %d: %s", len(parts), identity)
		}
	})

	t.Run("custom prefix", func(t *testing.T) {
		config := &LeaseConfig{IdentityPrefix: "scanner"}
		identity := generateHolderIdentity(config)

		if !strings.HasPrefix(identity, "scanner-") {
			t.Errorf("generateHolderIdentity() should start with 'scanner-', got %s", identity)
		}
	})

	t.Run("unique identities", func(t *testing.T) {
		config := &LeaseConfig{}
		identity1 := generateHolderIdentity(config)
		identity2 := generateHolderIdentity(config)

		// Due to random nonce, identities should be different
		if identity1 == identity2 {
			t.Error("generateHolderIdentity() should generate unique identities")
		}
	})
}

func TestNewLeaseManager_DefaultConfig(t *testing.T) {
	// Mock client
	client := &mockLeaseClient{}

	manager := NewLeaseManager(client, nil)

	if manager.config.LeaseDuration != DefaultLeaseDuration {
		t.Errorf("NewLeaseManager() default LeaseDuration = %v, want %v", manager.config.LeaseDuration, DefaultLeaseDuration)
	}

	if manager.config.RenewInterval != DefaultRenewInterval {
		t.Errorf("NewLeaseManager() default RenewInterval = %v, want %v", manager.config.RenewInterval, DefaultRenewInterval)
	}

	if manager.config.MaxJobs != DefaultMaxConcurrentJobs {
		t.Errorf("NewLeaseManager() default MaxJobs = %d, want %d", manager.config.MaxJobs, DefaultMaxConcurrentJobs)
	}

	// Holder identity should be secure by default
	if len(manager.holderIdentity) < 40 { // hostname-pid-nonce should be > 40 chars
		t.Errorf("NewLeaseManager() holderIdentity seems too short for secure identity: %s", manager.holderIdentity)
	}
}

func TestLeaseStatus(t *testing.T) {
	client := &mockLeaseClient{}
	config := &LeaseConfig{
		LeaseDuration: 60,
		GracePeriod:   15,
	}
	manager := NewLeaseManager(client, config)

	status := manager.GetStatus()

	if status.Running {
		t.Error("GetStatus() Running should be false before Start()")
	}

	if status.CurrentJobs != 0 {
		t.Errorf("GetStatus() CurrentJobs = %d, want 0", status.CurrentJobs)
	}
}

// mockLeaseClient implements LeaseClient for testing
type mockLeaseClient struct {
	renewCount   int
	releaseCount int
}

func (m *mockLeaseClient) RenewLease(ctx context.Context, req *LeaseRenewRequest) (*LeaseRenewResponse, error) {
	m.renewCount++
	return &LeaseRenewResponse{
		Success:         true,
		ResourceVersion: m.renewCount,
	}, nil
}

func (m *mockLeaseClient) ReleaseLease(ctx context.Context) error {
	m.releaseCount++
	return nil
}

// failingLeaseClient always fails renewal — used to exercise the expiry path.
type failingLeaseClient struct{ releaseCount int32 }

func (f *failingLeaseClient) RenewLease(_ context.Context, _ *LeaseRenewRequest) (*LeaseRenewResponse, error) {
	return nil, fmt.Errorf("renew failed")
}

func (f *failingLeaseClient) ReleaseLease(_ context.Context) error {
	atomic.AddInt32(&f.releaseCount, 1)
	return nil
}

// TestLeaseManager_NoPrematureExpiryOnFailedInitialRenew verifies that when the
// initial renewal fails, the agent gets a full LeaseDuration+GracePeriod window
// before OnLeaseExpired fires. Previously lastRenewTime was the zero value, so
// time.Since(zero) was astronomically large and the expiry callback (which
// shuts the agent down) fired on the very first failed tick.
func TestLeaseManager_NoPrematureExpiryOnFailedInitialRenew(t *testing.T) {
	var expiredCalls int32
	config := &LeaseConfig{
		LeaseDuration:  60 * time.Second,
		GracePeriod:    60 * time.Second, // window ~120s, far longer than the test
		RenewInterval:  5 * time.Millisecond,
		OnLeaseExpired: func() { atomic.AddInt32(&expiredCalls, 1) },
	}
	manager := NewLeaseManager(&failingLeaseClient{}, config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = manager.Start(ctx) // initial renew fails
	time.Sleep(80 * time.Millisecond)
	_ = manager.Stop(context.Background())

	if got := atomic.LoadInt32(&expiredCalls); got != 0 {
		t.Errorf("OnLeaseExpired must NOT fire within the lease window despite failed renews, fired %d times", got)
	}
}

// TestLeaseManager_ExpiryFiresExactlyOnce verifies the expiry callback fires a
// single time once the lease genuinely expires, not on every subsequent tick.
func TestLeaseManager_ExpiryFiresExactlyOnce(t *testing.T) {
	var expiredCalls int32
	config := &LeaseConfig{
		LeaseDuration:  10 * time.Millisecond,
		GracePeriod:    1 * time.Millisecond, // tiny window so it expires quickly
		RenewInterval:  2 * time.Millisecond,
		OnLeaseExpired: func() { atomic.AddInt32(&expiredCalls, 1) },
	}
	manager := NewLeaseManager(&failingLeaseClient{}, config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = manager.Start(ctx)
	time.Sleep(150 * time.Millisecond) // ~70 ticks, all past the window
	_ = manager.Stop(context.Background())

	if got := atomic.LoadInt32(&expiredCalls); got != 1 {
		t.Errorf("OnLeaseExpired must fire exactly once after expiry, fired %d times", got)
	}
}
