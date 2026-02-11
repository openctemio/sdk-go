package platform

import (
	"context"
	"strings"
	"testing"
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
