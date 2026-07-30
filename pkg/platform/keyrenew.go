package platform

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// KeyRenewer is the subset of PlatformClient the renew manager needs: fetch a
// fresh key and swap it in. *PlatformClient satisfies this.
type KeyRenewer interface {
	RenewKey(ctx context.Context) (*RenewKeyResponse, error)
	SetAPIKey(key string)
}

var _ KeyRenewer = (*PlatformClient)(nil)

// Defaults for KeyRenewConfig.
const (
	// defaultRenewFraction: renew when this fraction of the key's lifetime has
	// elapsed (renew at ~50% TTL — the kubelet posture, lots of slack to retry).
	defaultRenewFraction = 0.5
	// defaultMinRenewInterval floors the schedule so a very short TTL can't spin
	// the loop.
	defaultMinRenewInterval = 1 * time.Minute
	// defaultRetryInterval is how soon to retry after a failed renewal. The old
	// key is still valid until its expiry, so failures have slack.
	defaultRetryInterval = 30 * time.Second
)

// KeyRenewConfig configures the KeyRenewManager.
type KeyRenewConfig struct {
	// RenewFraction is the fraction of the key lifetime at which to renew
	// (0 < f < 1). Default 0.5.
	RenewFraction float64

	// MinInterval floors the computed schedule. Default 1m.
	MinInterval time.Duration

	// RetryInterval is the wait before retrying a failed renewal. Default 30s.
	RetryInterval time.Duration

	// OnRotated is called after a successful key swap so the caller can persist
	// the new key (e.g. FileCredentialStore.Save) for the next restart. A
	// non-nil error is logged but does not stop the loop — the running client
	// already uses the new key.
	OnRotated func(newKey string, expiresAt *time.Time) error

	// Verbose enables debug logging.
	Verbose bool
}

// KeyRenewManager auto-renews the agent's API key before it expires, then swaps
// it into the live client and persists it. It is a no-op when the server has no
// key TTL (renewal returns a nil expiry) — after the discovery renewal it stops.
//
// Rotation model: this pairs with a server that issues short-lived keys. On the
// current server the previous key is invalidated the instant renewal succeeds
// (no overlap window yet), so a request already in flight at the swap instant
// can see a 401; the poll and lease loops self-heal on their next tick. Zero-
// window overlap is a planned server-side change.
type KeyRenewManager struct {
	client KeyRenewer
	config *KeyRenewConfig

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewKeyRenewManager creates a KeyRenewManager. A nil config uses defaults.
func NewKeyRenewManager(client KeyRenewer, config *KeyRenewConfig) *KeyRenewManager {
	if config == nil {
		config = &KeyRenewConfig{}
	}
	if config.RenewFraction <= 0 || config.RenewFraction >= 1 {
		config.RenewFraction = defaultRenewFraction
	}
	if config.MinInterval <= 0 {
		config.MinInterval = defaultMinRenewInterval
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = defaultRetryInterval
	}
	return &KeyRenewManager{
		client: client,
		config: config,
		stopCh: make(chan struct{}),
	}
}

// Start launches the renewal loop in the background. It performs one discovery
// renewal immediately: if the server returns no expiry (TTL disabled), the loop
// exits and the agent keeps its non-expiring key. Otherwise it schedules the
// next renewal at RenewFraction of the remaining lifetime and repeats.
func (m *KeyRenewManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("key renew manager already running")
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	m.wg.Add(1)
	go m.loop(ctx)
	return nil
}

// Stop stops the renewal loop.
func (m *KeyRenewManager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *KeyRenewManager) loop(ctx context.Context) {
	defer m.wg.Done()

	for {
		next, keepGoing := m.renewOnce(ctx)
		if !keepGoing {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-time.After(next):
		}
	}
}

// renewOnce performs a single renewal and returns how long to wait before the
// next one plus whether the loop should keep running. On a nil expiry (server
// TTL disabled) it returns keepGoing=false so the loop exits.
func (m *KeyRenewManager) renewOnce(ctx context.Context) (next time.Duration, keepGoing bool) {
	resp, err := m.client.RenewKey(ctx)
	if err != nil {
		m.logf("[apikey] renewal failed, retrying in %v: %v", m.config.RetryInterval, err)
		return m.config.RetryInterval, true
	}

	// Swap the new key into the live client, then persist it.
	m.client.SetAPIKey(resp.APIKey)
	if m.config.OnRotated != nil {
		if perr := m.config.OnRotated(resp.APIKey, resp.ExpiresAt); perr != nil {
			// The running client already uses the new key; a failed persist only
			// risks a restart falling back to the old key. Log, don't stop.
			m.logf("[apikey] rotated key persist failed: %v", perr)
		}
	}

	if resp.ExpiresAt == nil {
		// Server has no key TTL — nothing to schedule. The key we just received
		// never expires; stop the loop.
		m.logf("[apikey] renewed; server reports no expiry (TTL disabled) — auto-renew idle")
		return 0, false
	}

	next = m.scheduleFor(*resp.ExpiresAt)
	m.logf("[apikey] rotated key; expires %s, next renewal in %v", resp.ExpiresAt.Format(time.RFC3339), next)
	return next, true
}

// scheduleFor computes the wait until the next renewal: RenewFraction of the
// remaining lifetime, floored at MinInterval. A key already past (or near) its
// expiry renews again after MinInterval rather than hammering.
func (m *KeyRenewManager) scheduleFor(expiresAt time.Time) time.Duration {
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return m.config.MinInterval
	}
	next := time.Duration(float64(remaining) * m.config.RenewFraction)
	return max(next, m.config.MinInterval)
}

func (m *KeyRenewManager) logf(format string, args ...any) {
	if m.config.Verbose {
		fmt.Printf(format+"\n", args...)
	}
}
