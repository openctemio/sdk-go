package platform

import (
	"context"
	"fmt"
	"os"
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
	// the new key (e.g. FileCredentialStore.Save) for the next restart.
	//
	// A non-nil error is treated as a failure, not a warning: the server has
	// already invalidated the previous key, so an unpersisted new key means
	// the next restart comes up with a dead credential. The manager reports
	// the error (stderr + OnPersistError), keeps the running client on the new
	// key, and retries the persist every RetryInterval. It does NOT rotate
	// again until the persist succeeds — rotating on top of an unsaved key
	// would only widen the gap.
	OnRotated func(newKey string, expiresAt *time.Time) error

	// OnPersistError, if set, is called each time OnRotated fails. Use it to
	// surface the condition (metrics, health check, alert).
	OnPersistError func(err error)

	// CurrentKeyExpiresAt is the expiry of the key the client starts with,
	// when the caller knows it (e.g. stored next to the key). When set, the
	// first renewal is scheduled from it instead of rotating immediately.
	CurrentKeyExpiresAt *time.Time

	// CurrentKeyNeverExpires tells the manager the server issued the current
	// key without a TTL. The manager then does nothing: there is nothing to
	// renew, and the discovery rotation would replace a working key for no
	// benefit. Leave false when unknown — the manager then performs one
	// discovery renewal to learn the server's TTL posture.
	CurrentKeyNeverExpires bool

	// Verbose enables debug logging.
	Verbose bool
}

// KeyRenewManager auto-renews the sensor's API key before it expires, then swaps
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

	// unpersisted holds a rotated key whose persist (OnRotated) failed. Only
	// touched by the loop goroutine.
	unpersisted *RenewKeyResponse
	// lastRotated is when the key was last swapped. Only touched by the loop
	// goroutine.
	lastRotated time.Time

	// trigger carries at most one pending RenewNow request.
	trigger chan struct{}
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
		client:  client,
		config:  config,
		stopCh:  make(chan struct{}),
		trigger: make(chan struct{}, 1),
	}
}

// RenewNow asks the running manager to renew the key now instead of at its
// schedule, e.g. because the platform's heartbeat said the key is inside its
// renewal window (the rotate_key doorbell action). It never blocks; requests
// made while one is pending collapse into it, and a request within
// MinInterval of the last rotation is ignored (the platform judged the key
// that was just replaced).
func (m *KeyRenewManager) RenewNow() {
	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

// Start launches the renewal loop in the background. Without a known expiry
// it performs one discovery renewal immediately: if the server returns no
// expiry (TTL disabled), nothing more is scheduled and the sensor keeps its
// non-expiring key. Otherwise it schedules the next renewal at RenewFraction
// of the remaining lifetime and repeats. In every case RenewNow still renews
// on request while the loop runs.
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

	// due is when the next scheduled renewal runs; zero means none is
	// scheduled and only RenewNow renews.
	var due time.Time
	switch {
	case m.config.CurrentKeyNeverExpires:
		m.logf("[apikey] current key has no expiry — auto-renew idle")
	case m.config.CurrentKeyExpiresAt != nil:
		// A known expiry for the starting key: wait until it is due instead
		// of rotating a perfectly good key at startup.
		exp := m.config.CurrentKeyExpiresAt
		wait := m.scheduleFor(*exp)
		m.logf("[apikey] current key expires %s, first renewal in %v", exp.Format(time.RFC3339), wait)
		due = time.Now().Add(wait)
	default:
		due = time.Now() // discovery renewal
	}

	for {
		if !due.IsZero() && !time.Now().Before(due) {
			next, keepGoing := m.renewOnce(ctx)
			due = time.Time{}
			if keepGoing {
				due = time.Now().Add(next)
			}
			continue
		}
		var timer <-chan time.Time
		if !due.IsZero() {
			timer = time.After(time.Until(due))
		}
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-timer:
		case <-m.trigger:
			if m.unpersisted == nil && !m.lastRotated.IsZero() && time.Since(m.lastRotated) < m.config.MinInterval {
				m.logf("[apikey] renewal requested, but the key was rotated %v ago — skipped",
					time.Since(m.lastRotated).Round(time.Second))
				continue
			}
			m.logf("[apikey] renewal requested — renewing now")
			due = time.Now()
		}
	}
}

// renewOnce performs a single renewal and returns how long to wait before the
// next one plus whether the loop should keep running. On a nil expiry (server
// TTL disabled) it returns keepGoing=false so the loop exits.
func (m *KeyRenewManager) renewOnce(ctx context.Context) (next time.Duration, keepGoing bool) {
	// A previous rotation is still unsaved: retry the persist, never rotate
	// again on top of it.
	if m.unpersisted != nil {
		return m.persist(m.unpersisted)
	}

	resp, err := m.client.RenewKey(ctx)
	if err != nil {
		m.logf("[apikey] renewal failed, retrying in %v: %v", m.config.RetryInterval, err)
		return m.config.RetryInterval, true
	}

	// Swap the new key into the live client first: the server has already
	// invalidated the old one, so the running sensor must use the new key
	// whether or not it can be saved.
	m.client.SetAPIKey(resp.APIKey)
	m.lastRotated = time.Now()
	return m.persist(resp)
}

// persist saves a rotated key via OnRotated and computes the next schedule.
// On failure the key is kept in m.unpersisted and the persist is retried
// after RetryInterval.
func (m *KeyRenewManager) persist(resp *RenewKeyResponse) (next time.Duration, keepGoing bool) {
	if m.config.OnRotated != nil {
		if perr := m.config.OnRotated(resp.APIKey, resp.ExpiresAt); perr != nil {
			m.unpersisted = resp
			// Always reported, not just in verbose mode: a restart now would
			// load a revoked key.
			fmt.Fprintf(os.Stderr, "[apikey] ERROR: rotated key could not be persisted (a restart would use a revoked key); retrying in %v: %v\n",
				m.config.RetryInterval, perr)
			if m.config.OnPersistError != nil {
				m.config.OnPersistError(perr)
			}
			return m.config.RetryInterval, true
		}
	}
	m.unpersisted = nil

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
