package client

// Binding memory and per-reason backoff for protocol v3 (api
// docs/rfcs/RFC-059-sensor-transport-v3.md §7, T13): a sensor whose gRPC
// binding failed for a network reason does not try it again at every
// negotiation or restart; it waits a backoff that grows with each failure
// (from ReprobeInterval, doubling, at most maxGRPCBackoff), on the HTTPS
// binding meanwhile. The last outcome is kept in CertDir so a restart does
// not repeat a known-bad gRPC attempt. A platform that does not offer gRPC
// yet (its self-probe is failing) is asked again sooner, so sensors move to
// gRPC soon after the platform's path is fixed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const (
	selectFile = "transport-v3-state.json"
	// maxGRPCBackoff caps the wait after repeated gRPC network failures.
	maxGRPCBackoff = 4 * time.Hour
	// platformRecheck is how soon a sensor asks again when the platform
	// offers no gRPC (or no v3) yet.
	platformRecheck = 10 * time.Minute
)

// selection is the remembered outcome of the last gRPC attempt.
type selection struct {
	Binding  Binding   `json:"binding"`
	Reason   string    `json:"reason,omitempty"`
	At       time.Time `json:"at"`
	Failures int       `json:"failures,omitempty"`
}

// networkReason reports whether a fallback reason is the network's (worth a
// growing backoff), not the platform's or the configuration's.
func networkReason(reason string) bool {
	switch reason {
	case ReasonGRPCUnreachable, ReasonHandshakeFailed, ReasonHTTP2Refused, ReasonStreamReset,
		ReasonGRPCUnimplemented, ReasonGRPCFailed:
		return true
	}
	return false
}

// grpcBackoff is the wait after n consecutive network failures.
func grpcBackoff(base time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < maxGRPCBackoff; i++ {
		d *= 2
	}
	return min(d, maxGRPCBackoff)
}

// loadSelection reads the remembered outcome once. Callers hold m.mu.
func (m *v3Manager) loadSelection() {
	if m.selLoaded {
		return
	}
	m.selLoaded = true
	if m.opts.CertDir == "" {
		return
	}
	b, err := os.ReadFile(filepath.Join(m.opts.CertDir, selectFile))
	if err != nil {
		return
	}
	var s selection
	if json.Unmarshal(b, &s) == nil && !s.At.IsZero() && !s.At.After(time.Now().Add(time.Minute)) {
		m.sel = s
	}
}

// skipGRPC reports the remembered network failure whose backoff has not
// elapsed: the gRPC attempt is skipped and its reason reported.
func (m *v3Manager) skipGRPC(now time.Time) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadSelection()
	if !networkReason(m.sel.Reason) || m.sel.Failures == 0 {
		return "", false
	}
	if now.Sub(m.sel.At) >= grpcBackoff(m.opts.ReprobeInterval, m.sel.Failures) {
		return "", false
	}
	return m.sel.Reason, true
}

// remember records the outcome of a gRPC attempt ("" reason: success).
func (m *v3Manager) remember(b Binding, reason string, now time.Time) {
	m.mu.Lock()
	m.loadSelection()
	s := selection{Binding: b, Reason: reason, At: now}
	if networkReason(reason) {
		s.Failures = m.sel.Failures + 1
	}
	m.sel = s
	dir := m.opts.CertDir
	m.mu.Unlock()
	if dir == "" {
		return
	}
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	tmp := filepath.Join(dir, "."+selectFile+".tmp")
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, filepath.Join(dir, selectFile))
	}
}

// nextNegotiation is how long the loop waits before negotiating again for
// the state st (auto mode).
func (m *v3Manager) nextNegotiation(st *v3State) time.Duration {
	half := m.opts.ReprobeInterval / 2
	if st != nil && (st.reason == ReasonPlatformWithoutGRPC || st.reason == ReasonPlatformWithoutV3 ||
		st.reason == ReasonCertificates || st.reason == ReasonHTTPSUnavailable) {
		half = min(half, platformRecheck/2)
	}
	return half + jitterDuration(half)
}
