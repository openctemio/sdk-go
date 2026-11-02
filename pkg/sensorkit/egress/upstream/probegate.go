package upstream

import (
	"sync"
	"time"
)

// Idle probes: the platform may ask a sensor to probe the endpoints it holds
// on probation or in quarantine, through its own echo (a proxy_test command
// marked as a probe, with one echo token per endpoint). A ProbeGate bounds
// what such probes cost the sensor and the proxies: at most one probe per
// endpoint per ProbeInterval, whatever the platform asks.

// ProbeInterval is the least time between two probes of one endpoint by one
// sensor.
const ProbeInterval = 10 * time.Minute

// maxProbeEntries bounds the endpoints a gate remembers; past it (after the
// entries older than ProbeInterval are dropped) a probe is refused.
const maxProbeEntries = 4096

// ProbeGate decides which endpoints may be probed now. It is safe for
// concurrent use; the zero value is not usable (NewProbeGate).
type ProbeGate struct {
	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time
}

// NewProbeGate returns an empty gate.
func NewProbeGate() *ProbeGate {
	return &ProbeGate{last: map[string]time.Time{}, now: time.Now}
}

var processProbes = sync.OnceValue(NewProbeGate)

// ProcessProbeGate is the process's gate: the one bound for the sensor.
func ProcessProbeGate() *ProbeGate { return processProbes() }

// Take reports whether the endpoint of the pool may be probed now, and if so
// records the probe.
func (g *ProbeGate) Take(poolID, endpointID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	key := poolID + "\x00" + endpointID
	if t, ok := g.last[key]; ok && now.Sub(t) < ProbeInterval {
		return false
	}
	if _, ok := g.last[key]; !ok && len(g.last) >= maxProbeEntries {
		for k, t := range g.last {
			if now.Sub(t) >= ProbeInterval {
				delete(g.last, k)
			}
		}
		if len(g.last) >= maxProbeEntries {
			return false
		}
	}
	g.last[key] = now
	return true
}
