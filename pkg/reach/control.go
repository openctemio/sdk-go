package reach

import (
	"context"
	"net"
	"sync"
	"time"
)

// Control is the network-path self-check: a cheap probe through the same
// egress path a task's traffic takes, to tell a fault of the sensor's own
// network or DNS from a fact about the targets. When every target of a task
// failed to answer, the cause is either the targets (stopped, filtered) or the
// sensor (no route out, a dead resolver); only a probe to somewhere that is
// known to answer tells them apart.
//
// The probe is two things, each bounded: a TCP connection to Endpoint, a
// platform-owned address that always accepts connections (the egress echo),
// made with Dial (the task forwarder's dial hook, so scope, record and
// confinement apply as to any task traffic); and one lookup of Name, a
// platform-owned name, with Resolve (the sensor's own resolver). Endpoint and
// Name come from the sensor's configuration or the platform's settings, never
// from a job's targets, and the probe sends nothing: it only connects and
// closes. A probe that is not configured is skipped, and a skipped probe never
// charges anything to the sensor.
//
// Check caches its result for TTL, so a task's many unreached targets cost one
// probe.
type Control struct {
	// Dial connects to Endpoint through the task's egress path.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Endpoint is the host:port Dial connects to; empty skips the path probe.
	Endpoint string
	// Resolve looks up Name with the sensor's resolver; nil skips the DNS
	// probe.
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
	// Name is the name Resolve looks up; empty skips the DNS probe.
	Name string
	// Timeout bounds each probe (default 3s).
	Timeout time.Duration
	// TTL is how long a result is reused (default 30s).
	TTL time.Duration

	mu   sync.Mutex
	last ControlResult
	now  func() time.Time
}

// ProbeState is the outcome of one probe of the control check.
type ProbeState string

// Probe states.
const (
	// ProbeSkipped: not configured, or not run.
	ProbeSkipped ProbeState = "skipped"
	// ProbeOK: the probe succeeded.
	ProbeOK ProbeState = "ok"
	// ProbeFailed: the probe failed.
	ProbeFailed ProbeState = "failed"
)

// ControlResult is what the control check found.
type ControlResult struct {
	// Path is the connection to the endpoint through the egress path.
	Path ProbeState `json:"path"`
	// DNS is the lookup of the platform's name.
	DNS ProbeState `json:"dns"`
	// At is when the probes ran.
	At time.Time `json:"at"`
}

// Checked reports whether at least one probe ran.
func (r ControlResult) Checked() bool {
	ran := func(s ProbeState) bool { return s == ProbeOK || s == ProbeFailed }
	return ran(r.Path) || ran(r.DNS)
}

// SensorFault reports whether the check shows the sensor, not the target, as
// the cause of an unreached outcome of class c. A DNS failure is the sensor's
// when its resolver failed the control lookup; any other unreached class is
// the sensor's when the path probe failed. A target that was reached, and a
// check that did not run or passed, never charge the sensor.
func (r ControlResult) SensorFault(c Class) bool {
	switch c {
	case DNSFailure:
		return r.DNS == ProbeFailed
	case NoRoute, Timeout, FirewallRefused:
		return r.Path == ProbeFailed
	}
	return false
}

// Failed reports whether any probe failed.
func (r ControlResult) Failed() bool { return r.Path == ProbeFailed || r.DNS == ProbeFailed }

const (
	defaultControlTimeout = 3 * time.Second
	defaultControlTTL     = 30 * time.Second
)

func (c *Control) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Check runs the probes (or returns the cached result) and returns what they
// found. A nil Control, or one with nothing configured, returns a result with
// both probes skipped.
func (c *Control) Check(ctx context.Context) ControlResult {
	skipped := ControlResult{Path: ProbeSkipped, DNS: ProbeSkipped}
	if c == nil {
		return skipped
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := c.TTL
	if ttl <= 0 {
		ttl = defaultControlTTL
	}
	if c.last.Checked() && c.clock().Sub(c.last.At) < ttl {
		return c.last
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultControlTimeout
	}
	res := skipped
	var wg sync.WaitGroup
	if c.Dial != nil && c.Endpoint != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			conn, err := c.Dial(pctx, "tcp", c.Endpoint)
			if err != nil {
				res.Path = ProbeFailed
				return
			}
			_ = conn.Close()
			res.Path = ProbeOK
		}()
	}
	if c.Resolve != nil && c.Name != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ips, err := c.Resolve(pctx, c.Name)
			if err != nil || len(ips) == 0 {
				res.DNS = ProbeFailed
				return
			}
			res.DNS = ProbeOK
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		// A canceled job says nothing about the network: report skipped and
		// do not cache it.
		return skipped
	}
	res.At = c.clock()
	if res.Checked() {
		c.last = res
	}
	return res
}

type controlKey struct{}

// WithControl returns ctx carrying c: the code that settles a task's outcomes
// runs the check from it.
func WithControl(ctx context.Context, c *Control) context.Context {
	return context.WithValue(ctx, controlKey{}, c)
}

// ControlFromContext returns the control check ctx carries (nil: none).
func ControlFromContext(ctx context.Context) *Control {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(controlKey{}).(*Control)
	return c
}
