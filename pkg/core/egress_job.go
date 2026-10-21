package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
)

// Proxy pools for scan traffic (sensor proxies). A scan or retest command
// may carry an `egress` block: the organization's proxy pool the job's tool
// connections go through (upstream.Config; never credentials). The
// executor checks the sensor-local veto (EgressPolicy), validates the
// pool, fetches the credentials once per job when an endpoint has some
// (EgressCredentials), and hands the pool to the scanner (ScanOptions.Egress,
// and the job context: EgressDialerFrom). The tool host makes it the task
// forwarder's Dial hook; a task that would not run behind a forwarder that
// confines the network is refused, so a pooled job never goes direct. At
// the end of the job (completed or failed) the poller sends the pool's
// per-endpoint signals (EgressReporter) before the result.

// Refusal rules of egress jobs.
const (
	// RefusalEgressRefusedByHost: the sensor's own settings refuse the
	// job's pool (SENSOR_SCAN_EGRESS=direct-only, or an endpoint outside
	// SENSOR_SCAN_EGRESS_ALLOW).
	RefusalEgressRefusedByHost = "egress_refused_by_host"
	// RefusalEgressUnavailable: the job cannot run through its pool: no
	// usable endpoint, no credentials, or a scanner or sandbox that cannot
	// keep its tools behind the pool. Never run direct instead.
	RefusalEgressUnavailable = "egress_unavailable"
)

// CapabilityEgressUpstream is the sensor-wide capability of a sensor whose
// tool tasks run confined to the per-task forwarder and that accepts
// platform proxy pools (SENSOR_SCAN_EGRESS is not direct-only). The
// platform sends a job with an effective pool only to a sensor that
// reports it next to net.confined@1.
const CapabilityEgressUpstream = "egress.upstream@1"

// EgressDialer dials a task's connections through a job's proxy pool
// (*upstream.Pool). Addresses are always the IP and port the forwarder's
// scope check allowed.
type EgressDialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// EgressScanner is a scanner whose every tool task runs through the tool
// host behind the task forwarder (a tool with network "none" excepted), so
// a job's proxy pool carries all of its target connections. A job with a
// pool is refused for any other scanner.
type EgressScanner interface {
	Scanner
	RoutesEgress() bool
}

// EgressCredentials fetches the credentials of a command's proxy pool (the
// platform client: client.EgressCredentials).
type EgressCredentials interface {
	EgressCredentials(ctx context.Context, cmdID, poolID string) ([]upstream.Credential, error)
}

// EgressReporter sends a job's proxy pool signals (the platform client:
// client.EgressReport).
type EgressReporter interface {
	EgressReport(ctx context.Context, cmdID string, r upstream.Report) error
}

// EgressPolicy is the sensor-local veto on platform proxy pools
// (sensorkit reads it from SENSOR_SCAN_EGRESS and SENSOR_SCAN_EGRESS_ALLOW).
// The zero value accepts any pool whose endpoints pass validation.
type EgressPolicy struct {
	// DirectOnly refuses every job that carries a pool.
	DirectOnly bool
	// Reason says why DirectOnly is set (shown in the refusal).
	Reason string
	// Allow, when not nil, is the only endpoints accepted.
	Allow upstream.Allow
}

type egressSetup struct {
	policy EgressPolicy
	creds  EgressCredentials
}

// SetEgressPolicy sets the sensor-local veto on proxy pools.
func (e *DefaultCommandExecutor) SetEgressPolicy(p EgressPolicy) {
	e.egressMu.Lock()
	e.egress.policy = p
	e.egressMu.Unlock()
}

// SetEgressCredentials wires the credential fetch of pooled jobs; without
// it a job whose pool has an endpoint with credentials is refused.
func (e *DefaultCommandExecutor) SetEgressCredentials(c EgressCredentials) {
	e.egressMu.Lock()
	e.egress.creds = c
	e.egressMu.Unlock()
}

// PrepareEgress turns a command's egress block into the job's pool: nil
// without one. It applies the local veto, validates the pool, fetches the
// credentials (once, only when an endpoint has some) and registers the
// pool for the job's egress report. A refusal is a *LocalPolicyError with
// rule RefusalEgressRefusedByHost or RefusalEgressUnavailable.
func (e *DefaultCommandExecutor) PrepareEgress(ctx context.Context, cmdID string, cfg *upstream.Config) (*upstream.Pool, error) {
	if cfg == nil {
		return nil, nil
	}
	e.egressMu.Lock()
	setup := e.egress
	e.egressMu.Unlock()
	if setup.policy.DirectOnly {
		reason := setup.policy.Reason
		if reason == "" {
			reason = "this sensor runs scans direct only (SENSOR_SCAN_EGRESS=direct-only)"
		}
		return nil, egressRefusal(RefusalEgressRefusedByHost, "the job's traffic is to go through proxy pool %s; %s", cfg.PoolID, reason)
	}
	pool, err := upstream.New(*cfg, upstream.Options{Key: cmdID, Allow: setup.policy.Allow})
	switch {
	case errors.Is(err, upstream.ErrUnavailable):
		return nil, egressRefusal(RefusalEgressUnavailable, "proxy pool %s has no usable endpoint; the job does not run direct", cfg.PoolID)
	case errors.Is(err, upstream.ErrNotAllowed):
		return nil, egressRefusal(RefusalEgressRefusedByHost, "%v (SENSOR_SCAN_EGRESS_ALLOW)", err)
	case err != nil:
		return nil, fmt.Errorf("invalid egress block: %w", err)
	}
	if cfg.NeedsCredentials() {
		if setup.creds == nil {
			return nil, egressRefusal(RefusalEgressUnavailable, "proxy pool %s needs credentials and this sensor cannot ask the platform for them", cfg.PoolID)
		}
		creds, err := setup.creds.EgressCredentials(ctx, cmdID, cfg.PoolID)
		if err != nil {
			return nil, egressRefusal(RefusalEgressUnavailable, "proxy pool %s: the platform gave no credentials: %v", cfg.PoolID, err)
		}
		if err := pool.SetCredentials(creds); err != nil {
			return nil, egressRefusal(RefusalEgressUnavailable, "proxy pool %s: %v", cfg.PoolID, err)
		}
	}
	if h := egressHolderFrom(ctx); h != nil {
		h.set(pool)
	}
	return pool, nil
}

func egressRefusal(rule, format string, args ...any) error {
	return &LocalPolicyError{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

// EgressNotRouted is the refusal of a pooled job for a scanner whose tools
// would not all run behind the task forwarder.
func EgressNotRouted(scanner string) error {
	return egressRefusal(RefusalEgressUnavailable, "scanner %s does not run its tools behind the task forwarder, so the job's proxy pool cannot carry its traffic; the job does not run direct", scanner)
}

type egressDialerKey struct{}

// WithEgressDialer returns ctx carrying the job's proxy pool: every tool
// task the tool host runs under it dials through the pool.
func WithEgressDialer(ctx context.Context, d EgressDialer) context.Context {
	if d == nil {
		return ctx
	}
	return context.WithValue(ctx, egressDialerKey{}, d)
}

// EgressDialerFrom is the job's proxy pool on ctx (nil: none).
func EgressDialerFrom(ctx context.Context) EgressDialer {
	d, _ := ctx.Value(egressDialerKey{}).(EgressDialer)
	return d
}

// egressHolder keeps the pool a job prepared, for its report.
type egressHolder struct {
	mu   sync.Mutex
	pool *upstream.Pool
}

func (h *egressHolder) set(p *upstream.Pool) {
	h.mu.Lock()
	h.pool = p
	h.mu.Unlock()
}

func (h *egressHolder) get() *upstream.Pool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pool
}

type egressHolderKey struct{}

func withEgressHolder(ctx context.Context) (context.Context, *egressHolder) {
	h := &egressHolder{}
	return context.WithValue(ctx, egressHolderKey{}, h), h
}

func egressHolderFrom(ctx context.Context) *egressHolder {
	h, _ := ctx.Value(egressHolderKey{}).(*egressHolder)
	return h
}

// SetEgressReporter wires the end-of-job egress report; without it no
// report is sent.
func (p *CommandPoller) SetEgressReporter(r EgressReporter) {
	if r == nil {
		p.egressReporter.Store(nil)
		return
	}
	p.egressReporter.Store(&r)
}

// egressReportTimeout bounds the best-effort egress report.
const egressReportTimeout = 30 * time.Second

// reportEgress sends the job's pool signals, best-effort, before its
// result: nothing when the job had no pool or used none of it.
func (p *CommandPoller) reportEgress(ctx context.Context, cmd *Command, h *egressHolder) {
	r := p.egressReporter.Load()
	pool := h.get()
	if r == nil || pool == nil {
		return
	}
	rep := pool.Report()
	if !rep.Used() {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), egressReportTimeout)
	defer cancel()
	if err := (*r).EgressReport(rctx, cmd.ID, rep); err != nil {
		fmt.Printf("[command-poller] Command %s: egress report not sent: %v\n", cmd.ID, err)
	}
}
