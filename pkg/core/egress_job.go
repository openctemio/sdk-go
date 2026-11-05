package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/openctemio/contract/secretref"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
)

// Proxy pools for scan traffic (sensor proxies). A scan or retest command
// may carry an `egress` block: the organization's proxy pool the job's tool
// connections go through (upstream.Config; never credentials). The
// executor checks the sensor-local veto (EgressPolicy), validates the
// pool, fetches the credentials once per job when an endpoint has some
// (the job's egress_proxy secret ref, JobSecrets), and hands the pool to the scanner (ScanOptions.Egress,
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

// RefusalUnconfinedSandbox: the tool contacts its targets (tier T1 and
// above) and this sensor's tool sandbox is not available (it is Linux
// only), so the tool would run unconfined; the operator acknowledges that
// with SENSOR_SANDBOX=off (executor.Status.RefusesActiveTools).
const RefusalUnconfinedSandbox = "unconfined_sandbox"

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
}

// SetEgressPolicy sets the sensor-local veto on proxy pools.
func (e *DefaultCommandExecutor) SetEgressPolicy(p EgressPolicy) {
	e.egressMu.Lock()
	e.egress.policy = p
	e.egressMu.Unlock()
}

// PrepareEgress turns a command's egress block into the job's pool: nil
// without one. It applies the local veto, validates the pool, fetches the
// credentials (once, only when an endpoint has some: the job's signed
// egress_proxy ref for exactly this pool, JobSecretsFrom(ctx)) and registers the
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
		creds, err := poolCredentials(ctx, cfg.PoolID)
		if err != nil {
			return nil, egressRefusal(RefusalEgressUnavailable, "proxy pool %s: %v", cfg.PoolID, err)
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

// egressFetchTask names the job's pool credentials fetch (audit only).
const egressFetchTask = "egress"

// poolCredentials fetches the credentials of pool poolID through the job's
// egress_proxy ref (the forwarder's, required). No ref, a fetch that fails
// or answers without the value: no credentials, and the job does not run
// (never direct, never another source).
func poolCredentials(ctx context.Context, poolID string) ([]upstream.Credential, error) {
	js := JobSecretsFrom(ctx)
	ref, ok := js.ForwarderRef(poolID)
	if !ok {
		return nil, errors.New("the pool needs credentials and the job's signed secret list names none for it")
	}
	ans, err := js.Fetch(ctx, egressFetchTask, []string{ref.ID})
	if err != nil {
		return nil, fmt.Errorf("the platform gave no credentials: %w", err)
	}
	defer ZeroAnswer(ans)
	for _, sec := range ans.Secrets {
		if sec.ID != ref.ID {
			continue
		}
		v, err := secretref.DecodeEgressProxy(sec.Value)
		if err != nil {
			return nil, errors.New("the platform's credentials are not valid")
		}
		creds := make([]upstream.Credential, 0, len(v.Endpoints))
		for _, ep := range v.Endpoints {
			creds = append(creds, upstream.Credential{EndpointID: ep.ID, Username: ep.Username, Password: ep.Password})
		}
		return creds, nil
	}
	return nil, errors.New("the platform holds no credentials for the pool")
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
