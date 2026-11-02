package core

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
)

// Testing a proxy pool: the platform never connects to a proxy, it asks a
// sensor to. A proxy_test command carries the pool's endpoints (as a job's
// egress block does; credentials are fetched under the command's lease)
// and the platform's echo; the sensor tests every endpoint
// (upstream.Pool.Test) and completes the command with the result under the
// metadata key MetadataKeyProxyTest. The sensor-local veto applies as for a
// scan: a sensor that does not accept platform pools, or whose
// SENSOR_SCAN_EGRESS_ALLOW does not list an endpoint, refuses the test.

const (
	// CommandTypeProxyTest is the command type of a proxy pool test.
	CommandTypeProxyTest = "proxy_test"
	// CapabilityProxyTest is the capability of a sensor that serves
	// proxy_test commands. The platform offers only such sensors.
	CapabilityProxyTest = "proxy.test@1"
	// CapabilityEgressValidate is the sensor-wide capability of a sensor
	// whose validate jobs (finding re-checks) go through the job's proxy
	// pool and never direct. The platform withholds validate jobs of a
	// pooled sensor that does not report it.
	CapabilityEgressValidate = "egress.validate@1"
	// CapabilityEgressHostDirect marks a sensor whose owner set
	// SENSOR_SCAN_EGRESS=direct-only: it runs every scan direct and takes
	// no pool. The platform treats it as a sensor with a Direct path set
	// on the host, and not as one that cannot honor a pool.
	CapabilityEgressHostDirect = "egress.host-direct@1"

	// MetadataKeyProxyTest is the result metadata member of a proxy test.
	MetadataKeyProxyTest = "proxy_test"
)

// ProxyTestEcho is where a test connects through each proxy.
type ProxyTestEcho struct {
	// URL is the platform's echo (https, with a token for this test).
	URL string `json:"url"`
	// AltPort is the echo host's second port (0: not tried).
	AltPort int `json:"alt_port,omitempty"`
	// Endpoints are echo URLs of single endpoints (endpoint id to a URL on
	// the same https host and port as URL, whose token names that endpoint
	// alone), so the platform binds each observed exit to its endpoint. An
	// endpoint without one uses URL.
	Endpoints map[string]string `json:"endpoints,omitempty"`
}

// ProxyTestPayload is the payload of a proxy_test command.
type ProxyTestPayload struct {
	Egress *upstream.Config `json:"egress"`
	Echo   ProxyTestEcho    `json:"echo"`
	// Probe marks an idle probe of endpoints the platform holds on
	// probation or in quarantine. Only endpoints with their own echo URL
	// (Echo.Endpoints) are probed, each at most once per
	// upstream.ProbeInterval on this sensor; the others are left out of
	// the result.
	Probe bool `json:"probe,omitempty"`
}

// ProxyTestResult is what a proxy_test command completes with.
type ProxyTestResult struct {
	PoolID    string                    `json:"pool_id"`
	Endpoints []upstream.EndpointResult `json:"endpoints"`
}

// proxyTestTimeout bounds a whole test command.
const proxyTestTimeout = 3 * time.Minute

// EgressPreparer turns an egress block into a pool the way a scan job's is:
// the sensor-local veto, validation and the credentials fetched under the
// command's lease (*DefaultCommandExecutor).
type EgressPreparer interface {
	PrepareEgress(ctx context.Context, cmdID string, cfg *upstream.Config) (*upstream.Pool, error)
}

// ProxyTestExecutor runs proxy_test commands.
type ProxyTestExecutor struct {
	Egress EgressPreparer
	// RootCAs verify the echo's certificate (nil: the system roots).
	RootCAs func() *x509.CertPool
	// Probes bounds idle probes (nil: upstream.ProcessProbeGate).
	Probes *upstream.ProbeGate
}

// probeTargets are the endpoints an idle probe tests: those with their own
// echo URL (a shared token would not bind an observation to its endpoint)
// that the sensor did not probe within upstream.ProbeInterval. Never nil.
func (x *ProxyTestExecutor) probeTargets(p ProxyTestPayload) []string {
	gate := x.Probes
	if gate == nil {
		gate = upstream.ProcessProbeGate()
	}
	ids := []string{}
	for _, e := range p.Egress.Endpoints {
		if _, ok := p.Echo.Endpoints[e.ID]; ok && gate.Take(p.Egress.PoolID, e.ID) {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

// Execute tests the command's pool. A test whose endpoints all fail is a
// completed command with failed results; a command that cannot be run at
// all (unreadable payload, a local veto) fails.
func (x *ProxyTestExecutor) Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	start := time.Now()
	var p ProxyTestPayload
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		return nil, fmt.Errorf("proxy test: unreadable payload: %w", err)
	}
	if p.Egress == nil || len(p.Egress.Endpoints) == 0 {
		return nil, errors.New("proxy test: the command names no endpoint")
	}
	if x.Egress == nil {
		return nil, errors.New("proxy test: this sensor cannot prepare a proxy pool")
	}
	pool, err := x.Egress.PrepareEgress(ctx, cmd.ID, p.Egress)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, proxyTestTimeout)
	defer cancel()
	spec := upstream.TestSpec{EchoURL: p.Echo.URL, AltPort: p.Echo.AltPort, EndpointURLs: p.Echo.Endpoints}
	if x.RootCAs != nil {
		spec.RootCAs = x.RootCAs()
	}
	if p.Probe {
		spec.Endpoints = x.probeTargets(p)
	}
	res := ProxyTestResult{PoolID: p.Egress.PoolID, Endpoints: pool.Test(ctx, spec)}
	return &CommandExecutionResult{
		DurationMs: time.Since(start).Milliseconds(),
		Metadata:   map[string]any{MetadataKeyProxyTest: res},
	}, nil
}
