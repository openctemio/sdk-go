package client

// Transport negotiation for sensor protocol v3 (openctem api RFC-059 T13):
// gRPC over mTLS first, Connect over HTTPS on a transport-level failure,
// protocol v2 when the platform has no v3. Identity errors never cause a
// fallback. The client certificate certifies the sensor's own key and is
// renewed at two thirds of its lifetime.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/sdk-go/pkg/sensorproto/v3"
	"github.com/openctemio/sdk-go/pkg/sensorproto/v3/sensorv3connect"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// TransportMode is SENSOR_TRANSPORT.
type TransportMode string

// Transport modes.
const (
	// TransportAuto: gRPC, then HTTPS on a transport failure, then v2.
	TransportAuto TransportMode = "auto"
	// TransportGRPC: gRPC only; a failure is an error.
	TransportGRPC TransportMode = "grpc"
	// TransportHTTPS: the HTTPS binding only (v2 if the platform has no v3).
	TransportHTTPS TransportMode = "https"
	// TransportV2: protocol v2 only.
	TransportV2 TransportMode = "v2"
)

// ParseTransportMode reads SENSOR_TRANSPORT ("" is auto).
func ParseTransportMode(s string) (TransportMode, error) {
	switch m := TransportMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return TransportAuto, nil
	case TransportAuto, TransportGRPC, TransportHTTPS, TransportV2:
		return m, nil
	}
	return TransportAuto, fmt.Errorf("SENSOR_TRANSPORT=%q is not one of auto, grpc, https, v2", s)
}

// Fallback reasons reported on the heartbeat.
const (
	ReasonForcedByConfig      = "forced_by_config"
	ReasonNotKeyBound         = "not_key_bound"
	ReasonPlatformWithoutV3   = "platform_without_v3"
	ReasonPlatformWithoutGRPC = "platform_without_grpc"
	ReasonCertificates        = "certificates_unavailable"
	ReasonGRPCUnreachable     = "grpc_unreachable"
	ReasonHandshakeFailed     = "handshake_failed"
	ReasonHTTP2Refused        = "http2_refused"
	ReasonStreamReset         = "stream_reset"
	ReasonGRPCUnimplemented   = "grpc_unimplemented"
	ReasonGRPCFailed          = "grpc_failed"
	ReasonHTTPSUnavailable    = "https_binding_unavailable"
	ReasonIdentityRefused     = "identity_refused"
)

// ErrIdentityRefused is an identity error from the platform on v3: no
// weaker transport is tried.
var ErrIdentityRefused = errors.New("protocol v3: the platform refused the sensor's identity")

// TransportOptions configure protocol v3 (Client.EnableTransportV3).
type TransportOptions struct {
	// Mode is SENSOR_TRANSPORT.
	Mode TransportMode
	// CertDir keeps the client certificate and the pinned CA (0600 files
	// in an existing 0700 directory, e.g. the identity directory). ""
	// keeps them in memory.
	CertDir string
	// ReprobeInterval is how often a sensor not on gRPC tries gRPC again
	// (auto mode). Zero is 30 minutes (jittered).
	ReprobeInterval time.Duration
	// FailureThreshold is how many consecutive transport failures of the
	// binding in use trigger a new negotiation. Zero is 3.
	FailureThreshold int
	// Logf receives one line per transport change (nil: none).
	Logf func(format string, args ...any)
}

// TransportStatus is the transport in use.
type TransportStatus struct {
	Binding        Binding
	FallbackReason string
	Since          time.Time
	// CertificateNotAfter is the client certificate's expiry (gRPC).
	CertificateNotAfter time.Time
}

const (
	certFile          = "transport-v3-client.pem"
	pinFile           = "transport-v3-platform-ca.pem"
	probeTimeout      = 15 * time.Second
	defaultReprobe    = 30 * time.Minute
	streamMaxBackoff  = 30 * time.Second
	defaultFailStreak = 3
)

type v3Manager struct {
	c      *Client
	opts   TransportOptions
	signer *sensorsig.Signer
	next   http.RoundTripper // the signed v2 transport
	rt     *v3RoundTripper

	state atomic.Pointer[v3State]

	mu        sync.Mutex
	cert      atomic.Pointer[tls.Certificate]
	notAfter  time.Time
	renewAt   time.Time
	pin       *x509.CertPool
	pinPEM    string
	endpoint  string
	failures  int
	renegoNow chan struct{}
	onEvent   func(*core.HeartbeatHints)
	streamGen chan struct{} // closed when the binding changes
}

// EnableTransportV3 installs protocol v3 under the client (key-bound
// clients only; a bearer-key client stays on v2). StartTransport negotiates.
func (c *Client) EnableTransportV3(opts TransportOptions) {
	if opts.Mode == "" {
		opts.Mode = TransportAuto
	}
	if opts.ReprobeInterval <= 0 {
		opts.ReprobeInterval = defaultReprobe
	}
	if opts.FailureThreshold <= 0 {
		opts.FailureThreshold = defaultFailStreak
	}
	m := &v3Manager{c: c, opts: opts, renegoNow: make(chan struct{}, 1), streamGen: make(chan struct{})}
	if st, ok := c.httpClient.Transport.(*sensorsig.Transport); ok && c.signed {
		m.signer = st.Signer
	}
	m.next = c.httpClient.Transport
	base := ""
	if u, err := urlPath(c.baseURL); err == nil {
		base = u
	}
	m.rt = &v3RoundTripper{next: m.next, state: &m.state, prefix: base + protov2.PathPrefix, failed: m.failed}
	c.httpClient.Transport = m.rt
	c.v3 = m
}

// SetControlEventHandler receives the control stream's events (the doorbell,
// pushed); a sensor hands them to core.Doorbell.Handle.
func (c *Client) SetControlEventHandler(f func(*core.HeartbeatHints)) {
	if c.v3 == nil {
		return
	}
	c.v3.mu.Lock()
	c.v3.onEvent = f
	c.v3.mu.Unlock()
}

// TransportStatus is the transport in use (v2 without protocol v3).
func (c *Client) TransportStatus() TransportStatus {
	if c.v3 == nil {
		return TransportStatus{Binding: BindingV2}
	}
	st := c.v3.state.Load()
	if st == nil {
		return TransportStatus{Binding: BindingV2}
	}
	c.v3.mu.Lock()
	na := c.v3.notAfter
	c.v3.mu.Unlock()
	out := TransportStatus{Binding: st.binding, FallbackReason: st.reason, Since: st.since}
	if st.binding == BindingGRPC {
		out.CertificateNotAfter = na
	}
	return out
}

// StartTransport negotiates the transport now and keeps it current until
// ctx ends: renews the certificate, re-probes gRPC, renegotiates after
// repeated transport failures and runs the control stream. It returns the
// first negotiation's error (an identity refusal); the client then stays
// on v2 for its requests, which the platform will refuse the same way.
func (c *Client) StartTransport(ctx context.Context) error {
	m := c.v3
	if m == nil {
		return nil
	}
	err := m.negotiate(ctx)
	go m.loop(ctx)
	go m.streamLoop(ctx)
	return err
}

func (m *v3Manager) logf(format string, args ...any) {
	if m.opts.Logf != nil {
		m.opts.Logf(format, args...)
	}
}

// set installs a binding and restarts the control stream.
func (m *v3Manager) set(svc sensorv3connect.SensorServiceClient, b Binding, reason string) {
	old := m.state.Load()
	if old != nil && old.binding == b && old.reason == reason && old.svc == svc {
		return
	}
	since := time.Now()
	if old != nil && old.binding == b {
		since = old.since
	}
	m.state.Store(&v3State{svc: svc, binding: b, reason: reason, since: since})
	m.mu.Lock()
	m.failures = 0
	close(m.streamGen)
	m.streamGen = make(chan struct{})
	m.mu.Unlock()
	if reason != "" {
		m.logf("transport: %s (%s)", b, reason)
	} else {
		m.logf("transport: %s", b)
	}
}

// failed counts a transport failure of the binding in use.
func (m *v3Manager) failed(b Binding, _ error) {
	m.mu.Lock()
	st := m.state.Load()
	if st == nil || st.binding != b {
		m.mu.Unlock()
		return
	}
	m.failures++
	trip := m.failures >= m.opts.FailureThreshold
	if trip {
		m.failures = 0
	}
	m.mu.Unlock()
	if trip {
		select {
		case m.renegoNow <- struct{}{}:
		default:
		}
	}
}

// negotiate picks the binding (RFC-059 T13).
func (m *v3Manager) negotiate(ctx context.Context) error {
	mode := m.opts.Mode
	if mode == TransportV2 {
		m.set(nil, BindingV2, ReasonForcedByConfig)
		return nil
	}
	if m.signer == nil {
		m.set(nil, BindingV2, ReasonNotKeyBound)
		return nil
	}
	// The v2 hello says whether and where v3 is served. It runs on v2.
	m.state.Store(&v3State{binding: BindingV2, since: time.Now()})
	hello, err := m.c.Hello(ctx)
	if err != nil || hello.TransportV3 == nil || hello.TransportV3.HTTPSPath == "" {
		m.set(nil, BindingV2, ReasonPlatformWithoutV3)
		return nil
	}
	https := m.httpsClient(hello.TransportV3.HTTPSPath)

	reason := ""
	switch {
	case mode == TransportHTTPS:
		reason = ReasonForcedByConfig
	case hello.TransportV3.GRPCEndpoint == "":
		reason = ReasonPlatformWithoutGRPC
	default:
		svc, r, err := m.tryGRPC(ctx, https, hello.TransportV3.GRPCEndpoint)
		if err != nil {
			m.set(nil, BindingV2, ReasonIdentityRefused)
			return err
		}
		if svc != nil {
			m.set(svc, BindingGRPC, "")
			return nil
		}
		if mode == TransportGRPC {
			m.set(nil, BindingV2, r)
			return fmt.Errorf("protocol v3 gRPC binding unavailable (%s) and SENSOR_TRANSPORT=grpc", r)
		}
		reason = r
	}

	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	_, err = https.Hello(pctx, connect.NewRequest(&sensorv3.HelloRequest{}))
	cancel()
	switch {
	case err == nil:
		m.set(https, BindingHTTPS, reason)
		return nil
	case identityError(err):
		m.set(nil, BindingV2, ReasonIdentityRefused)
		return fmt.Errorf("%w: %v", ErrIdentityRefused, err)
	}
	m.set(nil, BindingV2, ReasonHTTPSUnavailable)
	return nil
}

// httpsClient is the HTTPS binding's client: the platform host, the signed
// v2 transport (RFC 9421) underneath.
func (m *v3Manager) httpsClient(path string) sensorv3connect.SensorServiceClient {
	hc := &http.Client{Transport: m.next}
	return sensorv3connect.NewSensorServiceClient(hc, strings.TrimRight(m.c.baseURL, "/")+path)
}

// tryGRPC gets a certificate when needed and says hello over gRPC. It
// returns the client on success, or the fallback reason; err is an identity
// refusal (no fallback).
func (m *v3Manager) tryGRPC(ctx context.Context, https sensorv3connect.SensorServiceClient, endpoint string) (sensorv3connect.SensorServiceClient, string, error) {
	fresh := false
	if !m.haveCert(endpoint) {
		if err := m.issue(ctx, https); err != nil {
			if identityError(err) {
				return nil, "", fmt.Errorf("%w: %v", ErrIdentityRefused, err)
			}
			return nil, ReasonCertificates, nil
		}
		fresh = true
	}
	for attempt := 0; attempt < 2; attempt++ {
		svc := m.grpcClient(endpoint)
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		_, err := svc.Hello(pctx, connect.NewRequest(&sensorv3.HelloRequest{}))
		cancel()
		if err == nil {
			return svc, "", nil
		}
		if !identityError(err) && !certRefused(err) {
			m.logf("transport: gRPC binding at %s unavailable: %v", endpoint, err)
			return nil, fallbackReason(err), nil
		}
		// The platform refused the certificate: a new one, once. A second
		// refusal is the identity's, not the certificate's.
		if fresh || attempt == 1 {
			return nil, "", fmt.Errorf("%w: %v", ErrIdentityRefused, err)
		}
		if err := m.issue(ctx, https); err != nil {
			if identityError(err) {
				return nil, "", fmt.Errorf("%w: %v", ErrIdentityRefused, err)
			}
			return nil, ReasonCertificates, nil
		}
		fresh = true
	}
	return nil, ReasonGRPCFailed, nil
}

// grpcClient speaks gRPC over HTTP/2 with the client certificate, trusting
// only the pinned sensor CA for the platform's certificate.
func (m *v3Manager) grpcClient(endpoint string) sensorv3connect.SensorServiceClient {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	m.mu.Lock()
	pin := m.pin
	m.mu.Unlock()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: host,
		RootCAs:    pin,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c := m.cert.Load(); c != nil {
				return c, nil
			}
			return &tls.Certificate{}, nil
		},
	}
	p := new(http.Protocols)
	p.SetHTTP2(true)
	// The API client's transport (dial guard, platform proxy), HTTP/2 only,
	// with this TLS configuration.
	tr, ok := httpsec.NewAPIClient(0).Transport.(*http.Transport)
	if !ok {
		tr = &http.Transport{Proxy: httpsec.APIProxy().Func()}
	}
	tr = tr.Clone()
	tr.TLSClientConfig = cfg
	tr.Protocols = p
	tr.TLSHandshakeTimeout = 10 * time.Second
	tr.IdleConnTimeout = 90 * time.Second
	tr.ForceAttemptHTTP2 = true
	return sensorv3connect.NewSensorServiceClient(&http.Client{Transport: tr}, "https://"+endpoint, connect.WithGRPC())
}

// haveCert loads a cached certificate for endpoint that is not yet due for
// renewal.
func (m *v3Manager) haveCert(endpoint string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cert.Load() != nil && m.endpoint == endpoint && time.Now().Before(m.renewAt) {
		return true
	}
	if m.opts.CertDir == "" {
		return false
	}
	chain, err1 := os.ReadFile(filepath.Join(m.opts.CertDir, certFile))
	pinPEM, err2 := os.ReadFile(filepath.Join(m.opts.CertDir, pinFile))
	if err1 != nil || err2 != nil {
		return false
	}
	var cached struct {
		Endpoint string `json:"endpoint"`
	}
	if b, err := os.ReadFile(filepath.Join(m.opts.CertDir, certFile+".json")); err == nil {
		_ = json.Unmarshal(b, &cached)
	}
	if cached.Endpoint != endpoint {
		return false
	}
	return m.install(string(chain), string(pinPEM), endpoint) == nil && time.Now().Before(m.renewAt)
}

// install parses and installs a certificate chain for the sensor key and
// the CA bundle to pin. Callers hold m.mu.
func (m *v3Manager) install(chainPEM, caPEM, endpoint string) error {
	var cert tls.Certificate
	for rest := []byte(chainPEM); ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, b.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	// The certificate must be for this sensor's key: never present one for
	// another key.
	if pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(m.signer.PublicKey()) {
		return errors.New("the certificate is not for the sensor key")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return errors.New("no CA to pin")
	}
	cert.PrivateKey = m.signer.TLSKey()
	cert.Leaf = leaf
	m.cert.Store(&cert)
	m.notAfter = leaf.NotAfter
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	m.renewAt = leaf.NotBefore.Add(life * 2 / 3)
	m.pin, m.pinPEM, m.endpoint = pool, caPEM, endpoint
	return nil
}

// issue asks the platform for a certificate (over svc) and installs it.
func (m *v3Manager) issue(ctx context.Context, svc sensorv3connect.SensorServiceClient) error {
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	r, err := svc.IssueCertificate(pctx, connect.NewRequest(&sensorv3.IssueCertificateRequest{}))
	if err != nil {
		return err
	}
	msg := r.Msg
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.install(msg.GetCertificateChainPem(), msg.GetCaBundlePem(), msg.GetGrpcEndpoint()); err != nil {
		return err
	}
	if !msg.GetRenewAfter().AsTime().IsZero() {
		m.renewAt = msg.GetRenewAfter().AsTime()
	}
	if m.opts.CertDir != "" {
		m.persist(msg.GetCertificateChainPem(), msg.GetCaBundlePem(), msg.GetGrpcEndpoint())
	}
	m.logf("transport: client certificate valid until %s", m.notAfter.UTC().Format(time.RFC3339))
	return nil
}

// persist writes the certificate, the pin and the endpoint (0600). Callers
// hold m.mu. A failure only costs a new certificate at the next start.
func (m *v3Manager) persist(chain, ca, endpoint string) {
	write := func(name, data string) {
		tmp := filepath.Join(m.opts.CertDir, "."+name+".tmp")
		if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
			return
		}
		_ = os.Rename(tmp, filepath.Join(m.opts.CertDir, name))
	}
	write(certFile, chain)
	write(pinFile, ca)
	b, _ := json.Marshal(map[string]string{"endpoint": endpoint})
	write(certFile+".json", string(b))
}

// loop renews the certificate, re-probes gRPC and renegotiates after
// repeated failures until ctx ends.
func (m *v3Manager) loop(ctx context.Context) {
	for {
		wait := m.opts.ReprobeInterval/2 + jitterDuration(m.opts.ReprobeInterval/2)
		st := m.state.Load()
		m.mu.Lock()
		renewIn := time.Until(m.renewAt)
		m.mu.Unlock()
		if st != nil && st.binding == BindingGRPC && renewIn > 0 && renewIn < wait {
			wait = renewIn
		}
		if st != nil && st.binding == BindingGRPC && renewIn <= 0 {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-m.renegoNow:
			m.logf("transport: repeated failures on %s, negotiating again", st.binding)
			_ = m.negotiate(ctx)
		case <-time.After(wait):
			st = m.state.Load()
			switch {
			case st != nil && st.binding == BindingGRPC:
				m.mu.Lock()
				due := !time.Now().Before(m.renewAt)
				m.mu.Unlock()
				if due {
					if err := m.issue(ctx, st.svc); err != nil {
						m.logf("transport: certificate renewal failed: %v", err)
						if identityError(err) {
							_ = m.negotiate(ctx)
						}
					}
				}
			case m.opts.Mode == TransportAuto && (st == nil || st.reason != ReasonNotKeyBound):
				_ = m.negotiate(ctx)
			}
		}
	}
}

// streamLoop keeps the control stream open on a v3 binding and hands its
// events to the handler. A lost stream costs latency only: the heartbeat
// still carries the same hints.
func (m *v3Manager) streamLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		st := m.state.Load()
		m.mu.Lock()
		gen := m.streamGen
		onEvent := m.onEvent
		m.mu.Unlock()
		if st == nil || st.svc == nil || onEvent == nil {
			select {
			case <-ctx.Done():
				return
			case <-gen:
			case <-time.After(5 * time.Second):
			}
			continue
		}
		sctx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-gen:
				cancel()
			case <-sctx.Done():
			}
		}()
		started := time.Now()
		err := m.subscribe(sctx, st.svc, onEvent)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil && sctx.Err() == nil {
			m.logf("transport: control stream on %s ended: %v", st.binding, err)
		}
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			m.failed(st.binding, err)
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff + jitterDuration(backoff/2)):
		}
		backoff = min(backoff*2, streamMaxBackoff)
	}
}

func (m *v3Manager) subscribe(ctx context.Context, svc sensorv3connect.SensorServiceClient, onEvent func(*core.HeartbeatHints)) error {
	stream, err := svc.Subscribe(ctx, connect.NewRequest(&sensorv3.SubscribeRequest{}))
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	for stream.Receive() {
		ev := stream.Msg()
		if ev.GetKeepalive() {
			continue
		}
		onEvent(hintsOf(ev))
	}
	return stream.Err()
}

// hintsOf is a stream event as heartbeat hints (the same parser).
func hintsOf(ev *sensorv3.SubscribeResponse) *core.HeartbeatHints {
	pending := int(ev.GetPendingJobs())
	cv := ev.GetConfigVersion()
	raw, _ := json.Marshal(map[string]any{
		"status": ev.GetStatus(), "pending_jobs": pending, "actions": nonNilStrings(ev.GetActions()),
		"cancel_command_ids": nonNilStrings(ev.GetCancelCommandIds()), "config_version": cv,
	})
	return core.ParseHeartbeatHints(raw)
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// identityError reports a refusal by the platform of the sensor's identity.
func identityError(err error) bool {
	c := connect.CodeOf(err)
	return c == connect.CodeUnauthenticated || c == connect.CodePermissionDenied
}

// certRefused reports a TLS alert from the server about our certificate.
func certRefused(err error) bool {
	s := err.Error()
	return strings.Contains(s, "remote error: tls: bad certificate") ||
		strings.Contains(s, "remote error: tls: certificate required") ||
		strings.Contains(s, "remote error: tls: unknown certificate authority") ||
		strings.Contains(s, "remote error: tls: expired certificate") ||
		strings.Contains(s, "remote error: tls: revoked certificate") ||
		strings.Contains(s, "remote error: tls: certificate unknown")
}

// fallbackReason classifies a transport failure of the gRPC binding.
func fallbackReason(err error) string {
	s := err.Error()
	switch {
	case connect.CodeOf(err) == connect.CodeUnimplemented:
		return ReasonGRPCUnimplemented
	case strings.Contains(s, "x509:") || strings.Contains(s, "tls:") || strings.Contains(s, "handshake"):
		return ReasonHandshakeFailed
	case strings.Contains(s, "HTTP/1") || strings.Contains(s, "http2") || strings.Contains(s, "malformed HTTP") ||
		strings.Contains(s, "unexpected ALPN") || strings.Contains(s, "proxyconnect"):
		return ReasonHTTP2Refused
	case strings.Contains(s, "RST_STREAM") || strings.Contains(s, "stream error") || strings.Contains(s, "GOAWAY"):
		return ReasonStreamReset
	case strings.Contains(s, "dial") || strings.Contains(s, "connection refused") || strings.Contains(s, "no such host") ||
		strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline"):
		return ReasonGRPCUnreachable
	}
	return ReasonGRPCFailed
}

func jitterDuration(maxDur time.Duration) time.Duration {
	if maxDur <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxDur)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}
