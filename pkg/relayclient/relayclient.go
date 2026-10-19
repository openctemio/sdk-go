// Package relayclient carries a sensor's platform requests through a
// sensor relay (api docs/rfcs/RFC-116-sensor-relay.md in
// openctemio/openctem; openctem research 194 §4).
//
// Transport is an http.RoundTripper. Put it under the request signer
// (sensorsig.Transport's Base): each signed v2 request is sealed to the
// platform's ingest key (pkg/sealedmsg) and posted to the relay; the
// answer arrives on the sensor's relay mailbox, sealed to the sensor's
// encryption key and signed by the platform's response key, and is handed
// back as the request's http.Response. The relay can delay or drop
// traffic; it cannot read it, change it or answer in the platform's name.
//
// Connection: TLS 1.3 to the relay, the relay's certificate checked by its
// SPKI pin from the pairing bundle (or by RootCAs when no pin is set), the
// sensor's identity key as the client certificate, and the platform-signed
// ticket on every request (Config.Ticket returns the current one; the
// sensor renews it through the relay itself).
//
// Stability: Experimental (docs/STABILITY.md).
package relayclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openctemio/sdk-go/pkg/sealedmsg"
	"github.com/openctemio/sdk-go/pkg/sensorproto/relay"
)

// Defaults.
const (
	DefaultResponseTimeout = 60 * time.Second
	pollWait               = 25
	maxBackoff             = 60 * time.Second
	maxBatchBytes          = 64 << 20
	maxBatchItems          = 64
)

// Errors.
var (
	// ErrNoResponse: the platform's answer did not arrive in time (the
	// request may or may not have been processed; callers retry
	// idempotently, as for any lost response).
	ErrNoResponse = errors.New("relayclient: no response through the relay in time")
	// ErrTicket: the relay refused the ticket (expired, revoked, another
	// relay): renew it.
	ErrTicket = errors.New("relayclient: relay refused the ticket")
	// ErrPin: the relay's certificate does not match the pinned key.
	ErrPin = errors.New("relayclient: relay certificate does not match the pin")
)

// Config configures a Transport.
type Config struct {
	// RelayURL is the relay's base URL (https).
	RelayURL string
	// RelayPin is the SHA-256 of the relay certificate's
	// SubjectPublicKeyInfo (from the pairing bundle). When set, the
	// certificate chain is not used: the pin is the trust anchor.
	RelayPin []byte
	// RootCAs verifies the relay's certificate when no pin is set (nil:
	// the system roots).
	RootCAs *x509.CertPool
	// Identity is the sensor's Ed25519 identity key: the TLS client key the
	// ticket names.
	Identity ed25519.PrivateKey
	// Ticket returns the current relay ticket.
	Ticket func() string
	// Route is the sensor's realm and id (from its pairing).
	Route sealedmsg.Route
	// IngestKey is the platform's current ingest key.
	IngestKey *sealedmsg.PublicKey
	// ResponseKeys are the pinned platform response keys.
	ResponseKeys []ed25519.PublicKey
	// EncryptionKey is the sensor's own encryption key.
	EncryptionKey *sealedmsg.PrivateKey
	// Proxy is the control path's proxy (nil: none).
	Proxy func(*http.Request) (*url.URL, error)
	// ResponseTimeout bounds the wait for one answer (default 60 s).
	ResponseTimeout time.Duration
	// OnTicketRefused is called when the relay refuses the ticket.
	OnTicketRefused func()
	// Logf receives state changes (default: none).
	Logf func(format string, args ...any)

	now func() time.Time
}

// Stats are the transport's counters.
type Stats struct {
	Sent            int64 `json:"sent"`
	Answered        int64 `json:"answered"`
	TimedOut        int64 `json:"timed_out"`
	DroppedForeign  int64 `json:"dropped_foreign"`  // responses that answered no outstanding request
	DroppedRefused  int64 `json:"dropped_refused"`  // envelopes that did not open or verify
	RelayThrottled  int64 `json:"relay_throttled"`  // 429 from the relay
	TicketRefusals  int64 `json:"ticket_refusals"`  // 401 from the relay
	PollErrors      int64 `json:"poll_errors"`      // failed mailbox polls
	PendingRequests int64 `json:"pending_requests"` // waiting for an answer now
}

// Transport is the relay round tripper.
type Transport struct {
	cfg  Config
	base string
	hc   *http.Client // short requests (up)
	poll *http.Client // long-polls (down)

	mu      sync.Mutex
	pending map[[32]byte]chan *sealedmsg.Response

	sent, answered, timedOut, foreign, refused, throttled, ticketRefusals, pollErrors atomic.Int64
}

// New checks the configuration and builds a Transport. Call Run to start
// receiving answers.
func New(cfg Config) (*Transport, error) {
	u, err := url.Parse(cfg.RelayURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("relayclient: RelayURL must be an https URL")
	}
	switch {
	case len(cfg.Identity) != ed25519.PrivateKeySize:
		return nil, errors.New("relayclient: identity key required")
	case cfg.Ticket == nil:
		return nil, errors.New("relayclient: ticket source required")
	case cfg.IngestKey == nil || cfg.EncryptionKey == nil || len(cfg.ResponseKeys) == 0:
		return nil, errors.New("relayclient: ingest key, encryption key and response keys required")
	case cfg.Route.Realm == "" || cfg.Route.SensorID == "":
		return nil, errors.New("relayclient: route required")
	case cfg.RelayPin != nil && len(cfg.RelayPin) != sha256.Size:
		return nil, errors.New("relayclient: relay pin must be a SHA-256")
	}
	if cfg.ResponseTimeout <= 0 {
		cfg.ResponseTimeout = DefaultResponseTimeout
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	cert, err := clientCertificate(cfg.Identity)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: cfg.RootCAs, ServerName: u.Hostname()}
	if cfg.RelayPin != nil {
		pin := append([]byte(nil), cfg.RelayPin...)
		// The pin replaces chain verification: the relay's certificate is
		// trusted exactly when its key is the pinned one.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // VerifyConnection checks the pinned key instead
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrPin
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return ErrPin
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy:               cfg.Proxy,
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
	}
	return &Transport{
		cfg: cfg, base: strings.TrimRight(cfg.RelayURL, "/"),
		hc:      &http.Client{Transport: tr, Timeout: 2 * time.Minute},
		poll:    &http.Client{Transport: tr, Timeout: (pollWait + 20) * time.Second},
		pending: map[[32]byte]chan *sealedmsg.Response{},
	}, nil
}

// clientCertificate makes a self-signed certificate for the identity key
// (the relay checks the key against the ticket, not the certificate).
func clientCertificate(key ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "openctem-sensor"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("relayclient: client certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// Stats returns the counters.
func (t *Transport) Stats() Stats {
	t.mu.Lock()
	n := int64(len(t.pending))
	t.mu.Unlock()
	return Stats{Sent: t.sent.Load(), Answered: t.answered.Load(), TimedOut: t.timedOut.Load(), DroppedForeign: t.foreign.Load(),
		DroppedRefused: t.refused.Load(), RelayThrottled: t.throttled.Load(), TicketRefusals: t.ticketRefusals.Load(),
		PollErrors: t.pollErrors.Load(), PendingRequests: n}
}

// RoundTrip seals the request, posts it to the relay and waits for the
// platform's answer.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(req.Body, sealedmsg.MaxBody+1))
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(b) > sealedmsg.MaxBody {
			return nil, fmt.Errorf("relayclient: request body over %d bytes", sealedmsg.MaxBody)
		}
		body = b
	}
	inner := &sealedmsg.Request{RequestMeta: sealedmsg.RequestMeta{Method: req.Method, Path: req.URL.RequestURI(), Header: req.Header.Clone(),
		ReplyKey: t.cfg.EncryptionKey.Public().Bytes()}, Body: body}
	env, err := sealedmsg.SealRequest(t.cfg.IngestKey, t.cfg.Route, inner)
	if err != nil {
		return nil, err
	}
	digest := sealedmsg.Digest(env)
	ch := make(chan *sealedmsg.Response, 1)
	t.mu.Lock()
	t.pending[digest] = ch
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.pending, digest)
		t.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(req.Context(), t.cfg.ResponseTimeout)
	defer cancel()
	if err := t.postUp(ctx, env); err != nil {
		return nil, err
	}
	t.sent.Add(1)
	select {
	case resp := <-ch:
		t.answered.Add(1)
		return &http.Response{
			Status: strconv.Itoa(resp.Status) + " " + http.StatusText(resp.Status), StatusCode: resp.Status,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: resp.Header, Body: io.NopCloser(bytes.NewReader(resp.Body)), ContentLength: int64(len(resp.Body)),
			Request: req,
		}, nil
	case <-ctx.Done():
		t.timedOut.Add(1)
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
		return nil, ErrNoResponse
	}
}

// postUp posts one envelope, waiting out the relay's Retry-After on 429
// until ctx ends.
func (t *Transport) postUp(ctx context.Context, env []byte) error {
	for {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+relay.PathSensorUp, bytes.NewReader(env))
		if err != nil {
			return err
		}
		r.Header.Set(relay.TicketHeader, t.cfg.Ticket())
		r.Header.Set("Content-Type", "application/octet-stream")
		resp, err := t.hc.Do(r)
		if err != nil {
			return fmt.Errorf("relayclient: post to relay: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusAccepted:
			return nil
		case http.StatusUnauthorized:
			t.ticketRefused()
			return ErrTicket
		case http.StatusTooManyRequests:
			t.throttled.Add(1)
			wait := retryAfter(resp.Header.Get("Retry-After"))
			select {
			case <-ctx.Done():
				return ErrNoResponse
			case <-time.After(wait):
			}
		default:
			return fmt.Errorf("relayclient: relay answered %d", resp.StatusCode)
		}
	}
}

func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return time.Second
	}
	return min(time.Duration(n)*time.Second, maxBackoff)
}

func (t *Transport) ticketRefused() {
	t.ticketRefusals.Add(1)
	if t.cfg.OnTicketRefused != nil {
		t.cfg.OnTicketRefused()
	}
}

// Run polls the sensor's relay mailbox and hands answers to waiting
// requests until ctx ends. Failures back off with full jitter up to 60 s.
func (t *Transport) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := t.pollOnce(ctx)
		if err == nil {
			backoff = time.Second
			continue
		}
		if ctx.Err() != nil {
			return
		}
		t.pollErrors.Add(1)
		t.cfg.Logf("relay: mailbox poll failed: %v", err)
		wait := time.Duration(mrand.Int64N(int64(backoff))) //nolint:gosec // jitter, not a secret
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (t *Transport) pollOnce(ctx context.Context) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, t.base+relay.PathSensorDown+"?wait="+strconv.Itoa(pollWait), nil)
	if err != nil {
		return err
	}
	r.Header.Set(relay.TicketHeader, t.cfg.Ticket())
	resp, err := t.poll.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusOK:
	case http.StatusUnauthorized:
		t.ticketRefused()
		return ErrTicket
	default:
		return fmt.Errorf("relay answered %d", resp.StatusCode)
	}
	items, err := relay.ReadBatch(io.LimitReader(resp.Body, maxBatchBytes+maxBatchItems*6), maxBatchItems, maxBatchBytes)
	if err != nil {
		return err
	}
	for _, it := range items {
		t.deliver(it.Envelope)
	}
	return nil
}

// deliver opens one answer and hands it to the request it answers; an
// envelope that does not open or verify, or answers no outstanding
// request, is dropped and counted.
func (t *Transport) deliver(env []byte) {
	resp, digest, err := sealedmsg.OpenResponseAny(t.cfg.EncryptionKey, t.cfg.ResponseKeys, t.cfg.Route, env, t.cfg.now())
	if err != nil {
		t.refused.Add(1)
		t.cfg.Logf("relay: answer refused: %v", err)
		return
	}
	t.mu.Lock()
	ch, ok := t.pending[digest]
	if ok {
		delete(t.pending, digest) // one answer per request: a replay finds nothing
	}
	t.mu.Unlock()
	if !ok {
		t.foreign.Add(1)
		return
	}
	ch <- resp
}
