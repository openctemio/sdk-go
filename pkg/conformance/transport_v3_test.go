package conformance

// Sensor protocol v3 (openctem api RFC-059) end to end against the fake:
// the client negotiates gRPC over mTLS, falls back to the HTTPS binding on
// a transport failure (never on an identity error), uses v2 against a
// platform without v3, and every call of a sensor's life behaves exactly as
// on v2 (the fake carries v3 calls through its v2 routes).

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

func v3Fake(t *testing.T, grpc bool) (*FakePlatform, *sensorsig.Signer) {
	t.Helper()
	f := NewFakePlatform(true)
	f.SetControl(true)
	t.Cleanup(f.Close)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sensorsig.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.EnableV3(signer.PublicKey(), grpc); err != nil {
		t.Fatal(err)
	}
	return f, signer
}

func v3Client(t *testing.T, f *FakePlatform, signer *sensorsig.Signer, mode client.TransportMode) *client.Client {
	t.Helper()
	c := client.New(&client.Config{BaseURL: f.URL(), Signer: signer, MaxRetries: 3, RetryDelay: 10 * time.Millisecond})
	t.Cleanup(func() { _ = c.Close() })
	c.EnableTransportV3(client.TransportOptions{Mode: mode, CertDir: t.TempDir(), Logf: t.Logf})
	return c
}

// lifecycle runs a sensor's calls and checks they reached the fake.
func lifecycle(t *testing.T, f *FakePlatform, c *client.Client) {
	t.Helper()
	ctx := context.Background()
	f.QueueCommand("0192a3b4-0000-7000-8000-0000000000a1")
	hints, err := c.SendHeartbeatWithHints(ctx, status())
	if err != nil || !hints.Present || hints.PendingJobs != 1 {
		t.Fatalf("heartbeat: %+v %v", hints, err)
	}
	resp, err := c.GetCommands(ctx)
	if err != nil || len(resp.Commands) != 1 {
		t.Fatalf("poll: %+v %v", resp, err)
	}
	id := resp.Commands[0].ID
	if err := c.AcknowledgeCommand(ctx, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := c.StartCommand(ctx, id); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := c.ReportCommandResult(ctx, id, &core.CommandResult{Status: "completed", FindingsCount: 2}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if st, _ := f.CommandState(id); st != "completed" {
		t.Fatalf("command state %q", st)
	}
	if res, err := c.CheckFingerprints(ctx, []string{"a", "b"}); err != nil || len(res.Missing) != 2 {
		t.Fatalf("check %+v %v", res, err)
	}
	if _, err := c.PushFindings(ctx, report("semgrep", 1, 2)); err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(f.Reports()) != 1 {
		t.Fatalf("reports %d", len(f.Reports()))
	}
}

// carriedOn reports whether every sensor call after negotiation reached the
// fake's v2 routes through the binding b.
func carriedOn(t *testing.T, f *FakePlatform, b string) {
	t.Helper()
	n := 0
	for _, r := range f.Requests() {
		if r.Header.Get(HeaderV3Binding) == b {
			n++
		}
	}
	if n < 8 {
		t.Fatalf("only %d calls carried on %s", n, b)
	}
}

func TestTransportV3_GRPCCarriesTheWholeLifecycle(t *testing.T) {
	f, signer := v3Fake(t, true)
	c := v3Client(t, f, signer, client.TransportAuto)
	if err := c.StartTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := c.TransportStatus()
	if st.Binding != client.BindingGRPC || st.FallbackReason != "" || st.CertificateNotAfter.IsZero() {
		t.Fatalf("status %+v", st)
	}
	lifecycle(t, f, c)
	carriedOn(t, f, "grpc")
}

func TestTransportV3_HTTPSBindingCarriesTheWholeLifecycle(t *testing.T) {
	f, signer := v3Fake(t, true)
	c := v3Client(t, f, signer, client.TransportHTTPS)
	if err := c.StartTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := c.TransportStatus(); st.Binding != client.BindingHTTPS || st.FallbackReason != client.ReasonForcedByConfig {
		t.Fatalf("status %+v", st)
	}
	lifecycle(t, f, c)
	carriedOn(t, f, "https")
}

func TestTransportV3_FallsBackWhenGRPCIsUnreachable(t *testing.T) {
	f, signer := v3Fake(t, true)
	f.StopV3GRPC()
	c := v3Client(t, f, signer, client.TransportAuto)
	if err := c.StartTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := c.TransportStatus()
	if st.Binding != client.BindingHTTPS || st.FallbackReason != client.ReasonGRPCUnreachable {
		t.Fatalf("status %+v", st)
	}
	lifecycle(t, f, c)
	carriedOn(t, f, "https")
	// The heartbeat carried the reason.
	found := false
	for _, r := range f.Requests() {
		if r.Header.Get(HeaderV3Binding) == "https" && r.Path == "/api/v2/sensor/heartbeat" {
			found = true
		}
	}
	if !found {
		t.Fatal("no heartbeat over the HTTPS binding")
	}
}

// boxInTheWay replaces the fake's gRPC listener with an HTTP/1.1-only TLS
// server on the same address presenting cert.
func boxInTheWay(t *testing.T, f *FakePlatform, cert tls.Certificate) {
	t.Helper()
	endpoint := f.V3GRPCEndpoint()
	f.StopV3GRPC()
	ln, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Skipf("address reuse: %v", err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
}

// interceptor replaces the fake's gRPC listener with a TLS endpoint that
// speaks HTTP/2 (ALPN h2) with a certificate of its own CA.
func interceptor(t *testing.T, f *FakePlatform, cert tls.Certificate) {
	t.Helper()
	endpoint := f.V3GRPCEndpoint()
	f.StopV3GRPC()
	ln, err := tls.Listen("tcp", endpoint, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Skipf("address reuse: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()
}

// An intermediary that does not speak HTTP/2 (an old load balancer that
// holds the platform's gRPC certificate): the gRPC host answers with
// HTTP/1.1 only, a transport failure the HTTPS binding may stand in for.
func TestTransportV3_FallsBackWhenHTTP2IsRefused(t *testing.T) {
	f, signer := v3Fake(t, true)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := f.v3.issue(&key.PublicKey, false, "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	boxInTheWay(t, f, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})

	c := v3Client(t, f, signer, client.TransportAuto)
	if err := c.StartTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := c.TransportStatus()
	if st.Binding != client.BindingHTTPS || st.FallbackReason == "" {
		t.Fatalf("status %+v", st)
	}
	lifecycle(t, f, c)
}

func TestTransportV3_NeverFallsBackOnAnIdentityError(t *testing.T) {
	f, signer := v3Fake(t, true)
	f.RefuseV3Identity(true)
	c := v3Client(t, f, signer, client.TransportAuto)
	err := c.StartTransport(context.Background())
	if !errors.Is(err, client.ErrIdentityRefused) {
		t.Fatalf("err %v", err)
	}
	if st := c.TransportStatus(); st.FallbackReason != client.ReasonIdentityRefused {
		t.Fatalf("status %+v", st)
	}
	for _, r := range f.Requests() {
		if r.Header.Get(HeaderV3Binding) == "https" {
			t.Fatal("an identity refusal led to the HTTPS binding")
		}
	}
}

// A gRPC endpoint whose certificate the pinned platform CA bundle does not
// verify (a TLS-inspecting box, a rogue endpoint): a hard error, never the
// HTTPS binding or v2, and nothing is sent until gRPC verifies again.
func TestTransportV3_CertificateFailureNeverFallsBack(t *testing.T) {
	f, signer := v3Fake(t, true)
	interceptor(t, f, selfSigned(t))
	c := v3Client(t, f, signer, client.TransportAuto)
	err := c.StartTransport(context.Background())
	if !errors.Is(err, client.ErrPlatformCertificate) {
		t.Fatalf("err %v", err)
	}
	if st := c.TransportStatus(); st.FallbackReason != client.ReasonPlatformCertificate || st.Binding == client.BindingHTTPS || st.Binding == client.BindingV2 {
		t.Fatalf("status %+v", st)
	}
	noTrafficAfter(t, f, c)
}

// noTrafficAfter checks that a blocked client sends no heartbeat on any
// binding.
func noTrafficAfter(t *testing.T, f *FakePlatform, c *client.Client) {
	t.Helper()
	if _, err := c.SendHeartbeatWithHints(context.Background(), status()); err == nil {
		t.Fatal("a heartbeat went out on another binding")
	}
	for _, r := range f.Requests() {
		if r.Header.Get(HeaderV3Binding) == "https" || r.Path == "/api/v2/sensor/heartbeat" {
			t.Fatalf("a call reached the platform: %s %s", r.Header.Get(HeaderV3Binding), r.Path)
		}
	}
}

func TestTransportV3_ForcedGRPCDoesNotFallBack(t *testing.T) {
	f, signer := v3Fake(t, true)
	f.StopV3GRPC()
	c := v3Client(t, f, signer, client.TransportGRPC)
	if err := c.StartTransport(context.Background()); err == nil {
		t.Fatal("SENSOR_TRANSPORT=grpc fell back")
	}
	if st := c.TransportStatus(); st.Binding != client.BindingGRPC || st.FallbackReason != client.ReasonGRPCUnreachable {
		t.Fatalf("status %+v", st)
	}
	noTrafficAfter(t, f, c)
}

// SENSOR_TRANSPORT=grpc against a platform whose hello lists no protocol
// v3 does not drop to v2.
func TestTransportV3_ForcedGRPCDoesNotDropToV2(t *testing.T) {
	f, signer := v3Fake(t, true)
	f.HideV3()
	c := v3Client(t, f, signer, client.TransportGRPC)
	if err := c.StartTransport(context.Background()); err == nil {
		t.Fatal("SENSOR_TRANSPORT=grpc dropped to v2")
	}
	if st := c.TransportStatus(); st.Binding == client.BindingV2 || st.FallbackReason != client.ReasonPlatformWithoutV3 {
		t.Fatalf("status %+v", st)
	}
	noTrafficAfter(t, f, c)
}

func TestTransportV3_PlatformWithoutV3AndForcedV2(t *testing.T) {
	f, signer := v3Fake(t, true)
	// The fake knows the key (signed v2 requests pass) but its hello lists
	// no protocol v3: a platform from before it.
	f.HideV3()
	c := v3Client(t, f, signer, client.TransportAuto)
	if err := c.StartTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := c.TransportStatus(); st.Binding != client.BindingV2 || st.FallbackReason != client.ReasonPlatformWithoutV3 {
		t.Fatalf("without v3: %+v", st)
	}
	lifecycle(t, f, c)
	for _, r := range f.Requests() {
		if r.Header.Get(HeaderV3Binding) != "" {
			t.Fatal("a call went over v3")
		}
	}

	forced := v3Client(t, f, signer, client.TransportV2)
	_ = forced.StartTransport(context.Background())
	if st := forced.TransportStatus(); st.Binding != client.BindingV2 || st.FallbackReason != client.ReasonForcedByConfig {
		t.Fatalf("forced v2: %+v", st)
	}

	// A bearer-key client stays on v2.
	b := client.New(&client.Config{BaseURL: f.URL(), APIKey: f.APIKey})
	t.Cleanup(func() { _ = b.Close() })
	b.EnableTransportV3(client.TransportOptions{})
	_ = b.StartTransport(context.Background())
	if st := b.TransportStatus(); st.Binding != client.BindingV2 || st.FallbackReason != client.ReasonNotKeyBound {
		t.Fatalf("bearer: %+v", st)
	}
}

// selfSigned is a throwaway TLS certificate for 127.0.0.1.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTransportV3_ControlStreamPushesTheDoorbell(t *testing.T) {
	for _, mode := range []client.TransportMode{client.TransportAuto, client.TransportHTTPS} {
		t.Run(string(mode), func(t *testing.T) {
			f, signer := v3Fake(t, true)
			c := v3Client(t, f, signer, mode)
			var mu sync.Mutex
			got := make(chan *core.HeartbeatHints, 8)
			c.SetControlEventHandler(func(h *core.HeartbeatHints) {
				mu.Lock()
				defer mu.Unlock()
				got <- h
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := c.StartTransport(ctx); err != nil {
				t.Fatal(err)
			}
			first := <-got
			if first.PendingJobs != 0 {
				t.Fatalf("first %+v", first)
			}
			start := time.Now()
			f.QueueCommand("0192a3b4-0000-7000-8000-0000000000b1")
			select {
			case h := <-got:
				if h.PendingJobs != 1 || time.Since(start) > time.Second {
					t.Fatalf("event %+v after %v", h, time.Since(start))
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no push")
			}
		})
	}
}

// A connection lost after the platform stored a segment: the client retries
// and the report is stored once.
func TestTransportV3_DisconnectMidUploadIsExactlyOnce(t *testing.T) {
	f, signer := v3Fake(t, true)
	c := v3Client(t, f, signer, client.TransportAuto)
	if err := c.StartTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	dropped := false
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if r.Method == http.MethodPut && !dropped && r.Header.Get(HeaderV3Binding) == "grpc" {
			dropped = true
			return &FaultAnswer{Drop: true, Process: true}
		}
		return nil
	})
	if _, err := c.PushFindings(context.Background(), report("semgrep", 3, 1)); err != nil {
		t.Fatalf("push: %v", err)
	}
	if !dropped {
		t.Fatal("the fault did not fire")
	}
	if n := len(f.Reports()); n != 1 {
		t.Fatalf("%d reports stored, want 1", n)
	}
}

// A platform on one port (an IP address or a single host name): the gateway
// routes the gRPC binding by the sensor ALPN id, and the hello names it as
// grpc_alpn_endpoint only. The client offers the id next to h2, reaches the
// mTLS listener through the router and runs its whole life on gRPC.
func TestTransportV3_GRPCThroughALPNRoutingOnOnePort(t *testing.T) {
	f, signer := v3Fake(t, true)
	if err := f.RouteV3GRPCByALPN(); err != nil {
		t.Fatal(err)
	}
	c := v3Client(t, f, signer, client.TransportAuto)
	if err := c.StartTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := c.TransportStatus(); st.Binding != client.BindingGRPC || st.FallbackReason != "" {
		t.Fatalf("status %+v", st)
	}
	offered := f.V3OfferedALPN()
	if !slices.Contains(offered, client.SensorALPN) || !slices.Contains(offered, "h2") {
		t.Fatalf("ClientHello offered %q, want h2 and %q", offered, client.SensorALPN)
	}
	if client.SensorALPN != SensorALPN {
		t.Fatalf("client and fake disagree on the ALPN id: %q vs %q", client.SensorALPN, SensorALPN)
	}
	lifecycle(t, f, c)
	carriedOn(t, f, "grpc")
}

// A platform that stops answering for a moment (a restart, a gateway 502)
// trips the failure streak, but its failed negotiation says nothing about
// v3: the sensor stays on its binding instead of dropping to v2, and keeps
// using it once the platform answers again.
func TestTransportV3_PlatformOutageKeepsTheBinding(t *testing.T) {
	f, signer := v3Fake(t, false)
	c := client.New(&client.Config{BaseURL: f.URL(), Signer: signer, MaxRetries: 1, RetryDelay: time.Millisecond})
	t.Cleanup(func() { _ = c.Close() })
	c.EnableTransportV3(client.TransportOptions{Mode: client.TransportAuto, CertDir: t.TempDir(), FailureThreshold: 2, Logf: t.Logf})
	ctx := context.Background()
	if err := c.StartTransport(ctx); err != nil {
		t.Fatal(err)
	}
	if st := c.TransportStatus(); st.Binding != client.BindingHTTPS {
		t.Fatalf("status %+v", st)
	}

	var mu sync.Mutex
	hellos := 0
	f.SetFault(func(r *http.Request, _ int) *FaultAnswer {
		if r.URL.Path == "/api/v2/sensor/hello" {
			mu.Lock()
			hellos++
			mu.Unlock()
		}
		return &FaultAnswer{Status: http.StatusBadGateway}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, _ = c.SendHeartbeatWithHints(ctx, status())
		mu.Lock()
		n := hellos
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the failure streak never triggered a negotiation")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // let the negotiation finish
	if st := c.TransportStatus(); st.Binding != client.BindingHTTPS || st.FallbackReason != client.ReasonPlatformWithoutGRPC {
		t.Fatalf("after the outage: %+v, want the HTTPS binding kept", st)
	}

	f.SetFault(nil)
	if _, err := c.SendHeartbeatWithHints(ctx, status()); err != nil {
		t.Fatal(err)
	}
	beats := f.RequestsTo(http.MethodPost, "/api/v2/sensor/heartbeat")
	if last := beats[len(beats)-1]; last.Status != http.StatusOK || last.Header.Get(HeaderV3Binding) != "https" {
		t.Fatalf("heartbeat after the outage: status %d over %q", last.Status, last.Header.Get(HeaderV3Binding))
	}
}

// A sensor whose first negotiation gets no answer stays on v2 with its own
// reason (not "platform without v3") and negotiates again soon.
func TestTransportV3_UnreachablePlatformIsNotPlatformWithoutV3(t *testing.T) {
	f, signer := v3Fake(t, true)
	f.SetFault(func(*http.Request, int) *FaultAnswer { return &FaultAnswer{Status: http.StatusBadGateway} })
	c := v3Client(t, f, signer, client.TransportAuto)
	_ = c.StartTransport(context.Background())
	if st := c.TransportStatus(); st.Binding != client.BindingV2 || st.FallbackReason != client.ReasonPlatformUnreachable {
		t.Fatalf("status %+v", st)
	}
}
