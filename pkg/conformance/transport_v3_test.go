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
	if rules, err := c.GetSuppressions(ctx); err != nil || len(rules) != 1 {
		t.Fatalf("suppressions %v %v", rules, err)
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

// An intermediary that does not speak HTTP/2 (a TLS proxy, an old load
// balancer): the gRPC host answers with HTTP/1.1 only.
func TestTransportV3_FallsBackWhenHTTP2IsRefused(t *testing.T) {
	f, signer := v3Fake(t, true)
	endpoint := f.V3GRPCEndpoint()
	f.StopV3GRPC()
	// An HTTP/1.1-only TLS server on the same address, with a certificate
	// the client does not trust either: a box in the way.
	ln, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Skipf("address reuse: %v", err)
	}
	cert := selfSigned(t)
	srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

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

func TestTransportV3_ForcedGRPCDoesNotFallBack(t *testing.T) {
	f, signer := v3Fake(t, true)
	f.StopV3GRPC()
	c := v3Client(t, f, signer, client.TransportGRPC)
	if err := c.StartTransport(context.Background()); err == nil {
		t.Fatal("SENSOR_TRANSPORT=grpc fell back")
	}
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
