package conformance

// Sensor protocol v3 on the fake platform (openctem api RFC-059): the HTTPS
// binding under /api/v3/sensor on the fake's own server (RFC 9421
// signatures of a trusted key), and optionally the gRPC binding on a TLS 1.3
// listener that requires a client certificate from the fake's sensor CA.
// Like the platform, every RPC is carried through the fake's v2 routes, so a
// sensor behaves the same on v2 and v3 against it.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/sdk-go/pkg/sensorproto/v3"
	"github.com/openctemio/sdk-go/pkg/sensorproto/v3/sensorv3connect"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// HeaderV3Binding marks the fake's in-process v2 requests that carried a v3
// call, with the binding ("grpc" or "https"); Requests shows it.
const HeaderV3Binding = "X-Fake-V3-Binding"

const v3PathPrefix = "/api/v3/sensor"

type fakeV3 struct {
	f       *FakePlatform
	trusted ed25519.PublicKey

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  string

	https http.Handler
	grpc  *httptest.Server

	mu     sync.Mutex
	wakes  []chan struct{}
	refuse bool
	hidden bool
}

// HideV3 keeps protocol v3 off the v2 hello (signed requests of the trusted
// key still pass): a platform from before v3.
func (f *FakePlatform) HideV3() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.v3 != nil {
		f.v3.hidden = true
	}
}

// EnableV3 serves protocol v3 for the sensor holding key pub: the HTTPS
// binding, and with grpc the gRPC binding on its own TLS listener. The v2
// hello lists both. The fake's API key is used for the v2 routes the calls
// are carried through.
func (f *FakePlatform) EnableV3(pub ed25519.PublicKey, grpc bool) error {
	v := &fakeV3{f: f, trusted: pub}
	if err := v.newCA(); err != nil {
		return err
	}
	path, h := sensorv3connect.NewSensorServiceHandler(v)
	mux := http.NewServeMux()
	mux.Handle(v3PathPrefix+path, http.StripPrefix(v3PathPrefix, h))
	v.https = v.authHTTPS(mux)
	if grpc {
		srv, err := v.startGRPC(path, h)
		if err != nil {
			return err
		}
		v.grpc = srv
	}
	f.mu.Lock()
	f.v3 = v
	f.mu.Unlock()
	return nil
}

// V3GRPCEndpoint is host:port of the fake's gRPC binding ("" without one).
func (f *FakePlatform) V3GRPCEndpoint() string {
	f.mu.Lock()
	v := f.v3
	f.mu.Unlock()
	if v == nil || v.grpc == nil {
		return ""
	}
	return strings.TrimPrefix(v.grpc.URL, "https://")
}

// StopV3GRPC closes the gRPC binding's listener (the hello still names it):
// a sensor must fall back to the HTTPS binding.
func (f *FakePlatform) StopV3GRPC() {
	f.mu.Lock()
	v := f.v3
	f.mu.Unlock()
	if v != nil && v.grpc != nil {
		v.grpc.Close()
	}
}

// RefuseV3Identity makes every v3 call answer UNAUTHENTICATED: a sensor
// must not fall back to a weaker transport.
func (f *FakePlatform) RefuseV3Identity(on bool) {
	f.mu.Lock()
	v := f.v3
	f.mu.Unlock()
	if v != nil {
		v.mu.Lock()
		v.refuse = on
		v.mu.Unlock()
	}
}

func (f *FakePlatform) v3Hello() *protov2.TransportV3 {
	if f.v3 == nil || f.v3.hidden {
		return nil
	}
	t := &protov2.TransportV3{HTTPSPath: v3PathPrefix}
	if f.v3.grpc != nil {
		t.GRPCEndpoint = strings.TrimPrefix(f.v3.grpc.URL, "https://")
	}
	return t
}

// v3Wake wakes the fake's control streams (a command was queued).
func (f *FakePlatform) v3Wake() {
	f.mu.Lock()
	v := f.v3
	f.mu.Unlock()
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, w := range v.wakes {
		select {
		case w <- struct{}{}:
		default:
		}
	}
}

func (v *fakeV3) newCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake sensor CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	v.caCert, _ = x509.ParseCertificate(der)
	v.caKey = key
	v.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return nil
}

func (v *fakeV3) issue(pub any, client bool, host string, lifetime time.Duration) ([]byte, error) {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if client {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tpl.URIs = []*url.URL{{Scheme: "spiffe", Host: "openctem", Path: "/tenant/fake/sensor/fake"}}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP(host)}
	}
	return x509.CreateCertificate(rand.Reader, tpl, v.caCert, pub, v.caKey)
}

type fakeBindingKey struct{}

// signedByTrusted reports a request signed (RFC 9421) by the trusted key
// (the fake does not track nonces).
func (v *fakeV3) signedByTrusted(r *http.Request) bool {
	p, err := sensorsig.Parse(r.Header)
	return err == nil && p.Params.KeyID == sensorsig.Thumbprint(v.trusted) && p.Verify(r, v.trusted) == nil
}

// authHTTPS accepts a call signed (RFC 9421) by the trusted key.
func (v *fakeV3) authHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !v.signedByTrusted(r) {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), fakeBindingKey{}, "https")))
	})
}

func (v *fakeV3) startGRPC(path string, h http.Handler) (*httptest.Server, error) {
	pool := x509.NewCertPool()
	pool.AddCert(v.caCert)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no certificate", http.StatusUnauthorized)
			return
		}
		pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
		if !ok || !pub.Equal(v.trusted) {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), fakeBindingKey{}, "grpc")))
	}))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := v.issue(&key.PublicKey, false, "127.0.0.1", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	srv.StartTLS()
	return srv, nil
}

// v2 runs one carried call through the fake's v2 routes.
func (v *fakeV3) v2(ctx context.Context, method, path string, hdr http.Header, body []byte) (*httptest.ResponseRecorder, error) {
	v.mu.Lock()
	refuse := v.refuse
	v.mu.Unlock()
	if refuse {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("refused"))
	}
	req := httptest.NewRequest(method, protov2.PathPrefix+path, bytes.NewReader(body)).WithContext(ctx)
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", protov2.MediaTypeJSON)
	}
	v.f.mu.Lock()
	key := v.f.APIKey
	v.f.mu.Unlock()
	req.Header.Set("Authorization", "Bearer "+key)
	b, _ := ctx.Value(fakeBindingKey{}).(string)
	req.Header.Set(HeaderV3Binding, b)
	rec := httptest.NewRecorder()
	v.f.serve(rec, req)
	if rec.Code == 0 || rec.Code == http.StatusOK && rec.Body.Len() == 0 && method != http.MethodDelete &&
		rec.Header().Get("Content-Type") == "" {
		// A dropped answer (Fault.Drop): the call was lost on the wire.
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("connection lost"))
	}
	if rec.Code >= 400 {
		code := connect.CodeInvalidArgument
		switch rec.Code {
		case 401:
			code = connect.CodeUnauthenticated
		case 403:
			code = connect.CodePermissionDenied
		case 404:
			code = connect.CodeNotFound
		case 409:
			code = connect.CodeAborted
		case 429:
			code = connect.CodeResourceExhausted
		case 500, 502, 504:
			code = connect.CodeInternal
		case 503:
			code = connect.CodeUnavailable
		}
		ce := connect.NewError(code, errors.New(http.StatusText(rec.Code)))
		ra, _ := strconv.Atoi(rec.Header().Get(protov2.HeaderRetryAfter))
		if d, err := connect.NewErrorDetail(&sensorv3.Problem{HttpStatus: int32(rec.Code), //nolint:gosec // a status
			ProblemJson: rec.Body.Bytes(), RetryAfterSeconds: int32(ra)}); err == nil { //nolint:gosec // bounded
			ce.AddDetail(d)
		}
		return nil, ce
	}
	return rec, nil
}

func retryAfter(rec *httptest.ResponseRecorder) int32 {
	n, _ := strconv.Atoi(rec.Header().Get(protov2.HeaderRetryAfter))
	return int32(n) //nolint:gosec // a small header value
}

func jsonHdr() http.Header { return http.Header{"Content-Type": []string{protov2.MediaTypeJSON}} }

// --- SensorServiceHandler ----------------------------------------------------

func (v *fakeV3) Hello(ctx context.Context, _ *connect.Request[sensorv3.HelloRequest]) (*connect.Response[sensorv3.HelloResponse], error) {
	rec, err := v.v2(ctx, http.MethodGet, protov2.HelloPath, nil, nil)
	if err != nil {
		return nil, err
	}
	b := sensorv3.Binding_BINDING_HTTPS
	if s, _ := ctx.Value(fakeBindingKey{}).(string); s == "grpc" {
		b = sensorv3.Binding_BINDING_GRPC
	}
	return connect.NewResponse(&sensorv3.HelloResponse{Protocol: 3, HelloJson: rec.Body.Bytes(), Binding: b}), nil
}

func (v *fakeV3) Heartbeat(ctx context.Context, r *connect.Request[sensorv3.HeartbeatRequest]) (*connect.Response[sensorv3.HeartbeatResponse], error) {
	rec, err := v.v2(ctx, http.MethodPost, protov2.HeartbeatPath, jsonHdr(), r.Msg.GetHeartbeatJson())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.HeartbeatResponse{HeartbeatJson: rec.Body.Bytes()}), nil
}

func (v *fakeV3) Subscribe(ctx context.Context, _ *connect.Request[sensorv3.SubscribeRequest], out *connect.ServerStream[sensorv3.SubscribeResponse]) error {
	w := make(chan struct{}, 1)
	v.mu.Lock()
	v.wakes = append(v.wakes, w)
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		for i, x := range v.wakes {
			if x == w {
				v.wakes = append(v.wakes[:i], v.wakes[i+1:]...)
				break
			}
		}
		v.mu.Unlock()
	}()
	send := func() error {
		v.f.mu.Lock()
		pending := len(v.f.cmdQueue)
		paused := v.f.Paused
		v.f.mu.Unlock()
		ev := &sensorv3.SubscribeResponse{Status: "ok", PendingJobs: int32(pending), Actions: []string{}} //nolint:gosec // small
		if paused {
			ev.Status, ev.Actions = "paused", []string{"pause"}
		}
		return out.Send(ev)
	}
	if err := send(); err != nil {
		return err
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w:
			if err := send(); err != nil {
				return err
			}
		case <-tick.C:
			if err := out.Send(&sensorv3.SubscribeResponse{Status: "ok", Keepalive: true}); err != nil {
				return err
			}
		}
	}
}

func (v *fakeV3) ClaimCommands(ctx context.Context, r *connect.Request[sensorv3.ClaimCommandsRequest]) (*connect.Response[sensorv3.ClaimCommandsResponse], error) {
	h := http.Header{}
	h.Set(protov2.HeaderSensorFeatures, strings.Join(r.Msg.GetFeatures(), ","))
	rec, err := v.v2(ctx, http.MethodGet, protov2.CommandsPath+"?limit="+strconv.Itoa(int(r.Msg.GetLimit())), h, nil)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.ClaimCommandsResponse{CommandsJson: rec.Body.Bytes()}), nil
}

var fakeTransitions = map[sensorv3.CommandTransition]string{1: "claim", 2: "start", 3: "complete", 4: "fail", 5: "release"}

func (v *fakeV3) TransitionCommand(ctx context.Context, r *connect.Request[sensorv3.TransitionCommandRequest]) (*connect.Response[sensorv3.TransitionCommandResponse], error) {
	a, ok := fakeTransitions[r.Msg.GetTransition()]
	if !ok || strings.ContainsAny(r.Msg.GetCommandId(), "/?#") {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad transition"))
	}
	h := jsonHdr()
	if r.Msg.LeaseEpoch != nil {
		h.Set(protov2.HeaderLeaseEpoch, strconv.FormatInt(r.Msg.GetLeaseEpoch(), 10))
	}
	rec, err := v.v2(ctx, http.MethodPost, protov2.CommandsPath+"/"+r.Msg.GetCommandId()+"/"+a, h, r.Msg.GetBodyJson())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.TransitionCommandResponse{CommandJson: rec.Body.Bytes()}), nil
}

func (v *fakeV3) AppendCommandLogs(ctx context.Context, r *connect.Request[sensorv3.AppendCommandLogsRequest]) (*connect.Response[sensorv3.AppendCommandLogsResponse], error) {
	rec, err := v.v2(ctx, http.MethodPost, protov2.CommandsPath+"/"+r.Msg.GetCommandId()+"/logs", jsonHdr(), r.Msg.GetBodyJson())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.AppendCommandLogsResponse{ResponseJson: rec.Body.Bytes()}), nil
}

func resultsPath(report, command string) string {
	if command == "" {
		return protov2.ResultsPath + "/" + report
	}
	return protov2.CommandsPath + "/" + command + protov2.ResultsPath + "/" + report
}

func (v *fakeV3) PutResult(ctx context.Context, r *connect.Request[sensorv3.PutResultRequest]) (*connect.Response[sensorv3.PutResultResponse], error) {
	m := r.Msg
	p := resultsPath(m.GetReportId(), m.GetCommandId())
	if m.Segment != nil {
		p += "/segments/" + strconv.FormatUint(uint64(m.GetSegment()), 10)
	}
	h := http.Header{}
	h.Set("Content-Type", m.GetContentType())
	if m.GetContentEncoding() != "" {
		h.Set("Content-Encoding", m.GetContentEncoding())
	}
	h.Set(protov2.HeaderContentDigest, m.GetContentDigest())
	rec, err := v.v2(ctx, http.MethodPut, p, h, m.GetContent())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.PutResultResponse{Created: rec.Code == http.StatusAccepted,
		StatusJson: rec.Body.Bytes(), RetryAfterSeconds: retryAfter(rec)}), nil
}

func (v *fakeV3) CommitResult(ctx context.Context, r *connect.Request[sensorv3.CommitResultRequest]) (*connect.Response[sensorv3.CommitResultResponse], error) {
	rec, err := v.v2(ctx, http.MethodPost, resultsPath(r.Msg.GetReportId(), r.Msg.GetCommandId())+"/commit", jsonHdr(), r.Msg.GetBodyJson())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.CommitResultResponse{Created: rec.Code == http.StatusAccepted,
		StatusJson: rec.Body.Bytes(), RetryAfterSeconds: retryAfter(rec)}), nil
}

func (v *fakeV3) GetResultStatus(ctx context.Context, r *connect.Request[sensorv3.GetResultStatusRequest]) (*connect.Response[sensorv3.GetResultStatusResponse], error) {
	rec, err := v.v2(ctx, http.MethodGet, resultsPath(r.Msg.GetReportId(), ""), nil, nil)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.GetResultStatusResponse{StatusJson: rec.Body.Bytes(), RetryAfterSeconds: retryAfter(rec)}), nil
}

func (v *fakeV3) AbandonResult(ctx context.Context, r *connect.Request[sensorv3.AbandonResultRequest]) (*connect.Response[sensorv3.AbandonResultResponse], error) {
	if _, err := v.v2(ctx, http.MethodDelete, resultsPath(r.Msg.GetReportId(), ""), nil, nil); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.AbandonResultResponse{}), nil
}

func (v *fakeV3) PutManifest(ctx context.Context, r *connect.Request[sensorv3.PutManifestRequest]) (*connect.Response[sensorv3.PutManifestResponse], error) {
	rec, err := v.v2(ctx, http.MethodPut, protov2.ManifestPath, jsonHdr(), r.Msg.GetManifestJson())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.PutManifestResponse{ResponseJson: rec.Body.Bytes()}), nil
}

func (v *fakeV3) GetManifest(ctx context.Context, _ *connect.Request[sensorv3.GetManifestRequest]) (*connect.Response[sensorv3.GetManifestResponse], error) {
	rec, err := v.v2(ctx, http.MethodGet, protov2.ManifestPath, nil, nil)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.GetManifestResponse{ResponseJson: rec.Body.Bytes()}), nil
}

func (v *fakeV3) PutConfigReport(ctx context.Context, r *connect.Request[sensorv3.PutConfigReportRequest]) (*connect.Response[sensorv3.PutConfigReportResponse], error) {
	rec, err := v.v2(ctx, http.MethodPut, protov2.ConfigReportPath, jsonHdr(), r.Msg.GetReportJson())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.PutConfigReportResponse{ResponseJson: rec.Body.Bytes()}), nil
}

func (v *fakeV3) GetSuppressions(ctx context.Context, r *connect.Request[sensorv3.GetSuppressionsRequest]) (*connect.Response[sensorv3.GetSuppressionsResponse], error) {
	h := http.Header{}
	if r.Msg.GetEtag() != "" {
		h.Set("If-None-Match", r.Msg.GetEtag())
	}
	rec, err := v.v2(ctx, http.MethodGet, protov2.SuppressionsPath, h, nil)
	if err != nil {
		return nil, err
	}
	out := &sensorv3.GetSuppressionsResponse{Etag: rec.Header().Get("ETag")}
	if rec.Code == http.StatusNotModified {
		out.NotModified = true
	} else {
		out.SuppressionsJson = rec.Body.Bytes()
	}
	return connect.NewResponse(out), nil
}

func (v *fakeV3) CheckFingerprints(ctx context.Context, r *connect.Request[sensorv3.CheckFingerprintsRequest]) (*connect.Response[sensorv3.CheckFingerprintsResponse], error) {
	rec, err := v.v2(ctx, http.MethodPost, protov2.FingerprintsCheckPath, jsonHdr(), r.Msg.GetRequestJson())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.CheckFingerprintsResponse{ResponseJson: rec.Body.Bytes()}), nil
}

func (v *fakeV3) BaselineDiff(ctx context.Context, r *connect.Request[sensorv3.BaselineDiffRequest]) (*connect.Response[sensorv3.BaselineDiffResponse], error) {
	rec, err := v.v2(ctx, http.MethodPost, protov2.BaselineDiffPath, jsonHdr(), r.Msg.GetRequestJson())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.BaselineDiffResponse{ResponseJson: rec.Body.Bytes()}), nil
}

func (v *fakeV3) IssueCertificate(ctx context.Context, _ *connect.Request[sensorv3.IssueCertificateRequest]) (*connect.Response[sensorv3.IssueCertificateResponse], error) {
	v.mu.Lock()
	refuse := v.refuse
	v.mu.Unlock()
	if refuse {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("refused"))
	}
	if v.grpc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("no gRPC binding"))
	}
	der, err := v.issue(v.trusted, true, "", time.Hour)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	now := time.Now()
	return connect.NewResponse(&sensorv3.IssueCertificateResponse{
		CertificateChainPem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		CaBundlePem:         v.caPEM,
		NotBefore:           timestamppb.New(now.Add(-time.Minute)),
		NotAfter:            timestamppb.New(now.Add(time.Hour)),
		RenewAfter:          timestamppb.New(now.Add(40 * time.Minute)),
		GrpcEndpoint:        strings.TrimPrefix(v.grpc.URL, "https://"),
	}), nil
}
