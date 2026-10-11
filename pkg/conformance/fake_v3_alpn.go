package conformance

// The platform gateway's ALPN routing (openctem api RFC-059 §5), emulated in
// front of the fake's gRPC binding: one port for everything, as on a
// platform reached by an IP address or a single host name.

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"time"
)

// SensorALPN is the ALPN id the router passes through to the gRPC binding
// (client.SensorALPN; repeated here so the fake does not import the client).
const SensorALPN = "openctem-sensor/3"

type alpnRouter struct {
	ln   net.Listener
	term *httptest.Server

	mu      sync.Mutex
	offered []string
}

// RouteV3GRPCByALPN puts ALPN routing in front of the gRPC binding: a
// ClientHello that offers SensorALPN is passed through to the listener byte
// for byte; any other meets a server that terminates TLS with a certificate
// of its own (the web UI behind the gateway). The v2 hello then names the
// router as grpc_alpn_endpoint only, and no grpc_endpoint.
func (f *FakePlatform) RouteV3GRPCByALPN() error {
	f.mu.Lock()
	v := f.v3
	f.mu.Unlock()
	if v == nil || v.grpc == nil {
		return errors.New("EnableV3 with the gRPC binding first")
	}
	term := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "gateway")
	}))
	term.EnableHTTP2 = true
	term.StartTLS()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		term.Close()
		return err
	}
	r := &alpnRouter{ln: ln, term: term}
	upstream := v.grpc.Listener.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.route(c, upstream)
		}
	}()
	v.mu.Lock()
	v.alpn = r
	v.mu.Unlock()
	return nil
}

// V3OfferedALPN is the ALPN ids of the last ClientHello the router saw.
func (f *FakePlatform) V3OfferedALPN() []string {
	f.mu.Lock()
	v := f.v3
	f.mu.Unlock()
	if v == nil {
		return nil
	}
	v.mu.Lock()
	r := v.alpn
	v.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.offered)
}

func (r *alpnRouter) addr() string { return r.ln.Addr().String() }

func (r *alpnRouter) close() {
	_ = r.ln.Close()
	r.term.Close()
}

var errHelloRead = errors.New("client hello read")

// helloConn feeds the TLS server what the client sent and swallows its
// answers (the alert after the peek).
type helloConn struct {
	net.Conn
	r io.Reader
}

func (h helloConn) Read(b []byte) (int, error)  { return h.r.Read(b) }
func (h helloConn) Write(b []byte) (int, error) { return len(b), nil }

func (r *alpnRouter) route(c net.Conn, upstream string) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var seen bytes.Buffer
	var protos []string
	_ = tls.Server(helloConn{Conn: c, r: io.TeeReader(c, &seen)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			protos = h.SupportedProtos
			return nil, errHelloRead
		},
	}).Handshake()
	_ = c.SetReadDeadline(time.Time{})
	r.mu.Lock()
	r.offered = protos
	r.mu.Unlock()
	target := r.term.Listener.Addr().String()
	if slices.Contains(protos, SensorALPN) {
		target = upstream
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := up.Write(seen.Bytes()); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, up)
		_ = c.Close()
	}()
	_, _ = io.Copy(up, c)
	_ = up.Close()
	wg.Wait()
}
