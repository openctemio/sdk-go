package client

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	sensorv3 "github.com/openctemio/sdk-go/pkg/sensorproto/v3"
	sensorv3connect "github.com/openctemio/sdk-go/pkg/sensorproto/v3/sensorv3connect"
)

// redirectTarget is a second origin that records every request it gets (the
// redirect target of an attacker, or a plain-http downgrade).
func redirectTarget(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int32
	var bytesIn atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		hits.Add(1)
		bytesIn.Add(n)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &bytesIn
}

func putResult(svc sensorv3connect.SensorServiceClient) error {
	_, err := svc.PutResult(context.Background(), connect.NewRequest(&sensorv3.PutResultRequest{
		ReportId: "r1", Content: []byte(`{"findings":["finding-data"]}`)}))
	return err
}

// The protocol v3 HTTPS binding must not follow a redirect: the signing
// transport would sign the RPC again for the other host (the signature does
// not cover the host) and send the body there, even over plain http.
func TestV3HTTPSBindingRefusesRedirects(t *testing.T) {
	other, hits, bodyBytes := redirectTarget(t)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer a.Close()

	c := New(&Config{BaseURL: a.URL, APIKey: "k"})
	m := &v3Manager{c: c, next: c.httpClient.Transport}
	err := putResult(m.httpsClient("/api/v3"))
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("PutResult err = %v, want an error naming the refused redirect", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the redirect target got %d request(s) with %d body bytes, want none", n, bodyBytes.Load())
	}
}

// The gRPC binding's client refuses redirects too.
func TestV3GRPCBindingRefusesRedirects(t *testing.T) {
	other, hits, bodyBytes := redirectTarget(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c := New(&Config{BaseURL: srv.URL, APIKey: "k"})
	m := &v3Manager{c: c, next: c.httpClient.Transport, pin: pool}
	err := putResult(m.grpcClient(strings.TrimPrefix(srv.URL, "https://")))
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("PutResult err = %v, want an error naming the refused redirect", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the redirect target got %d request(s) with %d body bytes, want none", n, bodyBytes.Load())
	}
}
