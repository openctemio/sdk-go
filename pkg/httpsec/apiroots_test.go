package httpsec

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A platform behind a private CA: an API client trusts it only after its CA
// is added with SetAPIRootCAs, and clients created before keep their trust.
func TestSetAPIRootCAs_TrustsPrivateCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	t.Cleanup(func() { SetAPIRootCAs(nil) })

	before := NewAPIClient(5 * time.Second)
	if resp, err := before.Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("an unknown CA was trusted")
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadCAFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	SetAPIRootCAs(pool)
	if APIRootCAs() != pool {
		t.Fatal("APIRootCAs does not return the pool")
	}
	resp, err := NewAPIClient(5 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("private CA not trusted: %v", err)
	}
	_ = resp.Body.Close()
	if resp, err := before.Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a client created before SetAPIRootCAs changed its trust")
	}
}

func TestLoadCAFile_Errors(t *testing.T) {
	if _, err := LoadCAFile(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing file accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCAFile(empty); err == nil {
		t.Fatal("a file without a certificate accepted")
	}
}
