package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// A key-bound client (Config.Signer) sends no bearer key; every request,
// heartbeats included, carries a signature the sensor's public key verifies.
func TestKeyBoundClientSignsEveryRequest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := sensorsig.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen, bad int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen++
		body, _ := io.ReadAll(r.Body)
		p, err := sensorsig.Parse(r.Header)
		switch {
		case r.Header.Get("Authorization") != "":
			bad++
		case err != nil || p.CheckWindow(time.Now()) != nil || p.Verify(r, pub) != nil || p.Params.KeyID != signer.KeyID():
			bad++
		case len(body) > 0 && sensorsig.VerifyContentDigest(r.Header.Get(sensorsig.HeaderContentDigest), body) != nil:
			bad++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	c := New(&Config{BaseURL: srv.URL, APIKey: "octs_must_not_be_sent", Signer: signer, Protocol: "v1", Timeout: 5 * time.Second})
	if !c.KeyBound() {
		t.Fatal("KeyBound")
	}
	_ = c.SendHeartbeat(context.Background(), &core.SensorStatus{Name: "s", Status: core.SensorStateRunning})
	_, _ = c.PollCommands(context.Background(), 1)
	mu.Lock()
	defer mu.Unlock()
	if seen < 2 || bad != 0 {
		t.Fatalf("requests=%d unsigned or bearer=%d", seen, bad)
	}
	if hint := c.APIKeyHint(); hint == "" || hint[:len("signing key")] != "signing key" {
		t.Fatalf("hint %q", hint)
	}
}
