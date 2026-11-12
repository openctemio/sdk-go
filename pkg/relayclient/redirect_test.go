package relayclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The relay is not trusted: a redirect (here to a plain-http server, an
// https to http downgrade with no dial guard) must not be followed, on the
// request path (postUp) nor on the answer poll.
func TestRelayRedirectIsRefused(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer other.Close()
	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	s := newSensor(t)
	f := newFakeRelay(t, s.id.Public().(ed25519.PublicKey), s.enc)
	pin := sha256.Sum256(redirecting.Certificate().RawSubjectPublicKeyInfo)
	tr, _ := newTransport(t, f, s, func(c *Config) {
		c.RelayURL = redirecting.URL
		c.RelayPin = pin[:]
	})

	// The request path: the sealed message must not reach the other server.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://platform.example.com/api/v2/sensor/heartbeat", strings.NewReader(`{"x":1}`))
	if _, err := tr.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("RoundTrip err = %v, want an error naming the refused redirect", err)
	}
	// The answer poll.
	if err := tr.pollOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("pollOnce err = %v, want an error naming the refused redirect", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the redirect target got %d request(s), want 0", n)
	}
}
