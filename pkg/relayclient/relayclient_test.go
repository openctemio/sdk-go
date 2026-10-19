package relayclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sealedmsg"
	"github.com/openctemio/sdk-go/pkg/sensorproto/relay"
)

// fakeRelay plays the relay and the platform's connector in one server:
// it opens each request with the ingest key and queues a signed, sealed
// answer for the sensor.
type fakeRelay struct {
	t         *testing.T
	ts        *httptest.Server
	route     sealedmsg.Route
	ingest    *sealedmsg.PrivateKey
	respKey   ed25519.PrivateKey
	sensorPub *sealedmsg.PublicKey
	sensorID  ed25519.PublicKey
	ticket    string

	mu       sync.Mutex
	down     [][]byte
	wake     chan struct{}
	seen     []*sealedmsg.Request
	answer   func(req *sealedmsg.Request, digest [32]byte) [][]byte // envelopes to queue (default: one honest answer)
	throttle atomic.Int32                                           // 429 this many times first
}

func newFakeRelay(t *testing.T, sensorID ed25519.PublicKey, sensorEnc *sealedmsg.PrivateKey) *fakeRelay {
	t.Helper()
	ik, _ := sealedmsg.GenerateKey()
	_, rk, _ := ed25519.GenerateKey(nil)
	f := &fakeRelay{t: t, route: sealedmsg.Route{Realm: "realm-1", SensorID: "sensor-1"}, ingest: ik, respKey: rk,
		sensorPub: sensorEnc.Public(), sensorID: sensorID, ticket: "v1.ticket", wake: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+relay.PathSensorUp, f.up)
	mux.HandleFunc("GET "+relay.PathSensorDown, f.downPoll)
	f.ts = httptest.NewUnstartedServer(mux)
	f.ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	f.ts.StartTLS()
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeRelay) authorized(r *http.Request) bool {
	if r.Header.Get(relay.TicketHeader) != f.ticket || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return ok && pub.Equal(f.sensorID)
}

func (f *fakeRelay) honest(req *sealedmsg.Request, digest [32]byte) [][]byte {
	env, err := sealedmsg.SealResponse(f.sensorPub, f.respKey, f.route, digest,
		&sealedmsg.Response{Status: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: []byte("answer:" + req.Path)})
	if err != nil {
		f.t.Error(err)
	}
	return [][]byte{env}
}

func (f *fakeRelay) up(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if f.throttle.Load() > 0 {
		f.throttle.Add(-1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	env, _ := io.ReadAll(r.Body)
	req, err := sealedmsg.OpenRequest([]*sealedmsg.PrivateKey{f.ingest}, f.route, env)
	if err != nil {
		f.t.Errorf("platform could not open the request: %v", err)
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	answer := f.answer
	if answer == nil {
		answer = f.honest
	}
	f.mu.Lock()
	f.seen = append(f.seen, req)
	f.down = append(f.down, answer(req, sealedmsg.Digest(env))...)
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
	w.WriteHeader(http.StatusAccepted)
}

func (f *fakeRelay) downPoll(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	deadline := time.After(2 * time.Second)
	for {
		f.mu.Lock()
		items := make([]relay.Item, 0, len(f.down))
		for _, e := range f.down {
			items = append(items, relay.Item{Envelope: e})
		}
		f.down = nil
		f.mu.Unlock()
		if len(items) > 0 {
			var buf bytes.Buffer
			_ = relay.WriteBatch(&buf, items)
			w.Header().Set("Content-Type", relay.BatchContentType)
			_, _ = w.Write(buf.Bytes())
			return
		}
		select {
		case <-f.wake:
		case <-deadline:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (f *fakeRelay) pin() []byte {
	sum := sha256.Sum256(f.ts.Certificate().RawSubjectPublicKeyInfo)
	return sum[:]
}

type sensorKeys struct {
	id  ed25519.PrivateKey
	enc *sealedmsg.PrivateKey
}

func newSensor(t *testing.T) sensorKeys {
	t.Helper()
	_, id, _ := ed25519.GenerateKey(nil)
	enc, _ := sealedmsg.GenerateKey()
	return sensorKeys{id: id, enc: enc}
}

func newTransport(t *testing.T, f *fakeRelay, s sensorKeys, mod func(*Config)) (*Transport, context.CancelFunc) {
	t.Helper()
	cfg := Config{RelayURL: f.ts.URL, RelayPin: f.pin(), Identity: s.id, Ticket: func() string { return f.ticket },
		Route: f.route, IngestKey: f.ingest.Public(), ResponseKeys: []ed25519.PublicKey{f.respKey.Public().(ed25519.PublicKey)},
		EncryptionKey: s.enc, ResponseTimeout: 5 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	tr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go tr.Run(ctx)
	t.Cleanup(cancel)
	return tr, cancel
}

func get(t *testing.T, tr http.RoundTripper, path string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://platform.example.com"+path, strings.NewReader(`{"x":1}`))
	req.Header.Set("Signature", "sig1=:abc:")
	return (&http.Client{Transport: tr}).Do(req)
}

func TestRoundTripThroughRelay(t *testing.T) {
	s := newSensor(t)
	f := newFakeRelay(t, s.id.Public().(ed25519.PublicKey), s.enc)
	tr, _ := newTransport(t, f, s, nil)
	resp, err := get(t, tr, "/api/v2/sensor/heartbeat?a=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "answer:/api/v2/sensor/heartbeat?a=1" || resp.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}
	f.mu.Lock()
	seen := f.seen[0]
	f.mu.Unlock()
	if seen.Header.Get("Signature") != "sig1=:abc:" || string(seen.Body) != `{"x":1}` || seen.Method != "POST" {
		t.Fatalf("platform saw %+v", seen)
	}
	if st := tr.Stats(); st.Sent != 1 || st.Answered != 1 || st.PendingRequests != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestConcurrentRequestsMatched(t *testing.T) {
	s := newSensor(t)
	f := newFakeRelay(t, s.id.Public().(ed25519.PublicKey), s.enc)
	tr, _ := newTransport(t, f, s, nil)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			path := "/api/v2/sensor/r" + string(rune('a'+i))
			resp, err := get(t, tr, path)
			if err != nil {
				t.Error(err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "answer:"+path {
				t.Errorf("request %s got %q", path, body)
			}
		}()
	}
	wg.Wait()
}

// TestForgedAndReplayedAnswersDropped: the relay cannot answer in the
// platform's name, and a replayed answer reaches no request.
func TestForgedAndReplayedAnswersDropped(t *testing.T) {
	s := newSensor(t)
	f := newFakeRelay(t, s.id.Public().(ed25519.PublicKey), s.enc)
	_, relayKey, _ := ed25519.GenerateKey(nil)
	f.answer = func(req *sealedmsg.Request, d [32]byte) [][]byte {
		forged, _ := sealedmsg.SealResponse(f.sensorPub, relayKey, f.route, d, &sealedmsg.Response{Status: 200, Body: []byte("evil")})
		return [][]byte{forged}
	}
	tr, _ := newTransport(t, f, s, func(c *Config) { c.ResponseTimeout = 1500 * time.Millisecond })
	if _, err := get(t, tr, "/api/v2/sensor/commands"); !errors.Is(err, ErrNoResponse) {
		t.Fatalf("forged answer: %v, want ErrNoResponse", err)
	}
	if st := tr.Stats(); st.DroppedRefused != 1 || st.TimedOut != 1 {
		t.Fatalf("stats %+v", st)
	}
	// Honest answer, delivered twice by the relay: the copy reaches nothing.
	f.answer = func(req *sealedmsg.Request, d [32]byte) [][]byte {
		e := f.honest(req, d)
		return [][]byte{e[0], e[0]}
	}
	if _, err := get(t, tr, "/api/v2/sensor/commands"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for tr.Stats().DroppedForeign != 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if st := tr.Stats(); st.DroppedForeign != 1 || st.Answered != 1 {
		t.Fatalf("replayed answer not dropped: %+v", st)
	}
}

func TestRelayPinMismatch(t *testing.T) {
	s := newSensor(t)
	f := newFakeRelay(t, s.id.Public().(ed25519.PublicKey), s.enc)
	tr, _ := newTransport(t, f, s, func(c *Config) { c.RelayPin = make([]byte, 32) })
	if _, err := get(t, tr, "/x"); err == nil || !errors.Is(err, ErrPin) {
		t.Fatalf("wrong pin: %v", err)
	}
}

func TestTicketRefusedAndThrottle(t *testing.T) {
	s := newSensor(t)
	f := newFakeRelay(t, s.id.Public().(ed25519.PublicKey), s.enc)
	var refused atomic.Int32
	tr, _ := newTransport(t, f, s, func(c *Config) {
		c.Ticket = func() string { return "v1.stale" }
		c.OnTicketRefused = func() { refused.Add(1) }
	})
	if _, err := get(t, tr, "/x"); !errors.Is(err, ErrTicket) {
		t.Fatalf("stale ticket: %v", err)
	}
	if refused.Load() == 0 {
		t.Fatal("refusal callback not called")
	}
	// A relay that throttles once: the request waits and goes through.
	s2 := newSensor(t)
	f2 := newFakeRelay(t, s2.id.Public().(ed25519.PublicKey), s2.enc)
	f2.throttle.Store(1)
	tr2, _ := newTransport(t, f2, s2, nil)
	if _, err := get(t, tr2, "/x"); err != nil {
		t.Fatalf("after throttle: %v", err)
	}
	if st := tr2.Stats(); st.RelayThrottled != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// TestRelayCannotRead: the bytes the relay receives hold neither the path
// nor the body.
func TestRelayCannotRead(t *testing.T) {
	s := newSensor(t)
	f := newFakeRelay(t, s.id.Public().(ed25519.PublicKey), s.enc)
	var raw []byte
	inner := f.ts.Config.Handler
	f.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == relay.PathSensorUp {
			raw, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		inner.ServeHTTP(w, r)
	})
	tr, _ := newTransport(t, f, s, nil)
	if _, err := get(t, tr, "/api/v2/sensor/secret-path"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-path")) || bytes.Contains(raw, []byte(`{"x":1}`)) || bytes.Contains(raw, []byte("sig1")) {
		t.Fatal("the relay can read the request")
	}
}

func TestConfigRefusals(t *testing.T) {
	s := newSensor(t)
	ik, _ := sealedmsg.GenerateKey()
	pub, _, _ := ed25519.GenerateKey(nil)
	good := Config{RelayURL: "https://relay.example.com", Identity: s.id, Ticket: func() string { return "" },
		Route: sealedmsg.Route{Realm: "r", SensorID: "s"}, IngestKey: ik.Public(), ResponseKeys: []ed25519.PublicKey{pub}, EncryptionKey: s.enc}
	if _, err := New(good); err != nil {
		t.Fatalf("good config: %v", err)
	}
	for name, mod := range map[string]func(*Config){
		"http url":      func(c *Config) { c.RelayURL = "http://relay.example.com" },
		"no identity":   func(c *Config) { c.Identity = nil },
		"no ticket":     func(c *Config) { c.Ticket = nil },
		"no resp keys":  func(c *Config) { c.ResponseKeys = nil },
		"no route":      func(c *Config) { c.Route = sealedmsg.Route{} },
		"short pin":     func(c *Config) { c.RelayPin = []byte{1} },
		"no ingest key": func(c *Config) { c.IngestKey = nil },
	} {
		c := good
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
