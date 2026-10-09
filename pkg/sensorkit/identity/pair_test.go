package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// fakePlatform implements the platform side of pairing with the shared
// protocol package, verifying every request signature like the API does.
type fakePlatform struct {
	t *testing.T

	mu          sync.Mutex
	platformKey ed25519.PrivateKey
	sensorPub   ed25519.PublicKey
	commitment  []byte
	nonceP      []byte
	revealed    []byte
	status      string
	starts      int
	lastCode    string
	confirmed   bool
	sas         pairing.SAS
	unsigned    int

	// knobs
	tamperSignature bool
	grantKeyID      string // identity for another key
	finalStatus     string // what the poll answers after the first poll
}

func newFakePlatform(t *testing.T) (*fakePlatform, *httptest.Server) {
	_, pk, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakePlatform{t: t, platformKey: pk, finalStatus: pairing.StatusApproved}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakePlatform) verify(r *http.Request, pub ed25519.PublicKey) []byte {
	body, _ := io.ReadAll(r.Body)
	if r.Header.Get("Authorization") != "" {
		f.unsigned++
	}
	p, err := sensorsig.Parse(r.Header)
	if err != nil || p.CheckWindow(time.Now()) != nil || p.Verify(r, pub) != nil {
		f.unsigned++
		return body
	}
	if len(body) > 0 && sensorsig.VerifyContentDigest(r.Header.Get(sensorsig.HeaderContentDigest), body) != nil {
		f.unsigned++
	}
	return body
}

const pid = "0f8e1d5c-2b3a-4c5d-8e9f-0a1b2c3d4e5f"

func (f *fakePlatform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	base := "/api/v2/sensor/pairings"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == base:
		raw, _ := io.ReadAll(r.Body)
		var req pairing.StartRequest
		_ = json.Unmarshal(raw, &req)
		pub, _ := pairing.DecodeKey(req.PublicKey)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		f.verify(r, pub)
		f.sensorPub = pub
		f.commitment, _ = pairing.DecodeFixed(req.Commitment, 32)
		f.nonceP, _ = pairing.NewNonce()
		f.lastCode = req.Code
		f.starts++
		f.status = pairing.StatusPending
		f.revealed = nil
		exp := time.Now().Add(10 * time.Minute).Truncate(time.Second)
		ppub, _ := f.platformKey.Public().(ed25519.PublicKey)
		sig := ed25519.Sign(f.platformKey, pairing.PlatformTranscript(pid, pub, f.commitment, ppub, f.nonceP, exp))
		if f.tamperSignature {
			sig[0] ^= 1
		}
		resp := pairing.StartResponse{PairingID: pid, PlatformKey: pairing.Encode(ppub), PlatformNonce: pairing.Encode(f.nonceP),
			PlatformSignature: pairing.Encode(sig), ExpiresAt: exp, PollSeconds: 1}
		if req.Code == "" {
			resp.UserCode = "K7QM-4ZTD"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	case r.Method == http.MethodPut && r.URL.Path == base+"/"+pid+"/nonce":
		body := f.verify(r, f.sensorPub)
		var req pairing.RevealRequest
		_ = json.Unmarshal(body, &req)
		n, _ := pairing.DecodeFixed(req.SensorNonce, 32)
		if pairing.CheckCommitment(f.commitment, n) != nil {
			http.Error(w, "commitment", http.StatusBadRequest)
			return
		}
		f.revealed = n
		ppub, _ := f.platformKey.Public().(ed25519.PublicKey)
		f.sas = pairing.ComputeSAS(f.sensorPub, ppub, n, f.nonceP)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == base+"/"+pid:
		f.verify(r, f.sensorPub)
		if f.revealed == nil {
			http.Error(w, "not revealed", http.StatusNotFound)
			return
		}
		if f.status == pairing.StatusPending {
			f.status = f.finalStatus
			_ = json.NewEncoder(w).Encode(pairing.StatusResponse{Status: pairing.StatusPending, PollSeconds: 1})
			return
		}
		st := pairing.StatusResponse{Status: f.status}
		if f.status == pairing.StatusApproved {
			kid := sensorsig.Thumbprint(f.sensorPub)
			if f.grantKeyID != "" {
				kid = f.grantKeyID
			}
			st.Identity = &pairing.Identity{SensorID: "11111111-2222-3333-4444-555555555555", TenantID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				TenantName: "Acme", Name: "dmz-01", KeyID: kid}
		}
		_ = json.NewEncoder(w).Encode(st)
	case r.Method == http.MethodPost && r.URL.Path == base+"/"+pid+"/complete":
		body := f.verify(r, f.sensorPub)
		var req pairing.ConfirmRequest
		_ = json.Unmarshal(body, &req)
		sig, _ := pairing.DecodeFixed(req.Signature, ed25519.SignatureSize)
		msg := pairing.ConfirmTranscript(pid, req.SensorID, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", req.KeyID)
		if !ed25519.Verify(f.sensorPub, msg, sig) {
			http.Error(w, "bad confirm", http.StatusBadRequest)
			return
		}
		f.confirmed = true
		f.status = pairing.StatusCompleted
		_ = json.NewEncoder(w).Encode(pairing.StatusResponse{Status: pairing.StatusCompleted})
	default:
		http.NotFound(w, r)
	}
}

func opts(t *testing.T, srv *httptest.Server, out io.Writer) PairOptions {
	t.Helper()
	return PairOptions{BaseURL: srv.URL, Store: NewStore(t.TempDir()), Out: out, HTTPClient: srv.Client(),
		Host:  DefaultHostFacts("openctemio-sensor", "0.0.0-test", "dmz-01"),
		sleep: func(context.Context, time.Duration) error { return nil }}
}

func TestPairForwardMode(t *testing.T) {
	f, srv := newFakePlatform(t)
	var out bytes.Buffer
	o := opts(t, srv, &out)
	id, err := Pair(context.Background(), o)
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if !f.confirmed || f.unsigned != 0 {
		t.Fatalf("confirmed=%v unsigned requests=%d", f.confirmed, f.unsigned)
	}
	// The person sees the code and exactly the SAS the platform computed.
	for _, want := range []string{"K7QM-4ZTD", f.sas.String()} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
	got, sg, err := o.Store.Load()
	if err != nil || got.SensorID != id.SensorID || sg.KeyID() != sensorsig.Thumbprint(f.sensorPub) {
		t.Fatalf("load: %v %+v", err, got)
	}
	for path, mode := range map[string]os.FileMode{o.Store.Dir(): 0o700, filepath.Join(o.Store.Dir(), KeyFile): 0o600,
		filepath.Join(o.Store.Dir(), IdentityFile): 0o600} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v mode %v, want %v", path, err, fi.Mode().Perm(), mode)
		}
	}
	// Nothing secret in the identity file.
	b, _ := os.ReadFile(filepath.Join(o.Store.Dir(), IdentityFile))
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("identity.json holds key material")
	}
	// A sensor paired by this SDK fails closed without a local policy.
	if !id.RequireLocalPolicy || !got.RequireLocalPolicy || !strings.Contains(string(b), `"require_local_policy": true`) {
		t.Fatalf("the identity does not require a local policy: %s", b)
	}
}

func TestPairReverseModeSendsTheCodeAndPrintsNoCode(t *testing.T) {
	f, srv := newFakePlatform(t)
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.Code = "k7qm-4ztd"
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if f.lastCode != "K7QM4ZTD" {
		t.Fatalf("code sent %q", f.lastCode)
	}
	if strings.Contains(out.String(), "Code:") || !strings.Contains(out.String(), f.sas.String()) {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestPairRefusesATamperedPlatformSignature(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.tamperSignature = true
	o := opts(t, srv, io.Discard)
	if _, err := Pair(context.Background(), o); !errors.Is(err, pairing.ErrPlatformSignature) {
		t.Fatalf("err = %v", err)
	}
	if f.revealed != nil {
		t.Fatal("the nonce must not be revealed to an unverified platform")
	}
}

func TestPairRefusesAnotherPlatformKeyThanThePinned(t *testing.T) {
	f, srv := newFakePlatform(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	o := opts(t, srv, io.Discard)
	o.PlatformKeyPin = sensorsig.Thumbprint(other.Public().(ed25519.PublicKey))
	if _, err := Pair(context.Background(), o); !errors.Is(err, pairing.ErrPlatformKeyPin) {
		t.Fatalf("err = %v", err)
	}
	// The right pin passes.
	o.PlatformKeyPin = "SHA256:" + sensorsig.Thumbprint(f.platformKey.Public().(ed25519.PublicKey))
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatal(err)
	}
}

func TestPairRefusesAnIdentityForAnotherKey(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.grantKeyID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	o := opts(t, srv, io.Discard)
	if _, err := Pair(context.Background(), o); err == nil || f.confirmed {
		t.Fatalf("err = %v confirmed = %v", err, f.confirmed)
	}
	if _, _, err := o.Store.Load(); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("an identity was saved: %v", err)
	}
}

func TestPairDeniedAndExpired(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.finalStatus = pairing.StatusDenied
	if _, err := Pair(context.Background(), opts(t, srv, io.Discard)); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied: %v", err)
	}
	f.finalStatus = pairing.StatusExpired
	if _, err := Pair(context.Background(), opts(t, srv, io.Discard)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
}

func TestPairRetryStartsANewRequestWithTheSameKey(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.finalStatus = pairing.StatusExpired
	o := opts(t, srv, io.Discard)
	o.Retry = true
	var firstKey ed25519.PublicKey
	o.sleep = func(context.Context, time.Duration) error {
		if f.starts == 1 && firstKey == nil {
			firstKey = f.sensorPub
		}
		if f.starts >= 2 {
			f.finalStatus = pairing.StatusApproved
		}
		return nil
	}
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if f.starts < 2 || !firstKey.Equal(f.sensorPub) {
		t.Fatalf("starts=%d, same key=%v", f.starts, firstKey.Equal(f.sensorPub))
	}
}

func TestStoreRefusesLoosePermissionsWithTheFix(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(s.Dir(), KeyFile)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := s.LoadKey()
	var pe *PermissionError
	if !errors.As(err, &pe) || pe.Fix != "chmod 0600 "+key {
		t.Fatalf("err = %v", err)
	}
	_ = os.Chmod(key, 0o600)
	if err := os.Chmod(s.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadKey(); !errors.As(err, &pe) || pe.Fix != "chmod 0700 "+s.Dir() {
		t.Fatalf("dir: %v", err)
	}
	_ = os.Chmod(s.Dir(), 0o700)
	// A symbolic link in place of the key is refused.
	_ = os.Rename(key, key+".real")
	if err := os.Symlink(key+".real", key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadKey(); !errors.As(err, &pe) {
		t.Fatalf("symlink: %v", err)
	}
}

func TestStoreKeyMismatchIsRefused(t *testing.T) {
	s := NewStore(t.TempDir())
	sg, err := s.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&Identity{SensorID: "s", KeyID: "another"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err == nil || !strings.Contains(err.Error(), sg.KeyID()) {
		t.Fatalf("err = %v", err)
	}
	// RotateKey makes a new key and drops the identity.
	ng, err := s.RotateKey()
	if err != nil || ng.KeyID() == sg.KeyID() {
		t.Fatalf("rotate: %v", err)
	}
	if _, _, err := s.Load(); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("after rotate: %v", err)
	}
}

func TestEnsureKeyKeepsTheKeyAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	a, err := NewStore(dir).EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewStore(dir).EnsureKey()
	if err != nil || a.KeyID() != b.KeyID() {
		t.Fatalf("restart made a new key: %v", err)
	}
}
