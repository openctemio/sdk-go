package sensorkit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// fakeBindPlatform serves hello and the bind resource. answer decides the
// bind's status for a bearer call ("ok", "approval", "refused", "error",
// "bound": the API key is already retired).
type fakeBindPlatform struct {
	mu       sync.Mutex
	answer   string
	feature  bool
	binds    int
	signed   int
	boundKey string
}

func (f *fakeBindPlatform) serve(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(protov2.PathPrefix+protov2.HelloPath, func(w http.ResponseWriter, _ *http.Request) {
		feats := []string{protov2.FeatureResults}
		if f.feature {
			feats = append(feats, protov2.FeatureKeyBind)
		}
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		_ = json.NewEncoder(w).Encode(map[string]any{"protocol": 2, "features": feats})
	})
	mux.HandleFunc(protov2.PathPrefix+protov2.IdentityBindPath, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var req protov2.KeyBindRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("bind body: %v", err)
		}
		pub, _ := base64.RawURLEncoding.DecodeString(req.PublicKey)
		sig, _ := base64.RawURLEncoding.DecodeString(req.Proof)
		thumb := sensorsig.Thumbprint(pub)
		if !ed25519.Verify(pub, protov2.KeyBindProofMessage(thumb, req.IssuedAt), sig) {
			t.Errorf("proof of possession does not verify")
		}
		problem := func(status int, name string) {
			w.Header().Set("Content-Type", protov2.MediaTypeProblem)
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"type":%q,"status":%d}`, protov2.ProblemTypeBaseSensor+name, status)
		}
		bearer := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !bearer {
			f.signed++
			if f.boundKey == thumb {
				w.Header().Set("Content-Type", protov2.MediaTypeJSON)
				_ = json.NewEncoder(w).Encode(protov2.KeyBindResponse{SensorID: "s-1", TenantID: "t-1", Name: "n", KeyID: thumb})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.binds++
		switch f.answer {
		case "approval":
			problem(http.StatusForbidden, string(protov2.ProblemKeyBindApproval))
		case "refused":
			problem(http.StatusConflict, string(protov2.ProblemKeyBindRefused))
		case "error":
			// Applied, but the answer is lost.
			f.boundKey = thumb
			w.WriteHeader(http.StatusBadGateway)
		case "bound":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			f.boundKey = thumb
			w.Header().Set("Content-Type", protov2.MediaTypeJSON)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(protov2.KeyBindResponse{SensorID: "s-1", TenantID: "t-1", Name: "n", KeyID: thumb})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func bindKit(t *testing.T, url, stateDir string) (*Kit, *bytes.Buffer) {
	t.Helper()
	var errw bytes.Buffer
	k := &Kit{out: io.Discard, errw: &errw}
	k.s.apiURL, k.s.apiKey, k.s.stateDir, k.s.commands = url, "octs_test_key", stateDir, true
	return k, &errw
}

func stateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAutoBindKey_BindsAndPrefersTheIdentity(t *testing.T) {
	f := &fakeBindPlatform{answer: "ok", feature: true}
	srv := f.serve(t)
	dir := stateDir(t)
	k, errw := bindKit(t, srv.URL, dir)
	k.autoBindKey(client.ProtocolAuto)
	if k.s.signer == nil || k.s.apiKey != "" || k.s.sensorID != "s-1" {
		t.Fatalf("after the bind: signer %v, api key %q, sensor %q (%s)", k.s.signer != nil, k.s.apiKey, k.s.sensorID, errw)
	}
	store := identity.NewStore(dir)
	id, signer, err := store.Load()
	if err != nil || id.KeyID != signer.KeyID() || id.KeyID != f.boundKey || id.RequireLocalPolicy {
		t.Fatalf("stored identity %+v (%v)", id, err)
	}
	if store.BindPending() {
		t.Fatal("the marker must be gone once the bind is confirmed")
	}
	// Next start with SENSOR_API_KEY still configured: the identity wins, no new bind.
	k2, errw2 := bindKit(t, srv.URL, dir)
	if ok, err := k2.preferIdentity(); err != nil || !ok || k2.s.apiKey != "" || k2.s.signer == nil {
		t.Fatalf("preferIdentity: %v %v", ok, err)
	}
	if !strings.Contains(errw2.String(), "SENSOR_API_KEY is ignored") {
		t.Fatalf("operator not told to remove SENSOR_API_KEY: %s", errw2)
	}
	k2.autoBindKey(client.ProtocolAuto)
	if f.binds != 1 {
		t.Fatalf("binds %d, want 1", f.binds)
	}
}

func TestAutoBindKey_NoFeatureOrOff(t *testing.T) {
	f := &fakeBindPlatform{answer: "ok"}
	srv := f.serve(t)
	dir := stateDir(t)
	k, _ := bindKit(t, srv.URL, dir)
	k.autoBindKey(client.ProtocolAuto)
	if f.binds != 0 || k.s.signer != nil || k.s.apiKey == "" {
		t.Fatal("a platform without key_bind must not be asked")
	}
	if _, err := os.Stat(filepath.Join(dir, identity.DirName, identity.KeyFile)); err == nil {
		t.Fatal("no key may be generated without the feature")
	}
	f.feature = true
	t.Setenv(EnvKeyBind, "off")
	k.autoBindKey(client.ProtocolAuto)
	if f.binds != 0 {
		t.Fatal("SENSOR_KEY_BIND=off must not bind")
	}
	t.Setenv(EnvKeyBind, "maybe")
	if _, err := keyBindEnabled(); err == nil {
		t.Fatal("an unknown SENSOR_KEY_BIND must be refused")
	}
}

func TestAutoBindKey_RefusalKeepsTheAPIKey(t *testing.T) {
	for _, answer := range []string{"approval", "refused"} {
		f := &fakeBindPlatform{answer: answer, feature: true}
		srv := f.serve(t)
		dir := stateDir(t)
		k, errw := bindKit(t, srv.URL, dir)
		k.autoBindKey(client.ProtocolAuto)
		if k.s.signer != nil || k.s.apiKey == "" {
			t.Fatalf("%s: the sensor must keep its API key", answer)
		}
		store := identity.NewStore(dir)
		if store.BindPending() {
			t.Fatalf("%s: marker left behind", answer)
		}
		if _, err := os.Stat(filepath.Join(dir, identity.DirName, identity.KeyFile)); err == nil {
			t.Fatalf("%s: the refused key must be removed", answer)
		}
		if answer == "approval" && !strings.Contains(errw.String(), "pair -repair") {
			t.Fatalf("approval refusal must name the re-pair: %s", errw)
		}
	}
}

func TestAutoBindKey_LostAnswerIsConfirmedAtTheNextStart(t *testing.T) {
	f := &fakeBindPlatform{answer: "error", feature: true}
	srv := f.serve(t)
	dir := stateDir(t)
	k, _ := bindKit(t, srv.URL, dir)
	k.autoBindKey(client.ProtocolAuto)
	store := identity.NewStore(dir)
	if k.s.signer != nil || k.s.apiKey == "" || !store.BindPending() {
		t.Fatal("a lost answer keeps the API key and the marker for the next start")
	}
	firstKey, err := store.LoadKey()
	if err != nil {
		t.Fatal(err)
	}
	// Next start: the API key is retired now; the same key confirms.
	f.answer = "bound"
	k2, errw := bindKit(t, srv.URL, dir)
	k2.autoBindKey(client.ProtocolAuto)
	if k2.s.signer == nil || k2.s.signer.KeyID() != firstKey.KeyID() || f.signed != 1 || store.BindPending() {
		t.Fatalf("confirmation: signer %v, signed calls %d, pending %v (%s)", k2.s.signer != nil, f.signed, store.BindPending(), errw)
	}
	if _, _, err := store.Load(); err != nil {
		t.Fatalf("identity after the confirmation: %v", err)
	}
}
