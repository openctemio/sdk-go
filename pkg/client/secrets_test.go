package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/secretref"

	"github.com/openctemio/sdk-go/pkg/sealedmsg"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

const (
	secSensor = "0193a3f2-0000-7000-8000-000000000001"
	secCmd    = "0193a3f2-0000-7000-8000-000000000002"
	secKey    = "shodan-key-0123456789"
)

func secretsSet() secretref.Set {
	return secretref.Set{V: 1, Local: secretref.LocalNever, Refs: []secretref.Ref{
		{ID: "k1", Kind: secretref.KindProviderKey, Class: secretref.ClassProvider, Ref: "shodan", Slot: "shodan",
			Audience: []string{"provider:shodan"}, Consumer: secretref.ConsumerTool, Local: secretref.LocalNever},
		{ID: "k2", Kind: secretref.KindProviderKey, Class: secretref.ClassProvider, Ref: "virustotal", Slot: "virustotal",
			Audience: []string{"provider:virustotal"}, Consumer: secretref.ConsumerTool, Local: secretref.LocalNever},
	}}
}

// secretsPlatform is a platform answering the secrets route the way the
// spec fixes it; tamper changes what it does.
type secretsPlatform struct {
	pub     ed25519.PublicKey
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
	// tamper adjusts the answer (nil: a correct one).
	tamper func(req secretref.FetchRequest, ans *secretref.Answer, sensorID *string, contentType *string, replyKey *[]byte)
	status int
	// problem: answer status with a problem document (else a plain body).
	problem bool
}

func (p *secretsPlatform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	p.mu.Lock()
	p.bodies = append(p.bodies, body)
	p.headers = append(p.headers, r.Header.Clone())
	p.mu.Unlock()
	if r.URL.Path != protov2.PathPrefix+"/commands/"+secCmd+"/secrets" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if pp, err := sensorsig.Parse(r.Header); err != nil || pp.Verify(r, p.pub) != nil ||
		sensorsig.VerifyContentDigest(r.Header.Get(sensorsig.HeaderContentDigest), body) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if p.status != 0 {
		if p.problem {
			w.Header().Set("Content-Type", protov2.MediaTypeProblem)
			w.WriteHeader(p.status)
			_, _ = w.Write([]byte(`{"type":"about:blank","title":"Not Found","status":404,"code":"command_not_found"}`))
			return
		}
		w.WriteHeader(p.status)
		_, _ = w.Write([]byte("404 page not found"))
		return
	}
	var req secretref.FetchRequest
	if json.Unmarshal(body, &req) != nil || req.Validate() != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reply, _ := req.ReplyKeyBytes()
	ans := secretref.Answer{CommandID: secCmd, LeaseEpoch: req.LeaseEpoch, IssuedAt: time.Now().UTC()}
	for _, id := range req.Refs {
		if id == "k1" {
			ans.Secrets = append(ans.Secrets, secretref.Secret{ID: id, Kind: secretref.KindProviderKey,
				Value: json.RawMessage(`{"key":"` + secKey + `"}`), Provenance: secretref.ProvenanceTenant})
		} else {
			ans.Missing = append(ans.Missing, secretref.Missing{ID: id, Reason: secretref.MissingNotSet})
		}
	}
	sensorID, ct := secSensor, secretref.ContentType
	if p.tamper != nil {
		p.tamper(req, &ans, &sensorID, &ct, &reply)
	}
	pt, _ := json.Marshal(ans)
	sealed, err := sealedmsg.SealToKey(reply, secretref.Info(sensorID, secCmd, req.LeaseEpoch, body), pt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(secretref.SealedAnswer{Suite: secretref.SuiteHybridV1, KeyID: secretref.KeyID(reply),
		Sealed: base64.RawURLEncoding.EncodeToString(sealed)})
}

func secretsClient(t *testing.T, p *secretsPlatform, signed bool) *Client {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p.pub = pub
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	cfg := &Config{BaseURL: srv.URL, APIKey: "octs_bearer", SensorID: secSensor, MaxRetries: 0, RetryDelay: time.Millisecond, Timeout: 5 * time.Second}
	if signed {
		signer, err := sensorsig.NewSigner(priv)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Signer = signer
	}
	c := New(cfg)
	c.leases.record(secCmd, 3)
	return c
}

// The fetch: a signed request whose body (sent once, exactly as bound)
// carries the lease epoch and a fresh reply key; the sealed answer opens
// with that key and is checked against the job's list.
func TestSecretsFetch(t *testing.T) {
	p := &secretsPlatform{}
	c := secretsClient(t, p, true)
	ans, err := c.Secrets(context.Background(), secCmd, "chunk-1", secretsSet(), []string{"k1", "k2"})
	if err != nil {
		t.Fatal(err)
	}
	var key secretref.ProviderKey
	if len(ans.Secrets) != 1 || json.Unmarshal(ans.Secrets[0].Value, &key) != nil || key.Key != secKey ||
		len(ans.Missing) != 1 || ans.Missing[0].ID != "k2" {
		t.Fatalf("answer %+v", ans)
	}
	var req secretref.FetchRequest
	if err := json.Unmarshal(p.bodies[0], &req); err != nil || req.LeaseEpoch != 3 || req.Task != "chunk-1" {
		t.Fatalf("request %s", p.bodies[0])
	}
	if p.headers[0].Get("Authorization") != "" {
		t.Fatal("a bearer key was sent")
	}
	// A new reply key for every request.
	if _, err := c.Secrets(context.Background(), secCmd, "chunk-2", secretsSet(), []string{"k1"}); err != nil {
		t.Fatal(err)
	}
	var req2 secretref.FetchRequest
	_ = json.Unmarshal(p.bodies[1], &req2)
	if req2.ReplyKey == req.ReplyKey {
		t.Fatal("a reply key was used twice")
	}
	if strings.Contains(string(p.bodies[0])+string(p.bodies[1]), secKey) {
		t.Fatal("a value traveled in a request")
	}
}

// SECURITY: a client without a key-bound identity never asks (a reply key
// in a bearer-authenticated body would not be bound to the sensor).
func TestSecretsRefusedWithoutKeyBinding(t *testing.T) {
	p := &secretsPlatform{}
	c := secretsClient(t, p, false)
	if _, err := c.Secrets(context.Background(), secCmd, "t", secretsSet(), []string{"k1"}); !errors.Is(err, ErrSecretsNotKeyBound) {
		t.Fatalf("bearer client: %v", err)
	}
	if len(p.bodies) != 0 {
		t.Fatal("a bearer client sent a request")
	}
}

// SECURITY: every failure is an error, never an empty answer the caller
// could take for "no value, use another source": a refusal, a 404 without
// a problem document (a gateway or a platform without the route), no
// lease, an answer that is not a sealed one, sealed to another key or under
// another sensor's info, for another command or epoch, or holding a value
// that was not asked for.
func TestSecretsFailuresAreErrors(t *testing.T) {
	cases := []struct {
		name string
		p    *secretsPlatform
		cmd  string
	}{
		{"command_not_found", &secretsPlatform{status: http.StatusNotFound, problem: true}, secCmd},
		{"gateway 404 without a problem document", &secretsPlatform{status: http.StatusNotFound}, secCmd},
		{"405 without a problem document", &secretsPlatform{status: http.StatusMethodNotAllowed}, secCmd},
		{"no lease", &secretsPlatform{}, "0193a3f2-0000-7000-8000-000000000009"},
		{"plain JSON content type", &secretsPlatform{tamper: func(_ secretref.FetchRequest, _ *secretref.Answer, _ *string, ct *string, _ *[]byte) {
			*ct = "application/json"
		}}, secCmd},
		{"sealed to another key", &secretsPlatform{tamper: func(_ secretref.FetchRequest, _ *secretref.Answer, _ *string, _ *string, k *[]byte) {
			other, _ := sealedmsg.GenerateKey()
			*k = other.Public().Bytes()
		}}, secCmd},
		{"another sensor's info", &secretsPlatform{tamper: func(_ secretref.FetchRequest, _ *secretref.Answer, s *string, _ *string, _ *[]byte) {
			*s = "0193a3f2-0000-7000-8000-0000000000ff"
		}}, secCmd},
		{"another command", &secretsPlatform{tamper: func(_ secretref.FetchRequest, a *secretref.Answer, _ *string, _ *string, _ *[]byte) {
			a.CommandID = "0193a3f2-0000-7000-8000-0000000000ee"
		}}, secCmd},
		{"another epoch", &secretsPlatform{tamper: func(_ secretref.FetchRequest, a *secretref.Answer, _ *string, _ *string, _ *[]byte) {
			a.LeaseEpoch = 2
		}}, secCmd},
		{"a value not asked for", &secretsPlatform{tamper: func(_ secretref.FetchRequest, a *secretref.Answer, _ *string, _ *string, _ *[]byte) {
			a.Secrets = append(a.Secrets, secretref.Secret{ID: "k2", Kind: secretref.KindProviderKey,
				Value: json.RawMessage(`{"key":"other-key-0123456789"}`), Provenance: secretref.ProvenanceTenant})
		}}, secCmd},
		{"a stale answer", &secretsPlatform{tamper: func(_ secretref.FetchRequest, a *secretref.Answer, _ *string, _ *string, _ *[]byte) {
			a.IssuedAt = time.Now().Add(-time.Hour)
		}}, secCmd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := secretsClient(t, tc.p, true)
			ans, err := c.Secrets(context.Background(), tc.cmd, "t", secretsSet(), []string{"k1"})
			if err == nil || ans != nil {
				t.Fatalf("answer %+v, err %v", ans, err)
			}
			if strings.Contains(err.Error(), secKey) {
				t.Fatal("the error repeats a value")
			}
		})
	}
	// A ref the job does not list is never asked for.
	p := &secretsPlatform{}
	c := secretsClient(t, p, true)
	if _, err := c.Secrets(context.Background(), secCmd, "t", secretsSet(), []string{"k9"}); err == nil || len(p.bodies) != 0 {
		t.Fatalf("a ref outside the list: %v (%d requests)", err, len(p.bodies))
	}
}
