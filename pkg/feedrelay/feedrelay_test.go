package feedrelay_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/feedrelay"
	"github.com/openctemio/sdk-go/pkg/jobsig"
)

const (
	sensorID = "bbbbbbbb-0000-4000-8000-000000000002"
	roundID  = "cccccccc-0000-4000-8000-000000000003"
)

// fakePlatform serves one round and records uploads and the report.
type fakePlatform struct {
	mu      sync.Mutex
	round   *feedrelay.Round
	uploads map[string][]byte
	report  *feedrelay.Report
}

func (p *fakePlatform) NextFeedRelay(context.Context) (*feedrelay.Round, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.round
	p.round = nil
	return r, nil
}

func (p *fakePlatform) UploadFeedRelayFile(_ context.Context, id, name string, body io.Reader, size int64, sum string) error {
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if id != roundID || int64(len(b)) != size || hex.EncodeToString(h[:]) != sum {
		panic("upload does not match its declared size or digest")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.uploads == nil {
		p.uploads = map[string][]byte{}
	}
	p.uploads[name] = b
	return nil
}

func (p *fakePlatform) FeedRelayDone(_ context.Context, _ string, rep feedrelay.Report) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.report = &rep
	return nil
}

type signer struct {
	priv  ed25519.PrivateKey
	seq   uint64
	guard *core.JobGuard
}

func newSigner(t *testing.T, shared bool) *signer {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys, err := jobsig.NewKeys(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	v, err := jobsig.NewVerifier(jobsig.Config{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	s := &signer{priv: priv}
	if shared {
		s.guard, err = core.NewSharedJobGuard(v, sensorID)
	} else {
		s.guard, err = core.NewJobGuard(v, true, "aaaaaaaa-0000-4000-8000-000000000001", sensorID)
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// round signs payload the way the platform's job signer does; edit may
// change the statement before it is signed.
func (s *signer) round(t *testing.T, payload feedrelay.Payload, edit func(st *jobsig.Statement)) *feedrelay.Round {
	t.Helper()
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	s.seq++
	nonce := make([]byte, jobsig.NonceBytes)
	nonce[0] = byte(s.seq)
	now := time.Now()
	st := jobsig.Statement{Kind: jobsig.Kind, TenantID: jobsig.PlatformTenantID, SensorID: sensorID,
		SensorScope: jobsig.SensorScopeInstance, CommandID: roundID, CommandType: jobsig.CommandTypeFeedRelay,
		Tool: "", PayloadSHA256: jobsig.PayloadDigest(pb), Targets: jobsig.PayloadTargets(pb),
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(30 * time.Minute), Seq: s.seq,
		Nonce:  base64.RawURLEncoding.EncodeToString(nonce),
		Signer: &jobsig.SignerRef{KeyID: jobsig.KeyID(s.priv.Public().(ed25519.PublicKey))}}
	if edit != nil {
		edit(&st)
	}
	sp, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(jobsig.Envelope{PayloadType: jobsig.PayloadType, Payload: sp,
		Signatures: []jobsig.Signature{{KeyID: st.Signer.KeyID, Sig: ed25519.Sign(s.priv, jobsig.PreAuthEncoding(jobsig.PayloadType, sp))}}})
	if err != nil {
		t.Fatal(err)
	}
	return &feedrelay.Round{ID: roundID, Payload: pb, SignedJob: env}
}

// origin serves files; hits counts requests.
type origin struct {
	srv   *httptest.Server
	files map[string]string
	mu    sync.Mutex
	hits  int
}

func newOrigin(t *testing.T, files map[string]string) *origin {
	t.Helper()
	o := &origin{files: files}
	o.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.hits++
		o.mu.Unlock()
		b, ok := o.files[strings.TrimPrefix(r.URL.Path, "/feed/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, b)
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *origin) url() string { return o.srv.URL + "/feed" }

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func newRelay(t *testing.T, p *fakePlatform, s *signer, client *http.Client, origins ...string) *feedrelay.Relay {
	t.Helper()
	r, err := feedrelay.New(feedrelay.Config{Platform: p, Verifier: s.guard, Origins: origins, HTTP: client, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRelayDeliversFilesFromAllowedOrigins(t *testing.T) {
	a := newOrigin(t, map[string]string{"keyset.dsse.json": "K"})
	b := newOrigin(t, map[string]string{"keyset.dsse.json": "K", "sha256-x.jsonl.gz": "CHUNK"})
	s := newSigner(t, true)
	p := &fakePlatform{round: s.round(t, feedrelay.Payload{Feed: "vulnfeed", Targets: []string{a.url(), b.url()}, Files: []feedrelay.File{
		{Name: "keyset.dsse.json", MaxBytes: 1024},
		{Name: "sha256-x.jsonl.gz", SHA256: sum("CHUNK"), Size: 5, MaxBytes: 1024},
	}}, nil)}
	r := newRelay(t, p, s, a.srv.Client(), a.url(), b.url())
	served, err := r.RunOnce(context.Background())
	if err != nil || !served {
		t.Fatalf("served %v err %v", served, err)
	}
	if string(p.uploads["keyset.dsse.json"]) != "K" || string(p.uploads["sha256-x.jsonl.gz"]) != "CHUNK" {
		t.Fatalf("uploads %v", p.uploads)
	}
	for _, o := range p.report.Files {
		if o.Status != feedrelay.StatusOK {
			t.Fatalf("outcome %+v", o)
		}
	}
}

// SECURITY: a payload changed after signing (here: an origin swapped) is
// refused before anything is downloaded.
func TestRelayRefusesTamperedRound(t *testing.T) {
	a := newOrigin(t, map[string]string{"keyset.dsse.json": "K"})
	evil := newOrigin(t, map[string]string{"keyset.dsse.json": "EVIL"})
	s := newSigner(t, true)
	round := s.round(t, feedrelay.Payload{Feed: "vulnfeed", Targets: []string{a.url()}, Files: []feedrelay.File{{Name: "keyset.dsse.json", MaxBytes: 64}}}, nil)
	round.Payload = []byte(strings.Replace(string(round.Payload), a.url(), evil.url(), 1))
	p := &fakePlatform{round: round}
	r := newRelay(t, p, s, a.srv.Client(), a.url(), evil.url())
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.report == nil || !strings.HasPrefix(p.report.Refused, "signature_") || len(p.uploads) != 0 || evil.hits+a.hits != 0 {
		t.Fatalf("report %+v uploads %v hits %d/%d", p.report, p.uploads, a.hits, evil.hits)
	}
}

// SECURITY: a correctly signed round naming an origin outside the sensor's
// own allowlist is refused (a compromised platform and signer allowlist
// still cannot point the relay elsewhere).
func TestRelayRefusesOriginOutsideLocalAllowlist(t *testing.T) {
	a := newOrigin(t, map[string]string{"x.json": "X"})
	other := newOrigin(t, map[string]string{"x.json": "X"})
	s := newSigner(t, true)
	p := &fakePlatform{round: s.round(t, feedrelay.Payload{Feed: "vulnfeed", Targets: []string{other.url()}, Files: []feedrelay.File{{Name: "x.json", MaxBytes: 64}}}, nil)}
	r := newRelay(t, p, s, a.srv.Client(), a.url())
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.report == nil || p.report.Refused == "" || other.hits != 0 || len(p.uploads) != 0 {
		t.Fatalf("report %+v hits %d", p.report, other.hits)
	}
}

// SECURITY: an organization's sensor never relays, even a validly signed
// round.
func TestRelayRefusedOnOrganizationSensor(t *testing.T) {
	a := newOrigin(t, map[string]string{"x.json": "X"})
	s := newSigner(t, false)
	p := &fakePlatform{round: s.round(t, feedrelay.Payload{Feed: "vulnfeed", Targets: []string{a.url()}, Files: []feedrelay.File{{Name: "x.json", MaxBytes: 64}}}, nil)}
	r := newRelay(t, p, s, a.srv.Client(), a.url())
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.report == nil || p.report.Refused == "" || a.hits != 0 {
		t.Fatalf("report %+v hits %d", p.report, a.hits)
	}
}

// SECURITY: a round signed for an organization (not the platform) is
// refused by a shared sensor.
func TestRelayRefusesOrganizationStatement(t *testing.T) {
	a := newOrigin(t, map[string]string{"x.json": "X"})
	s := newSigner(t, true)
	p := &fakePlatform{round: s.round(t, feedrelay.Payload{Feed: "vulnfeed", Targets: []string{a.url()}, Files: []feedrelay.File{{Name: "x.json", MaxBytes: 64}}},
		func(st *jobsig.Statement) { st.TenantID = "aaaaaaaa-0000-4000-8000-000000000001" })}
	r := newRelay(t, p, s, a.srv.Client(), a.url())
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.report == nil || p.report.Refused != "signature_"+jobsig.ReasonTenant || a.hits != 0 {
		t.Fatalf("report %+v hits %d", p.report, a.hits)
	}
}

// A pinned file whose bytes differ is never uploaded; a file over its cap
// is refused; a missing file is reported not found.
func TestRelayPinsAndCaps(t *testing.T) {
	a := newOrigin(t, map[string]string{"sha256-a.jsonl.gz": "TAMPERED", "big.json": strings.Repeat("x", 100)})
	s := newSigner(t, true)
	p := &fakePlatform{round: s.round(t, feedrelay.Payload{Feed: "vulnfeed", Targets: []string{a.url()}, Files: []feedrelay.File{
		{Name: "sha256-a.jsonl.gz", SHA256: sum("ORIGINAL"), Size: 8, MaxBytes: 64},
		{Name: "big.json", MaxBytes: 10},
		{Name: "gone.json", MaxBytes: 10},
	}}, nil)}
	r := newRelay(t, p, s, a.srv.Client(), a.url())
	if _, err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(p.uploads) != 0 {
		t.Fatalf("uploaded %v", p.uploads)
	}
	want := map[string]string{"sha256-a.jsonl.gz": "refused_pin_mismatch", "big.json": "refused_too_large", "gone.json": "not_found"}
	for _, o := range p.report.Files {
		if o.Code != want[o.Name] {
			t.Fatalf("%s: code %q, want %q", o.Name, o.Code, want[o.Name])
		}
	}
}

// File names are single path segments: a traversal refuses the round.
func TestRelayRefusesBadNames(t *testing.T) {
	a := newOrigin(t, nil)
	s := newSigner(t, true)
	for _, name := range []string{"../etc/passwd", "a/b", ".hidden", "", strings.Repeat("a", 200)} {
		p := &fakePlatform{round: s.round(t, feedrelay.Payload{Feed: "vulnfeed", Targets: []string{a.url()}, Files: []feedrelay.File{{Name: name, MaxBytes: 10}}}, nil)}
		r := newRelay(t, p, s, a.srv.Client(), a.url())
		if _, err := r.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if p.report == nil || p.report.Refused == "" {
			t.Fatalf("name %q: report %+v", name, p.report)
		}
	}
	if a.hits != 0 {
		t.Fatalf("%d downloads", a.hits)
	}
}

func TestParseOrigins(t *testing.T) {
	o, err := feedrelay.ParseOrigins(" https://Mirror.Example.com/feeds/ ")
	if err != nil || o[len(o)-1] != "https://mirror.example.com/feeds" || len(o) != len(feedrelay.DefaultOrigins)+1 {
		t.Fatalf("%v %v", o, err)
	}
	for _, bad := range []string{"http://x.example", "https://u:p@x.example", "https://x.example/?q=1", "https://x.example/a/../b"} {
		if _, err := feedrelay.ParseOrigins(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
