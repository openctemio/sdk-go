package jobsig

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// vector is api pkg/jobsign/testdata/vector.json (openctemio/openctem): the
// platform signer's test vector, copied byte for byte.
type vector struct {
	Seed           []byte          `json:"seed"`
	KeyID          string          `json:"keyid"`
	PublicKey      string          `json:"public_key"`
	Payload        string          `json:"payload"`
	CommandPayload string          `json:"command_payload"`
	Envelope       json.RawMessage `json:"envelope"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

var vectorNow = time.Date(2026, 10, 9, 10, 0, 30, 0, time.UTC)

func vectorBinding(v vector) Binding {
	return Binding{
		TenantID:    "11111111-1111-4111-8111-111111111111",
		SensorID:    "22222222-2222-4222-8222-22222222abcd",
		CommandID:   "33333333-3333-4333-8333-333333333333",
		CommandType: "scan",
		LeaseEpoch:  2,
		Payload:     []byte(v.CommandPayload),
	}
}

func vectorVerifier(t *testing.T, v vector, stateFile string) *Verifier {
	t.Helper()
	keys, err := ParseKeys(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := NewVerifier(Config{Keys: keys, StateFile: stateFile, Now: func() time.Time { return vectorNow }})
	if err != nil {
		t.Fatal(err)
	}
	return ver
}

func TestGoldenVectorVerifies(t *testing.T) {
	v := loadVector(t)
	priv := ed25519.NewKeyFromSeed(v.Seed)
	if got := KeyID(priv.Public().(ed25519.PublicKey)); got != v.KeyID {
		t.Fatalf("KeyID = %s, vector %s", got, v.KeyID)
	}
	ver := vectorVerifier(t, v, "")
	st, err := ver.Verify(context.Background(), v.Envelope, vectorBinding(v))
	if err != nil {
		t.Fatalf("golden vector refused: %v", err)
	}
	if st.Seq != 18 || st.Tool != "nuclei" || len(st.Targets) != 2 || st.Signer.KeyID != v.KeyID {
		t.Fatalf("statement = %+v", st)
	}
}

func TestGoldenVectorRefusedOnceAByteChanges(t *testing.T) {
	v := loadVector(t)
	// A command payload byte changed: the digest no longer matches.
	b := vectorBinding(v)
	b.Payload = []byte(strings.Replace(v.CommandPayload, "203.0.113.10", "203.0.113.11", 1))
	if _, err := vectorVerifier(t, v, "").Verify(context.Background(), v.Envelope, b); ReasonOf(err) != ReasonPayloadDigest {
		t.Fatalf("changed command payload: err = %v, want %s", err, ReasonPayloadDigest)
	}
	// A statement byte changed: the signature no longer verifies.
	var env Envelope
	if err := json.Unmarshal(v.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = []byte(strings.Replace(string(env.Payload), `"seq":18`, `"seq":19`, 1))
	raw, _ := json.Marshal(env)
	if _, err := vectorVerifier(t, v, "").Verify(context.Background(), raw, vectorBinding(v)); ReasonOf(err) != ReasonBadSignature {
		t.Fatalf("changed statement: err = %v, want %s", err, ReasonBadSignature)
	}
}

// fixture signs statements the way the platform's signer does.
type fixture struct {
	priv ed25519.PrivateKey
	ver  *Verifier
	now  time.Time
	b    Binding
}

func newFixture(t *testing.T, stateFile string) *fixture {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys, _ := NewKeys(priv.Public().(ed25519.PublicKey))
	f := &fixture{priv: priv, now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	ver, err := NewVerifier(Config{Keys: keys, StateFile: stateFile, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	f.ver = ver
	f.b = Binding{TenantID: "aaaaaaaa-0000-4000-8000-000000000001", SensorID: "bbbbbbbb-0000-4000-8000-000000000002",
		CommandID: "cccccccc-0000-4000-8000-000000000003", CommandType: "scan", LeaseEpoch: 1,
		Payload: []byte(`{"scanner":"nuclei","targets":["a.example.com"," b.example.com","a.example.com"],"target":"c.example.com"}`)}
	return f
}

var nonceN byte

func (f *fixture) statement() Statement {
	nonceN++
	n := make([]byte, NonceBytes)
	n[0] = nonceN
	return Statement{Kind: Kind, TenantID: f.b.TenantID, SensorID: f.b.SensorID, CommandID: f.b.CommandID,
		CommandType: f.b.CommandType, Tool: "nuclei", PayloadSHA256: PayloadDigest(f.b.Payload),
		Targets: []string{"a.example.com", "b.example.com", "c.example.com"}, LeaseEpoch: f.b.LeaseEpoch,
		IssuedAt: f.now.Add(-10 * time.Second), ExpiresAt: f.now.Add(50 * time.Minute), Seq: uint64(nonceN),
		Nonce: base64.RawURLEncoding.EncodeToString(n), Signer: &SignerRef{KeyID: KeyID(f.priv.Public().(ed25519.PublicKey))}}
}

func sign(t *testing.T, priv ed25519.PrivateKey, keyID string, payload []byte) []byte {
	t.Helper()
	env := Envelope{PayloadType: PayloadType, Payload: payload,
		Signatures: []Signature{{KeyID: keyID, Sig: ed25519.Sign(priv, PreAuthEncoding(PayloadType, payload))}}}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) envelope(t *testing.T, st Statement) []byte {
	t.Helper()
	p, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return sign(t, f.priv, KeyID(f.priv.Public().(ed25519.PublicKey)), p)
}

func TestVerifyAcceptsAndRefusesEachTamper(t *testing.T) {
	other := ed25519.NewKeyFromSeed(bytesOf(7))
	cases := []struct {
		name   string
		mutate func(f *fixture, st *Statement, b *Binding) []byte // nil: sign st normally
		reason string
	}{
		{"valid", nil, ""},
		{"kind", func(_ *fixture, st *Statement, _ *Binding) []byte { st.Kind = "openctem.job/v2"; return nil }, ReasonKind},
		{"tenant", func(_ *fixture, st *Statement, _ *Binding) []byte {
			st.TenantID = "aaaaaaaa-0000-4000-8000-0000000000ff"
			return nil
		}, ReasonTenant},
		{"sensor", func(_ *fixture, st *Statement, _ *Binding) []byte {
			st.SensorID = "bbbbbbbb-0000-4000-8000-0000000000ff"
			return nil
		}, ReasonSensor},
		{"command", func(_ *fixture, _ *Statement, b *Binding) []byte {
			b.CommandID = "cccccccc-0000-4000-8000-0000000000ff"
			return nil
		}, ReasonCommand},
		{"command type", func(_ *fixture, _ *Statement, b *Binding) []byte { b.CommandType = "collect"; return nil }, ReasonCommandType},
		{"expired", func(f *fixture, st *Statement, _ *Binding) []byte {
			st.ExpiresAt = f.now.Add(-time.Second)
			st.IssuedAt = f.now.Add(-time.Minute)
			return nil
		}, ReasonExpired},
		{"ttl over an hour", func(f *fixture, st *Statement, _ *Binding) []byte {
			st.ExpiresAt = st.IssuedAt.Add(MaxTTL + time.Second)
			return nil
		}, ReasonExpired},
		{"issued in the future", func(f *fixture, st *Statement, _ *Binding) []byte {
			st.IssuedAt = f.now.Add(3 * time.Minute)
			return nil
		}, ReasonClockSkew},
		{"issued long ago", func(f *fixture, st *Statement, _ *Binding) []byte {
			st.IssuedAt = f.now.Add(-3 * time.Minute)
			return nil
		}, ReasonClockSkew},
		{"lease epoch", func(_ *fixture, _ *Statement, b *Binding) []byte { b.LeaseEpoch = 2; return nil }, ReasonLeaseEpoch},
		{"payload digest", func(_ *fixture, _ *Statement, b *Binding) []byte {
			b.Payload = []byte(`{"scanner":"nuclei","targets":["a.example.com"," b.example.com","a.example.com"],"target":"d.example.com"}`)
			return nil
		}, ReasonPayloadDigest},
		{"re-encoded payload", func(_ *fixture, _ *Statement, b *Binding) []byte {
			var m map[string]any
			_ = json.Unmarshal(b.Payload, &m)
			b.Payload, _ = json.MarshalIndent(m, "", " ")
			return nil
		}, ReasonPayloadDigest},
		{"tool", func(_ *fixture, st *Statement, _ *Binding) []byte { st.Tool = "naabu"; return nil }, ReasonTool},
		{"targets", func(_ *fixture, st *Statement, _ *Binding) []byte { st.Targets = st.Targets[:2]; return nil }, ReasonTargets},
		{"nonce", func(_ *fixture, st *Statement, _ *Binding) []byte { st.Nonce = "short"; return nil }, ReasonNonce},
		{"signer field", func(_ *fixture, st *Statement, _ *Binding) []byte {
			st.Signer = &SignerRef{KeyID: KeyID(other.Public().(ed25519.PublicKey))}
			return nil
		}, ReasonSigner},
		{"untrusted key", func(t2 *fixture, st *Statement, _ *Binding) []byte {
			p, _ := json.Marshal(st)
			return signRaw(other, KeyID(other.Public().(ed25519.PublicKey)), p)
		}, ReasonUntrustedKey},
		{"keyid of the pinned key, signature of another", func(f *fixture, st *Statement, _ *Binding) []byte {
			p, _ := json.Marshal(st)
			return signRaw(other, KeyID(f.priv.Public().(ed25519.PublicKey)), p)
		}, ReasonBadSignature},
		{"signature", func(f *fixture, st *Statement, _ *Binding) []byte {
			p, _ := json.Marshal(st)
			raw := signRaw(f.priv, KeyID(f.priv.Public().(ed25519.PublicKey)), p)
			var env Envelope
			_ = json.Unmarshal(raw, &env)
			env.Signatures[0].Sig[0] ^= 1
			out, _ := json.Marshal(env)
			return out
		}, ReasonBadSignature},
		{"payload type", func(f *fixture, st *Statement, _ *Binding) []byte {
			p, _ := json.Marshal(st)
			env := Envelope{PayloadType: "application/vnd.openctem.template-manifest+json", Payload: p,
				Signatures: []Signature{{KeyID: KeyID(f.priv.Public().(ed25519.PublicKey)),
					Sig: ed25519.Sign(f.priv, PreAuthEncoding("application/vnd.openctem.template-manifest+json", p))}}}
			out, _ := json.Marshal(env)
			return out
		}, ReasonPayloadType},
		{"unknown statement field", func(f *fixture, st *Statement, _ *Binding) []byte {
			p, _ := json.Marshal(st)
			p = append(p[:len(p)-1], []byte(`,"scope":"*"}`)...)
			return signRaw(f.priv, KeyID(f.priv.Public().(ed25519.PublicKey)), p)
		}, ReasonMalformed},
		{"unsigned", func(*fixture, *Statement, *Binding) []byte { return []byte(`{}`) }, ReasonPayloadType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			st := f.statement()
			b := f.b
			var env []byte
			if tc.mutate != nil {
				env = tc.mutate(f, &st, &b)
			}
			if env == nil {
				env = f.envelope(t, st)
			}
			_, err := f.ver.Verify(context.Background(), env, b)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("valid job refused: %v", err)
				}
				return
			}
			if got := ReasonOf(err); got != tc.reason {
				t.Fatalf("err = %v (reason %q), want reason %q", err, got, tc.reason)
			}
			// A refused job leaves no trace: the same sequence number is
			// still accepted once the job is right.
			if f.ver.LastSeq(KeyID(f.priv.Public().(ed25519.PublicKey))) != 0 {
				t.Fatal("a refused job advanced the sequence number")
			}
		})
	}
}

func bytesOf(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func signRaw(priv ed25519.PrivateKey, keyID string, payload []byte) []byte {
	env := Envelope{PayloadType: PayloadType, Payload: payload,
		Signatures: []Signature{{KeyID: keyID, Sig: ed25519.Sign(priv, PreAuthEncoding(PayloadType, payload))}}}
	b, _ := json.Marshal(env)
	return b
}

func TestReplayRefused(t *testing.T) {
	f := newFixture(t, "")
	st := f.statement()
	env := f.envelope(t, st)
	if _, err := f.ver.Verify(context.Background(), env, f.b); err != nil {
		t.Fatal(err)
	}
	// The same envelope again.
	if _, err := f.ver.Verify(context.Background(), env, f.b); ReasonOf(err) != ReasonReplay {
		t.Fatalf("replayed envelope: err = %v", err)
	}
	// A new sequence number with a used nonce.
	st2 := f.statement()
	st2.Nonce = st.Nonce
	if _, err := f.ver.Verify(context.Background(), f.envelope(t, st2), f.b); ReasonOf(err) != ReasonReplay || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("reused nonce: err = %v", err)
	}
	// A new nonce with a sequence number not above the last accepted.
	st3 := f.statement()
	st3.Seq = st.Seq
	if _, err := f.ver.Verify(context.Background(), f.envelope(t, st3), f.b); ReasonOf(err) != ReasonReplay || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("equal seq: err = %v", err)
	}
	st4 := f.statement()
	st4.Seq = st.Seq - 1
	if _, err := f.ver.Verify(context.Background(), f.envelope(t, st4), f.b); ReasonOf(err) != ReasonReplay {
		t.Fatalf("lower seq: err = %v", err)
	}
	// Gaps are allowed.
	st5 := f.statement()
	st5.Seq = st.Seq + 100
	if _, err := f.ver.Verify(context.Background(), f.envelope(t, st5), f.b); err != nil {
		t.Fatalf("seq with a gap refused: %v", err)
	}
}

func TestSeqSurvivesRestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state", "job-seq.json")
	f := newFixture(t, file)
	st := f.statement()
	st.Seq = 40
	env := f.envelope(t, st)
	if _, err := f.ver.Verify(context.Background(), env, f.b); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v", fi.Mode().Perm())
	}

	// A restarted sensor (new verifier, empty nonce memory) still refuses
	// the old envelope and anything not above seq 40.
	g := newFixture(t, file)
	if _, err := g.ver.Verify(context.Background(), env, g.b); ReasonOf(err) != ReasonReplay {
		t.Fatalf("replay after restart: err = %v", err)
	}
	st2 := g.statement()
	st2.Seq = 39
	if _, err := g.ver.Verify(context.Background(), g.envelope(t, st2), g.b); ReasonOf(err) != ReasonReplay {
		t.Fatalf("lower seq after restart: err = %v", err)
	}
	st3 := g.statement()
	st3.Seq = 41
	if _, err := g.ver.Verify(context.Background(), g.envelope(t, st3), g.b); err != nil {
		t.Fatalf("next seq after restart refused: %v", err)
	}

	// A corrupt state file stops the sensor rather than starting over.
	if err := os.WriteFile(file, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, _ := NewKeys(f.priv.Public().(ed25519.PublicKey))
	if _, err := NewVerifier(Config{Keys: keys, StateFile: file}); err == nil {
		t.Fatal("corrupt state file accepted")
	}
}

func TestKeyPinnedByIDResolvedFromHello(t *testing.T) {
	v := loadVector(t)
	pub := ed25519.NewKeyFromSeed(v.Seed).Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(bytesOf(9)).Public().(ed25519.PublicKey)
	keys, err := ParseKeys(" " + strings.ToUpper(v.KeyID[:7]) + v.KeyID[7:] + " ")
	if err != nil {
		t.Fatal(err)
	}
	if got := keys.IDs(); len(got) != 1 || got[0] != v.KeyID {
		t.Fatalf("IDs = %v", got)
	}
	// The hello lists another key under the pinned id: never trusted.
	forged := NewPublicKey(other)
	forged.KeyID = v.KeyID
	calls := 0
	src := func(context.Context) ([]PublicKey, error) { calls++; return []PublicKey{forged}, nil }
	ver, err := NewVerifier(Config{Keys: keys, KeySource: src, Now: func() time.Time { return vectorNow }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(context.Background(), v.Envelope, vectorBinding(v)); ReasonOf(err) != ReasonUntrustedKey {
		t.Fatalf("forged hello key: err = %v", err)
	}
	// The real key listed: resolved, and the job verifies.
	src2 := func(context.Context) ([]PublicKey, error) {
		return []PublicKey{NewPublicKey(other), NewPublicKey(pub)}, nil
	}
	ver2, _ := NewVerifier(Config{Keys: keys, KeySource: src2, Now: func() time.Time { return vectorNow }})
	if _, err := ver2.Verify(context.Background(), v.Envelope, vectorBinding(v)); err != nil {
		t.Fatalf("key resolved from hello refused: %v", err)
	}
	if calls != 1 {
		t.Fatalf("key source called %d times", calls)
	}
}

func TestParseKeys(t *testing.T) {
	v := loadVector(t)
	raw, _ := base64.StdEncoding.DecodeString(v.PublicKey)
	url := base64.RawURLEncoding.EncodeToString(raw)
	k, err := ParseKeys(v.PublicKey + "," + url + "\nSHA256:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if k.Len() != 2 {
		t.Fatalf("Len = %d (ids %v)", k.Len(), k.IDs())
	}
	for _, bad := range []string{"SHA256:abc", "SHA256:" + strings.Repeat("zz", 32), "bm90IGEga2V5", "%%%"} {
		if _, err := ParseKeys(bad); err == nil {
			t.Errorf("ParseKeys(%q) accepted", bad)
		}
	}
	empty, err := ParseKeys(" , ")
	if err != nil || empty.Len() != 0 {
		t.Fatalf("empty list: %v %v", empty, err)
	}
	if _, err := NewVerifier(Config{Keys: empty}); err == nil {
		t.Fatal("verifier without keys accepted")
	}
	// identity.json form: the id must be the key's own.
	pk := NewPublicKey(ed25519.PublicKey(raw))
	if _, err := FromPublicKeys([]PublicKey{pk}); err != nil {
		t.Fatal(err)
	}
	pk.KeyID = "SHA256:" + strings.Repeat("00", 32)
	if _, err := FromPublicKeys([]PublicKey{pk}); err == nil {
		t.Fatal("a key with another key's id accepted")
	}
}

func TestPayloadTargetsMatchesPlatform(t *testing.T) {
	got := PayloadTargets([]byte(`{"targets":[" a ","b",3,"a",""],"target":"c"}`))
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("targets = %v", got)
	}
	if got := PayloadTargets([]byte("null")); got == nil || len(got) != 0 {
		t.Fatalf("null payload targets = %#v", got)
	}
	if PayloadTool([]byte(`{"preferred_tool":"x"}`)) != "x" || PayloadTool([]byte(`{"scanner":"y","preferred_tool":"x"}`)) != "y" {
		t.Fatal("PayloadTool")
	}
}
