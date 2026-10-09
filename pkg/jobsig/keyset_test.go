package jobsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// keysetVector is api pkg/jobsign/testdata/keyset_vector.json
// (openctemio/openctem), copied byte for byte: key sets 1 [A], 2 [A, B]
// and 3 [B] of one root, and one of another root. Key A is the key of
// testdata/vector.json.
type keysetVector struct {
	RootSeed  []byte    `json:"root_seed"`
	RootKeyID string    `json:"root_keyid"`
	Now       time.Time `json:"now"`
	Keys      []struct {
		Name  string `json:"name"`
		Seed  []byte `json:"seed"`
		KeyID string `json:"keyid"`
	} `json:"keys"`
	KeySets []struct {
		Version  uint64          `json:"version"`
		Envelope json.RawMessage `json:"envelope"`
	} `json:"keysets"`
	OtherRoot struct {
		Envelope json.RawMessage `json:"envelope"`
	} `json:"other_root"`
}

func loadKeysetVector(t *testing.T) keysetVector {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "keyset_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v keysetVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.KeySets) != 3 || len(v.Keys) != 2 {
		t.Fatalf("keyset vector: %d key sets, %d keys", len(v.KeySets), len(v.Keys))
	}
	return v
}

// clock is a settable test clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTrust(t *testing.T, root, stateFile string, c *clock) *KeySetTrust {
	t.Helper()
	tr, err := NewKeySetTrust(KeySetConfig{Root: root, StateFile: stateFile, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// resignKeySet signs an edited copy of a key set with the root.
func resignKeySet(t *testing.T, env json.RawMessage, rootSeed []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	var e Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(e.Payload, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	e.Payload, _ = json.Marshal(m)
	e.Signatures[0].Sig = ed25519.Sign(ed25519.NewKeyFromSeed(rootSeed), PreAuthEncoding(KeySetPayloadType, e.Payload))
	b, _ := json.Marshal(e)
	return b
}

func TestKeySetVector_InOrderAndAnotherRoot(t *testing.T) {
	v := loadKeysetVector(t)
	c := &clock{v.Now}
	tr := newTrust(t, v.RootKeyID, "", c)
	for _, ks := range v.KeySets {
		changed, err := tr.Accept(ks.Envelope)
		if err != nil || !changed || tr.Current().Version != ks.Version {
			t.Fatalf("key set %d: changed %v, %v", ks.Version, changed, err)
		}
	}
	if _, err := tr.Accept(v.OtherRoot.Envelope); ReasonOf(err) != ReasonKeySet {
		t.Fatalf("a key set signed by another root: %v", err)
	}
	if _, err := VerifyKeySet(v.KeySets[0].Envelope, KeyID(ed25519.NewKeyFromSeed(v.Keys[0].Seed).Public().(ed25519.PublicKey)), v.Now); err == nil {
		t.Fatal("a key set verified against a pin that is not its root")
	}
}

func TestKeySet_Refusals(t *testing.T) {
	v := loadKeysetVector(t)
	c := &clock{v.Now}

	// Expired (past not_after plus the skew), and not yet valid.
	tr := newTrust(t, v.RootKeyID, "", c)
	c.t = v.Now.Add(MaxKeySetValidity + MaxClockSkew)
	if _, err := tr.Accept(v.KeySets[0].Envelope); ReasonOf(err) != ReasonKeySet || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired key set: %v", err)
	}
	c.t = v.Now.Add(-MaxClockSkew - time.Second)
	if _, err := tr.Accept(v.KeySets[0].Envelope); err == nil {
		t.Fatal("a key set issued in the future was accepted")
	}
	c.t = v.Now

	// Rollback: after version 2, version 1 is refused; a different
	// version 2 is refused; the same version 2 is no change.
	if _, err := tr.Accept(v.KeySets[1].Envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Accept(v.KeySets[0].Envelope); ReasonOf(err) != ReasonKeySet || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("rollback to version 1: %v", err)
	}
	other2 := resignKeySet(t, v.KeySets[1].Envelope, v.RootSeed, func(m map[string]any) { m["not_after"] = v.Now.Add(time.Hour) })
	if _, err := tr.Accept(other2); ReasonOf(err) != ReasonKeySet || !strings.Contains(err.Error(), "same version") {
		t.Fatalf("a different version 2: %v", err)
	}
	if changed, err := tr.Accept(v.KeySets[1].Envelope); err != nil || changed {
		t.Fatalf("the same version 2: changed %v, %v", changed, err)
	}

	// Well signed but invalid documents.
	for name, edit := range map[string]func(m map[string]any){
		"over 30 days":  func(m map[string]any) { m["version"] = 9; m["not_after"] = v.Now.Add(31 * 24 * time.Hour) },
		"unknown field": func(m map[string]any) { m["version"] = 9; m["extra"] = true },
		"wrong kind":    func(m map[string]any) { m["version"] = 9; m["kind"] = Kind },
		"no keys":       func(m map[string]any) { m["version"] = 9; m["keys"] = []any{} },
	} {
		if _, err := tr.Accept(resignKeySet(t, v.KeySets[1].Envelope, v.RootSeed, edit)); ReasonOf(err) != ReasonKeySet {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A changed byte without a new signature.
	var e Envelope
	_ = json.Unmarshal(v.KeySets[2].Envelope, &e)
	e.Payload = bytes.Replace(e.Payload, []byte(`"version":3`), []byte(`"version":4`), 1)
	tampered, _ := json.Marshal(e)
	if _, err := tr.Accept(tampered); ReasonOf(err) != ReasonKeySet {
		t.Fatalf("tampered key set: %v", err)
	}
	if tr.Current().Version != 2 {
		t.Fatalf("current version %d after refusals", tr.Current().Version)
	}
}

func TestKeySet_VersionSurvivesRestart(t *testing.T) {
	v := loadKeysetVector(t)
	c := &clock{v.Now}
	state := filepath.Join(t.TempDir(), "keyset.json")
	tr := newTrust(t, v.RootKeyID, state, c)
	if _, err := tr.Accept(v.KeySets[1].Envelope); err != nil {
		t.Fatal(err)
	}
	tr = newTrust(t, v.RootKeyID, state, c)
	if tr.Current() == nil || tr.Current().Version != 2 {
		t.Fatalf("after restart: %+v", tr.Current())
	}
	if _, err := tr.Accept(v.KeySets[0].Envelope); ReasonOf(err) != ReasonKeySet {
		t.Fatalf("rollback after restart: %v", err)
	}
	// A state file of another root, or a corrupt one, stops the start.
	if _, err := NewKeySetTrust(KeySetConfig{Root: v.Keys[0].KeyID, StateFile: state, Now: c.now}); err == nil {
		t.Fatal("a stored key set of another root was accepted")
	}
	if err := os.WriteFile(state, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeySetTrust(KeySetConfig{Root: v.RootKeyID, StateFile: state, Now: c.now}); err == nil {
		t.Fatal("a corrupt key set state was accepted")
	}
}

// jobSignedBy re-signs the job vector's statement with another key (the
// signer field names it; seq and nonce are new so it is not a replay).
func jobSignedBy(t *testing.T, job vector, seed []byte, seq string) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	id := KeyID(priv.Public().(ed25519.PublicKey))
	payload := strings.Replace(job.Payload, job.KeyID, id, 1)
	payload = strings.Replace(payload, `"seq":18`, `"seq":`+seq, 1)
	payload = strings.Replace(payload, `"nonce":"AAECAwQFBgcICQoLDA0ODw"`, `"nonce":"AAECAwQFBgcICQoLDA0O`+seq+`"`, 1)
	return sign(t, priv, id, []byte(payload))
}

// The verifier with a pinned root: jobs from keys of the current key set,
// rotation without pairing again, revocation by a newer key set, and fail
// closed without a valid key set.
func TestVerifier_KeySetRotationAndRevocation(t *testing.T) {
	v, job := loadKeysetVector(t), loadVector(t)
	c := &clock{vectorNow}
	var served []byte
	tr, err := NewKeySetTrust(KeySetConfig{Root: v.RootKeyID, Now: c.now,
		Source: func(context.Context) ([]byte, error) { return served, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ver, err := NewVerifier(Config{KeySet: tr, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	b := vectorBinding(job)

	// No key set yet: refused for the key set, not run.
	if _, err := ver.Verify(ctx, job.Envelope, b); ReasonOf(err) != ReasonKeySet {
		t.Fatalf("without a key set: %v", err)
	}
	// Key set 1 [A]: the job signed by A is accepted (fetched on demand,
	// once the refresh interval passed).
	served = v.KeySets[0].Envelope
	c.t = c.t.Add(KeySetRefreshInterval)
	if _, err := ver.Verify(ctx, job.Envelope, b); err != nil {
		t.Fatalf("job by A under key set 1: %v", err)
	}
	// A job by B is not accepted under key set 1.
	byB := jobSignedBy(t, job, v.Keys[1].Seed, "19")
	if _, err := ver.Verify(ctx, byB, b); ReasonOf(err) != ReasonUntrustedKey {
		t.Fatalf("job by B under key set 1: %v", err)
	}
	// Rotation: key set 2 [A, B] makes B valid, with no new pairing.
	served = v.KeySets[1].Envelope
	c.t = c.t.Add(KeySetRefreshInterval)
	if _, err := ver.Verify(ctx, byB, b); err != nil {
		t.Fatalf("job by B under key set 2: %v", err)
	}
	// Revocation: key set 3 [B] drops A; a job by A is refused.
	if _, err := tr.Accept(v.KeySets[2].Envelope); err != nil {
		t.Fatal(err)
	}
	byA := jobSignedBy(t, job, v.Keys[0].Seed, "20")
	if _, err := ver.Verify(ctx, byA, b); ReasonOf(err) != ReasonUntrustedKey {
		t.Fatalf("job by A after key set 3: %v", err)
	}
	if _, err := ver.Verify(ctx, jobSignedBy(t, job, v.Keys[1].Seed, "21"), b); err != nil {
		t.Fatalf("job by B under key set 3: %v", err)
	}
	// Expired key set, nothing newer served: fail closed.
	c.t = v.Now.Add(MaxKeySetValidity + MaxClockSkew)
	served = nil
	if _, err := ver.Verify(ctx, jobSignedBy(t, job, v.Keys[1].Seed, "22"), b); ReasonOf(err) != ReasonKeySet {
		t.Fatalf("expired key set: %v", err)
	}
}

// An explicitly pinned key still verifies next to a root's key set.
func TestVerifier_PinnedKeyBesideRoot(t *testing.T) {
	v, job := loadKeysetVector(t), loadVector(t)
	c := &clock{vectorNow}
	tr := newTrust(t, v.RootKeyID, "", c)
	if _, err := tr.Accept(v.KeySets[2].Envelope); err != nil { // [B] only
		t.Fatal(err)
	}
	keys, _ := ParseKeys(job.PublicKey) // A, pinned on the sensor
	ver, err := NewVerifier(Config{Keys: keys, KeySet: tr, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(context.Background(), job.Envelope, vectorBinding(job)); err != nil {
		t.Fatalf("job by the pinned key A: %v", err)
	}
}

func TestParseRootAndTrustOnFirstUse(t *testing.T) {
	v := loadKeysetVector(t)
	pub := ed25519.NewKeyFromSeed(v.RootSeed).Public().(ed25519.PublicKey)
	for _, in := range []string{v.RootKeyID, strings.ToUpper(v.RootKeyID[7:]), NewPublicKey(pub).PublicKey} {
		if in == strings.ToUpper(v.RootKeyID[7:]) {
			in = "SHA256:" + in
		}
		got, err := ParseRoot(in)
		if err != nil || got != v.RootKeyID {
			t.Fatalf("ParseRoot(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseRoot("SHA256:abc"); err == nil {
		t.Fatal("a short key id parsed")
	}
	ks, err := TrustOnFirstUse(v.KeySets[0].Envelope, v.Now)
	if err != nil || ks.RootKeyID != v.RootKeyID {
		t.Fatalf("TOFU: %v", err)
	}
	if _, err := TrustOnFirstUse(v.KeySets[0].Envelope, v.Now.Add(40*24*time.Hour)); err == nil {
		t.Fatal("TOFU accepted an expired key set")
	}
}
