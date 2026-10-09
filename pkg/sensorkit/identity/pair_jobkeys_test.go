package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/jobsig"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

func TestPairPinsTheJobSignerKeysTheHelloLists(t *testing.T) {
	f, srv := newFakePlatform(t)
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32)).Public().(ed25519.PublicKey)
	good := jobsig.NewPublicKey(signer)
	// A key listed under another key's id is not pinned.
	forged := jobsig.NewPublicKey(other)
	forged.KeyID = good.KeyID
	f.signedJobs = &protov2.SignedJobs{PayloadType: jobsig.PayloadType, Keys: []protov2.SignedJobKey{
		{KeyID: good.KeyID, Algorithm: good.Algorithm, PublicKey: good.PublicKey},
		{KeyID: forged.KeyID, Algorithm: forged.Algorithm, PublicKey: forged.PublicKey},
	}}
	var out bytes.Buffer
	o := opts(t, srv, &out)
	id, err := Pair(context.Background(), o)
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if f.helloAsked != 1 || f.unsigned != 0 {
		t.Fatalf("hello asked %d times, unsigned requests %d", f.helloAsked, f.unsigned)
	}
	if len(id.JobSigningKeys) != 1 || id.JobSigningKeys[0] != good {
		t.Fatalf("pinned %+v, want only %+v", id.JobSigningKeys, good)
	}
	got, _, err := o.Store.Load()
	if err != nil || len(got.JobSigningKeys) != 1 || got.JobSigningKeys[0] != good {
		t.Fatalf("identity.json: %v %+v", err, got)
	}
	if !strings.Contains(out.String(), "Job signer pinned: "+good.KeyID) || !strings.Contains(out.String(), "not pinned") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestPairWithAPlatformThatDoesNotSignJobsPinsNone(t *testing.T) {
	_, srv := newFakePlatform(t) // no hello route: an older platform
	var out bytes.Buffer
	id, err := Pair(context.Background(), opts(t, srv, &out))
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if len(id.JobSigningKeys) != 0 {
		t.Fatalf("pinned %+v", id.JobSigningKeys)
	}
	if !strings.Contains(out.String(), "could not read the platform's job-signing keys") {
		t.Fatalf("no warning:\n%s", out.String())
	}
}

// testKeySet signs a key set listing keys with root, issued at issued.
func testKeySet(t *testing.T, root ed25519.PrivateKey, issued time.Time, keys ...ed25519.PublicKey) []byte {
	t.Helper()
	rootPub := root.Public().(ed25519.PublicKey)
	ks := jobsig.KeySet{Kind: jobsig.KeySetKind, Version: 1, IssuedAt: issued.UTC().Truncate(time.Second),
		NotAfter: issued.UTC().Truncate(time.Second).Add(24 * time.Hour), RootKeyID: jobsig.KeyID(rootPub),
		RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	for _, k := range keys {
		ks.Keys = append(ks.Keys, jobsig.NewPublicKey(k))
	}
	p, _ := json.Marshal(ks)
	env, _ := json.Marshal(jobsig.Envelope{PayloadType: jobsig.KeySetPayloadType, Payload: p,
		Signatures: []jobsig.Signature{{KeyID: ks.RootKeyID, Sig: ed25519.Sign(root, jobsig.PreAuthEncoding(jobsig.KeySetPayloadType, p))}}})
	return env
}

// Pairing pins the root of the key set the hello serves, only when that
// key set is signed by it and current.
func TestPairPinsTheKeySetRoot(t *testing.T) {
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey)
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	good := jobsig.NewPublicKey(signer)
	for _, tc := range []struct {
		name   string
		keyset []byte
		want   string
	}{
		{"valid", testKeySet(t, root, time.Now(), signer), jobsig.KeyID(root.Public().(ed25519.PublicKey))},
		{"expired", testKeySet(t, root, time.Now().Add(-48*time.Hour), signer), ""},
		{"broken signature", bytes.Replace(testKeySet(t, root, time.Now(), signer), []byte(`"sig":"`), []byte(`"sig":"AAAA`), 1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFakePlatform(t)
			f.signedJobs = &protov2.SignedJobs{PayloadType: jobsig.PayloadType, KeySet: tc.keyset,
				Keys: []protov2.SignedJobKey{{KeyID: good.KeyID, Algorithm: good.Algorithm, PublicKey: good.PublicKey}}}
			var out bytes.Buffer
			o := opts(t, srv, &out)
			id, err := Pair(context.Background(), o)
			if err != nil {
				t.Fatalf("pair: %v\n%s", err, out.String())
			}
			if id.JobSigningRoot != tc.want {
				t.Fatalf("root %q, want %q\n%s", id.JobSigningRoot, tc.want, out.String())
			}
			got, _, err := o.Store.Load()
			if err != nil || got.JobSigningRoot != tc.want {
				t.Fatalf("identity.json: %v %+v", err, got)
			}
			if tc.want != "" && !strings.Contains(out.String(), "Job-signing root pinned: "+tc.want) {
				t.Fatalf("output:\n%s", out.String())
			}
		})
	}
}
