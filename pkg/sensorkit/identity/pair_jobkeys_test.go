package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

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
