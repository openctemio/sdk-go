package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// signTestKeySet signs a key set the way the platform's offline tooling
// does.
func signTestKeySet(t *testing.T, root ed25519.PrivateKey, version uint64, issued time.Time, keys ...ed25519.PublicKey) []byte {
	t.Helper()
	rootPub := root.Public().(ed25519.PublicKey)
	ks := jobsig.KeySet{Kind: jobsig.KeySetKind, Version: version, IssuedAt: issued.UTC().Truncate(time.Second),
		NotAfter: issued.UTC().Truncate(time.Second).Add(24 * time.Hour), RootKeyID: jobsig.KeyID(rootPub),
		RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	for _, k := range keys {
		ks.Keys = append(ks.Keys, jobsig.NewPublicKey(k))
	}
	p, _ := json.Marshal(ks)
	env, err := json.Marshal(jobsig.Envelope{PayloadType: jobsig.KeySetPayloadType, Payload: p,
		Signatures: []jobsig.Signature{{KeyID: ks.RootKeyID, Sig: ed25519.Sign(root, jobsig.PreAuthEncoding(jobsig.KeySetPayloadType, p))}}})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func refusalRule(err error) string {
	var lp *LocalPolicyError
	if errors.As(err, &lp) {
		return lp.Rule
	}
	return ""
}

// With a pinned root: no key set refuses with rule job_keyset; a key set
// that lists the signer's key lets its jobs run; a new config_version
// fetches the key set again, so a revoked key is refused at once.
func TestJobGuardKeySet(t *testing.T) {
	signer := newJobSigner()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
	var mu sync.Mutex
	var served []byte
	serve := func(b []byte) { mu.Lock(); served = b; mu.Unlock() }
	trust, err := jobsig.NewKeySetTrust(jobsig.KeySetConfig{Root: jobsig.KeyID(root.Public().(ed25519.PublicKey)),
		Source: func(context.Context) ([]byte, error) { mu.Lock(); defer mu.Unlock(); return served, nil }})
	if err != nil {
		t.Fatal(err)
	}
	v, err := jobsig.NewVerifier(jobsig.Config{KeySet: trust})
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewJobGuard(v, true, jsTenant, jsSensor)
	if err != nil {
		t.Fatal(err)
	}
	cv := "v1"
	g.SetConfigVersion(func() string { return cv })
	cmd := func() *Command {
		return &Command{ID: jsCmd, Type: "scan", Payload: jsPayload, LeaseEpoch: 1, SignedJob: signer.sign(t, jsCmd, 1, jsPayload, nil)}
	}
	ctx := context.Background()

	if err := g.Check(ctx, cmd()); refusalRule(err) != RefusalRuleJobKeySet {
		t.Fatalf("no key set: %v", err)
	}
	serve(signTestKeySet(t, root, 1, time.Now(), signer.pub()))
	cv = "v2" // the platform's config_version moves with the new key set
	if err := g.Check(ctx, cmd()); err != nil {
		t.Fatalf("key set 1 lists the signer: %v", err)
	}
	// Revoked in key set 2: the moved config_version fetches it before
	// the check, and the key is refused.
	serve(signTestKeySet(t, root, 2, time.Now(), other))
	cv = "v3"
	if err := g.Check(ctx, cmd()); refusalRule(err) != RefusalRuleJobSignature {
		t.Fatalf("a revoked key: %v", err)
	}
	if trust.Current().Version != 2 {
		t.Fatalf("key set version %d", trust.Current().Version)
	}
}
