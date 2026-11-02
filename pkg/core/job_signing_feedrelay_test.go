package core

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// SECURITY: a feed relay round never runs as a command, signed or not, on
// any guard (it has its own channel and verification).
func TestJobGuardRefusesFeedRelayCommand(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys, err := jobsig.NewKeys(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	v, err := jobsig.NewVerifier(jobsig.Config{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	shared, err := NewSharedJobGuard(v, "bbbbbbbb-0000-4000-8000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	unsignedOK, err := NewJobGuard(nil, false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, g := range map[string]*JobGuard{"shared": shared, "legacy unsigned": unsignedOK} {
		cmd := &Command{ID: "cccccccc-0000-4000-8000-000000000003", Type: jobsig.CommandTypeFeedRelay, Payload: []byte(`{}`)}
		if err := g.Check(context.Background(), cmd); err == nil {
			t.Errorf("%s: a feed_relay command was admitted", name)
		}
	}
	if _, err := unsignedOK.VerifyFeedRelay(context.Background(), "r", []byte(`{}`), []byte(`{}`)); err == nil {
		t.Error("a guard of an organization sensor verified a feed relay round")
	}
}
