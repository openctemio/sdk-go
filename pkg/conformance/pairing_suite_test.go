package conformance

import (
	"crypto/ed25519"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
)

// The SDK's own pairing passes the suite.
func TestPairingGrantSuite(t *testing.T) {
	RunPairingGrantSuite(t, pairing.VerifyGrant)
}

// A sensor that trusts whatever the answer says fails every refusal case.
func TestPairingGrantSuiteCatchesATrustingSensor(t *testing.T) {
	trusting := func(*pairing.SignedGrant, ed25519.PublicKey, ed25519.PublicKey, string, []byte) (*pairing.Grant, error) {
		return &pairing.Grant{}, nil
	}
	if fails := checkPairingGrant(trusting); len(fails) < 9 {
		t.Fatalf("the suite let a trusting sensor through: %q", fails)
	}
}
