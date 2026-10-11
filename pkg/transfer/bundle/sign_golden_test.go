package bundle

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// goldenEnvelope is the DSSE envelope package jobsig produces for this key,
// payload type and payload. pkg/jobsig holds the same vector, so the restated
// envelope, pre-authentication encoding and key id here cannot drift from it.
const goldenEnvelope = `{"payloadType":"application/vnd.openctem.golden+json","payload":"eyJnb2xkZW4iOnRydWV9","signatures":[{"keyid":"SHA256:fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889","sig":"ur0zss6MVnpXevEdDrmZe2tCP4H2gRBwaYalVPUgdOzGN5paqxH+atfo3qvvKiz8mWe+CR1sblidSmQFcW4qDg=="}]}`

func TestSignMatchesJobsigGoldenVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	const pt, payload = "application/vnd.openctem.golden+json", `{"golden":true}`
	got, err := Ed25519Signer{Key: key}.Sign(pt, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenEnvelope {
		t.Fatalf("envelope drifted from jobsig:\n got %s\nwant %s", got, goldenEnvelope)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	out, err := NewEd25519Verifier(pub).Verify([]byte(goldenEnvelope), pt)
	if err != nil || string(out) != payload {
		t.Fatalf("golden envelope not verified: %q %v", out, err)
	}
	// Another key, or the right key under another payload type, is refused.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
	if _, err := NewEd25519Verifier(other).Verify([]byte(goldenEnvelope), pt); err == nil {
		t.Error("envelope verified by an untrusted key")
	}
	if _, err := NewEd25519Verifier(pub).Verify([]byte(goldenEnvelope), "application/other"); err == nil {
		t.Error("envelope verified under another payload type")
	}
}
