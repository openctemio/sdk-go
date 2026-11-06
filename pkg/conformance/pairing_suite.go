package conformance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
)

// VerifyPairingGrant is a sensor's check of the platform's signed pairing
// answer (pairing.SignedGrant): it returns the statement it accepted, or an
// error. platformPub is the key of the verified start answer; sensorPub,
// pairingID and sensorNonce are this sensor's own request. pairing.VerifyGrant
// is the SDK's.
type VerifyPairingGrant func(sg *pairing.SignedGrant, platformPub, sensorPub ed25519.PublicKey, pairingID string, sensorNonce []byte) (*pairing.Grant, error)

// RunPairingGrantSuite checks that a sensor's pairing accepts the
// platform's signed grant and nothing else (research 452 N3: someone in the
// middle of the first pairing relays the start untouched, so the fingerprint
// the administrator compares matches, and swaps what the sensor pins later).
// A conforming sensor accepts a valid grant for its own request and refuses:
// an answer without a grant (it never falls back to the unsigned identity),
// a grant whose payload was changed (job signer, TLS anchors, content keys,
// identity), a grant re-signed with another key, and the platform's own valid
// grant for another sensor, request or nonce (a replay). A sensor that pairs
// with identity.Pair passes by construction; one with its own pairing runs
// this against its verifier.
func RunPairingGrantSuite(t *testing.T, verify VerifyPairingGrant) {
	t.Helper()
	for _, msg := range checkPairingGrant(verify) {
		t.Error(msg)
	}
}

// checkPairingGrant runs the cases and returns one message per failure.
func checkPairingGrant(verify VerifyPairingGrant) []string {
	var fails []string
	platform := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	attacker := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	sensor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x54}, ed25519.SeedSize))
	ppub := platform.Public().(ed25519.PublicKey)
	spub := sensor.Public().(ed25519.PublicKey)
	const pairingID = "0b5a3c1e-6f0f-4d4c-9a51-0e1c2b3a4d5e"
	nonce := bytes.Repeat([]byte{0x55}, pairing.NonceSize)

	grant := func(edit func(*pairing.Grant)) *pairing.Grant {
		key := pairing.ContentKey{KeyID: "SHA256:" + string(bytes.Repeat([]byte("ab"), 32)), Algorithm: "ed25519",
			PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}
		g := &pairing.Grant{PairingID: pairingID, SensorKey: pairing.Encode(spub), SensorNonce: pairing.Encode(nonce),
			Identity: pairing.Identity{SensorID: "66666666-7777-4888-9999-aaaaaaaaaaaa", TenantID: "11111111-2222-4333-8444-555555555555",
				Name: "conformance", KeyID: "k", ContentSigning: &pairing.ContentSigning{Platform: []pairing.ContentKey{key}}},
			SignedJobs: &pairing.JobSigning{PayloadType: "application/vnd.openctem.job.v1+json",
				Keys: []pairing.JobKey{{KeyID: key.KeyID, Algorithm: key.Algorithm, PublicKey: key.PublicKey}}},
			TLSAnchors: []string{"sha256:" + string(bytes.Repeat([]byte("0f"), 32))}}
		if edit != nil {
			edit(g)
		}
		return g
	}
	sign := func(k ed25519.PrivateKey, g *pairing.Grant) *pairing.SignedGrant {
		sg, _ := pairing.SignGrant(k, g) // a fixed grant and key: never fails
		return sg
	}
	// altered keeps the platform's signature over a changed statement.
	altered := func(edit func(*pairing.Grant)) *pairing.SignedGrant {
		sg := sign(platform, grant(nil))
		g := grant(edit)
		g.Protocol = pairing.Version
		b, _ := json.Marshal(g)
		sg.Payload = pairing.Encode(b)
		return sg
	}

	g, err := verify(sign(platform, grant(nil)), ppub, spub, pairingID, nonce)
	switch {
	case err != nil:
		fails = append(fails, fmt.Sprintf("pairing grant: a valid grant was refused: %v", err))
	case g == nil || g.Identity.SensorID != "66666666-7777-4888-9999-aaaaaaaaaaaa" || g.SignedJobs == nil || len(g.SignedJobs.Keys) != 1:
		fails = append(fails, fmt.Sprintf("pairing grant: the accepted statement is not the signed one: %+v", g))
	}
	refuse := map[string]*pairing.SignedGrant{
		"no grant (platform from before signed answers)": nil,
		"job keys changed": altered(func(g *pairing.Grant) {
			g.SignedJobs.Keys[0].PublicKey = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
		}),
		"TLS anchors changed":   altered(func(g *pairing.Grant) { g.TLSAnchors = []string{"sha256:" + string(bytes.Repeat([]byte("00"), 32))} }),
		"content keys removed":  altered(func(g *pairing.Grant) { g.Identity.ContentSigning = nil }),
		"organization changed":  altered(func(g *pairing.Grant) { g.Identity.TenantID = "22222222-2222-4333-8444-555555555555" }),
		"re-signed by attacker": sign(attacker, grant(func(g *pairing.Grant) { g.SignedJobs = nil })),
		"another sensor's grant": sign(platform, grant(func(g *pairing.Grant) {
			g.SensorKey = pairing.Encode(other.Public().(ed25519.PublicKey))
		})),
		"another request's grant": sign(platform, grant(func(g *pairing.Grant) { g.PairingID = "5f1d6a8e-1b2c-4d3e-8f90-a1b2c3d4e5f6" })),
		"another nonce's grant": sign(platform, grant(func(g *pairing.Grant) {
			g.SensorNonce = pairing.Encode(bytes.Repeat([]byte{0x56}, pairing.NonceSize))
		})),
	}
	names := make([]string, 0, len(refuse))
	for name := range refuse {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := verify(refuse[name], ppub, spub, pairingID, nonce); err == nil {
			fails = append(fails, "pairing grant: accepted "+name+"; a conforming sensor refuses it and saves nothing")
		}
	}
	return fails
}
