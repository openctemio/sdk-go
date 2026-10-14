package jobsig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

// goldenEnvelope is also asserted by github.com/openctemio/ctis/transfer/bundle,
// a contract module that restates the DSSE envelope, pre-authentication
// encoding and key id. Change both together, or feed signatures break.
const goldenEnvelope = `{"payloadType":"application/vnd.openctem.golden+json","payload":"eyJnb2xkZW4iOnRydWV9","signatures":[{"keyid":"SHA256:fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889","sig":"ur0zss6MVnpXevEdDrmZe2tCP4H2gRBwaYalVPUgdOzGN5paqxH+atfo3qvvKiz8mWe+CR1sblidSmQFcW4qDg=="}]}`

func TestDSSEGoldenVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	const pt, payload = "application/vnd.openctem.golden+json", `{"golden":true}`
	pub, _ := key.Public().(ed25519.PublicKey)
	env := Envelope{PayloadType: pt, Payload: []byte(payload), Signatures: []Signature{{
		KeyID: KeyID(pub), Sig: ed25519.Sign(key, PreAuthEncoding(pt, []byte(payload))),
	}}}
	got, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenEnvelope {
		t.Fatalf("DSSE envelope changed:\n got %s\nwant %s", got, goldenEnvelope)
	}
}
