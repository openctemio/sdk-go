package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Signer wraps a payload in a signed DSSE envelope.
type Signer interface {
	Sign(payloadType string, payload []byte) ([]byte, error)
}

// Verifier checks a DSSE envelope of the expected payload type and returns
// its payload. A feed's verifier checks its key set (offline root, version,
// expiry) and the online keys it lists; Ed25519Verifier is the plain one.
type Verifier interface {
	Verify(envelope []byte, payloadType string) ([]byte, error)
}

// ErrSignature: no trusted key signed the envelope.
var ErrSignature = errors.New("bundle: signature not verified")

// Ed25519Signer signs DSSE v1 envelopes. The envelope, pre-authentication
// encoding and key id are byte-identical to package
// github.com/openctemio/sdk-go/pkg/jobsig (a shared golden vector in both
// packages' tests holds them together); they are restated here so this
// module needs nothing outside the standard library to sign or verify.
type Ed25519Signer struct{ Key ed25519.PrivateKey }

// Sign implements Signer.
func (s Ed25519Signer) Sign(payloadType string, payload []byte) ([]byte, error) {
	if len(s.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("bundle: invalid signing key")
	}
	pub, _ := s.Key.Public().(ed25519.PublicKey)
	env := dsseEnvelope{PayloadType: payloadType, Payload: payload, Signatures: []signature{{
		KeyID: keyID(pub),
		Sig:   ed25519.Sign(s.Key, preAuthEncoding(payloadType, payload)),
	}}}
	return json.Marshal(env)
}

// dsseEnvelope is a DSSE v1 envelope (the JSON shape of jobsig.Envelope).
type dsseEnvelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// keyID is "SHA256:" + lower-case hex of the SHA-256 of the raw key.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

// preAuthEncoding is the DSSE v1 PAE: "DSSEv1 <len> <type> <len> <payload>".
func preAuthEncoding(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// Ed25519Verifier accepts envelopes signed by any of its keys.
type Ed25519Verifier struct{ keys map[string]ed25519.PublicKey }

// NewEd25519Verifier trusts pubs.
func NewEd25519Verifier(pubs ...ed25519.PublicKey) *Ed25519Verifier {
	v := &Ed25519Verifier{keys: map[string]ed25519.PublicKey{}}
	for _, p := range pubs {
		if len(p) == ed25519.PublicKeySize {
			v.keys[keyID(p)] = p
		}
	}
	return v
}

// Verify implements Verifier.
func (v *Ed25519Verifier) Verify(envelope []byte, payloadType string) ([]byte, error) {
	var env dsseEnvelope
	if err := decodeStrict(envelope, &env); err != nil {
		return nil, fmt.Errorf("%w: envelope: %w", ErrSignature, err)
	}
	if env.PayloadType != payloadType {
		return nil, fmt.Errorf("%w: payload type %q, want %q", ErrSignature, env.PayloadType, payloadType)
	}
	pae := preAuthEncoding(env.PayloadType, env.Payload)
	for _, s := range env.Signatures {
		if k, ok := v.keys[s.KeyID]; ok && ed25519.Verify(k, pae, s.Sig) {
			return env.Payload, nil
		}
	}
	return nil, ErrSignature
}

// decodeStrict decodes one JSON value, refusing unknown fields and trailing
// data.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
