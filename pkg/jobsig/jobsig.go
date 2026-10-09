// Package jobsig verifies signed jobs on the sensor (api
// docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §5.6; wire format in
// api docs/architecture/job-signing.md).
//
// The platform's job signer is a separate process from the API: it signs a
// statement for every command a claim hands out (the tenant, the sensor and
// the command it is for, the command type, the tool, the targets, the
// SHA-256 of the command's payload bytes, the lease epoch, a validity
// window, a per-sensor sequence number and a nonce) and returns it in a DSSE
// envelope. A sensor that pins the signer's key runs only what the signer
// signed: anyone who can write the commands table or run code in the API
// can no longer decide on their own what the sensor scans.
//
// Verify checks the signature over the exact payload bytes with a pinned
// key before it parses them, then binds the statement to the command being
// run and to this sensor, and refuses a replay (a nonce seen before, a
// sequence number not above the last accepted one, persisted across
// restarts).
//
// Stability: Beta (docs/STABILITY.md).
package jobsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// PayloadType is the DSSE payload type of a signed job.
const PayloadType = "application/vnd.openctem.job.v1+json"

// Kind is the statement kind (v1).
const Kind = "openctem.job/v1"

// Algorithm is the only signature algorithm a signer key may have.
const Algorithm = "ed25519"

// Limits of a statement, as the signer enforces them.
const (
	// MaxClockSkew is how far issued_at may be from the sensor's clock.
	MaxClockSkew = 2 * time.Minute
	// MaxTTL caps expires_at - issued_at.
	MaxTTL = time.Hour
	// MaxPayloadBytes caps the statement bytes.
	MaxPayloadBytes = 1 << 20
	// MaxEnvelopeBytes caps the envelope JSON (base64 payload plus
	// signatures).
	MaxEnvelopeBytes = 2 << 20
	// NonceBytes is the size of a nonce before encoding.
	NonceBytes = 16
)

// Statement is a signed job statement. A verifier never re-encodes it: it
// verifies and parses the envelope's payload bytes.
type Statement struct {
	Kind        string `json:"kind"`
	TenantID    string `json:"tenant_id"`
	SensorID    string `json:"sensor_id"`
	CommandID   string `json:"command_id"`
	CommandType string `json:"command_type"`
	// Tool is the payload's "scanner", else its "preferred_tool"; "" when
	// it names neither.
	Tool string `json:"tool"`
	// PayloadSHA256 is "sha256:" + lower-case hex SHA-256 of the command's
	// payload bytes as the claim response carried them.
	PayloadSHA256 string    `json:"payload_sha256"`
	Targets       []string  `json:"targets"`
	LeaseEpoch    int       `json:"lease_epoch"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	// Seq is per sensor and strictly increasing (gaps are possible).
	Seq uint64 `json:"seq"`
	// Nonce is 16 random bytes, base64url without padding.
	Nonce  string     `json:"nonce"`
	Signer *SignerRef `json:"signer"`
}

// SignerRef names the key that signed a statement.
type SignerRef struct {
	KeyID string `json:"keyid"`
}

// PublicKey is a signer key as the platform's hello lists it
// ("signed_jobs.keys") and identity.json keeps it.
type PublicKey struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	// PublicKey is the raw 32-byte Ed25519 key, standard base64.
	PublicKey string `json:"public_key"`
}

// Decode returns the raw key after checking the algorithm and that the key
// id is the key's own (KeyID is recomputed, never trusted).
func (k PublicKey) Decode() (ed25519.PublicKey, error) {
	if k.Algorithm != Algorithm {
		return nil, fmt.Errorf("job-signing key %s: unsupported algorithm %q", k.KeyID, k.Algorithm)
	}
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("job-signing key %s: not a 32-byte Ed25519 key", k.KeyID)
	}
	pub := ed25519.PublicKey(raw)
	if KeyID(pub) != k.KeyID {
		return nil, fmt.Errorf("job-signing key %s: the key id does not match the key", k.KeyID)
	}
	return pub, nil
}

// NewPublicKey describes pub.
func NewPublicKey(pub ed25519.PublicKey) PublicKey {
	return PublicKey{KeyID: KeyID(pub), Algorithm: Algorithm, PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

// Envelope is a DSSE envelope: Payload holds the exact signed bytes
// (standard base64 in JSON).
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signature of an Envelope.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// KeyID names a public key: "SHA256:" + lower-case hex of the SHA-256 of
// the raw 32-byte key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

// validKeyID reports whether id is "SHA256:" + 64 lower-case hex digits.
func validKeyID(id string) bool {
	h, ok := strings.CutPrefix(id, "SHA256:")
	return ok && isLowerHex(h, 64)
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// PreAuthEncoding is DSSE v1's PAE: "DSSEv1 <len(type)> <type>
// <len(body)> <body>", lengths in ASCII decimal.
func PreAuthEncoding(payloadType string, payload []byte) []byte {
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

// PayloadDigest is the payload_sha256 of payload bytes.
func PayloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PayloadTool is the tool a command payload names, as the platform puts it
// in the statement: "scanner", else "preferred_tool", else "".
func PayloadTool(payload []byte) string {
	var p struct {
		Scanner       string `json:"scanner"`
		PreferredTool string `json:"preferred_tool"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &p) != nil {
		return ""
	}
	if p.Scanner != "" {
		return p.Scanner
	}
	return p.PreferredTool
}

// PayloadTargets are the targets a command payload names, as the platform
// puts them in the statement: "targets" then "target", trimmed,
// de-duplicated, in order; never nil.
func PayloadTargets(payload []byte) []string {
	out := []string{}
	var p struct {
		Targets []any `json:"targets"`
		Target  any   `json:"target"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &p) != nil {
		return out
	}
	seen := map[string]bool{}
	add := func(v any) {
		s, ok := v.(string)
		if !ok {
			return
		}
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, t := range p.Targets {
		add(t)
	}
	add(p.Target)
	return out
}

// Keys are the signer keys a sensor trusts: full public keys, and key ids
// whose public key the platform's hello supplies (a key it lists is
// trusted only when its recomputed id is pinned).
type Keys struct {
	pubs map[string]ed25519.PublicKey // by KeyID
	ids  map[string]bool              // pinned by id only
}

// NewKeys trusts pubs.
func NewKeys(pubs ...ed25519.PublicKey) (*Keys, error) {
	k := &Keys{pubs: map[string]ed25519.PublicKey{}, ids: map[string]bool{}}
	for i, p := range pubs {
		if len(p) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("job-signing key %d: %d bytes, want %d", i+1, len(p), ed25519.PublicKeySize)
		}
		k.pubs[KeyID(p)] = slices.Clone(p)
	}
	return k, nil
}

// ParseKeys reads a comma- or space-separated list of pins, the form
// SENSOR_JOB_SIGNING_KEYS takes: each one a key id ("SHA256:" + 64 hex
// digits, as the platform shows it) or a base64 (standard or URL
// alphabet, padded or not) 32-byte Ed25519 public key. Empty: no keys.
func ParseKeys(s string) (*Keys, error) {
	k, _ := NewKeys()
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' })
	for i, f := range fields {
		if h, ok := strings.CutPrefix(f, "SHA256:"); ok {
			id := "SHA256:" + strings.ToLower(h)
			if !validKeyID(id) {
				return nil, fmt.Errorf("job-signing key %d: %q is not SHA256:<64 hex digits>", i+1, f)
			}
			k.ids[id] = true
			continue
		}
		raw, err := decodeBase64Any(f)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("job-signing key %d: neither SHA256:<hex> nor a base64 32-byte Ed25519 key", i+1)
		}
		pub := ed25519.PublicKey(raw)
		k.pubs[KeyID(pub)] = pub
	}
	return k, nil
}

// FromPublicKeys trusts keys as identity.json keeps them; each id must be
// its key's own.
func FromPublicKeys(keys []PublicKey) (*Keys, error) {
	k, _ := NewKeys()
	for _, pk := range keys {
		pub, err := pk.Decode()
		if err != nil {
			return nil, err
		}
		k.pubs[pk.KeyID] = pub
	}
	return k, nil
}

func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// Merge returns the union of k and o (either may be nil).
func (k *Keys) Merge(o *Keys) *Keys {
	out, _ := NewKeys()
	for _, src := range []*Keys{k, o} {
		if src == nil {
			continue
		}
		for id, p := range src.pubs {
			out.pubs[id] = p
		}
		for id := range src.ids {
			out.ids[id] = true
		}
	}
	return out
}

// Len is the number of pinned keys (full keys and ids).
func (k *Keys) Len() int {
	if k == nil {
		return 0
	}
	n := len(k.pubs)
	for id := range k.ids {
		if _, ok := k.pubs[id]; !ok {
			n++
		}
	}
	return n
}

// IDs are the pinned key ids, sorted.
func (k *Keys) IDs() []string {
	if k == nil {
		return nil
	}
	ids := make([]string, 0, len(k.pubs)+len(k.ids))
	for id := range k.pubs {
		ids = append(ids, id)
	}
	for id := range k.ids {
		if _, ok := k.pubs[id]; !ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

// clone copies k so a Verifier owns its keys.
func (k *Keys) clone() *Keys { return k.Merge(nil) }
