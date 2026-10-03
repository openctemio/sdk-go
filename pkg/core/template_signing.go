package core

// Signed custom-template manifests (api docs/rfcs/RFC-038-sensor-tool-settings.md,
// "Custom template trust").
//
// When the platform hands a sensor a scan command with custom templates, it
// signs one manifest for the whole set: the tenant, the sensor and the
// command it is for, when it was issued and when it expires, and the id,
// name, type and SHA-256 of every template, in order. The manifest travels in
// a DSSE envelope: the exact signed bytes plus a payload type, signed with
// Ed25519 over DSSE's pre-authentication encoding by a key derived for the
// tenant. The sensor verifies the signature over those bytes before it
// parses them, then checks that the manifest is for this command (and this
// sensor, when it knows its id), has not expired, and lists exactly the
// templates the command carries, byte for byte. Anything else fails the
// command before a template is written or a scanner runs.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TemplateManifestPayloadType is the DSSE payload type of a template
// manifest.
const TemplateManifestPayloadType = "application/vnd.openctem.template-manifest+json"

// TemplateManifestKind is the kind of a template manifest (v1).
const TemplateManifestKind = "openctem.template-manifest/v1"

// MaxTemplateManifestBytes bounds a manifest's payload.
const MaxTemplateManifestBytes = 256 << 10

// templateClockSkew is how far in the future a manifest's issue time may be
// (the platform's clock ahead of the sensor's).
const templateClockSkew = 5 * time.Minute

// ErrNoTemplateKeys is returned when a command carries custom templates and
// the sensor has no template-signing key to check them with.
var ErrNoTemplateKeys = errors.New("custom templates are refused: no template-signing key is pinned on this sensor (SENSOR_TEMPLATE_SIGNING_KEYS)")

// ErrTemplatesUnsigned is returned for custom templates without a signed
// manifest.
var ErrTemplatesUnsigned = errors.New("custom templates are not signed by the platform")

// SignedEnvelope is a DSSE envelope: Payload holds the exact signed bytes
// (base64 in JSON), each signature covers DSSEPreAuthEncoding(PayloadType,
// Payload).
type SignedEnvelope struct {
	PayloadType string              `json:"payloadType"`
	Payload     []byte              `json:"payload"`
	Signatures  []EnvelopeSignature `json:"signatures"`
}

// EnvelopeSignature is one signature of a SignedEnvelope.
type EnvelopeSignature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// DSSEPreAuthEncoding is DSSE v1's PAE: "DSSEv1 <len(type)> <type>
// <len(body)> <body>", lengths in ASCII decimal.
func DSSEPreAuthEncoding(payloadType string, payload []byte) []byte {
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

// TemplateManifest is the signed description of a command's custom
// templates.
type TemplateManifest struct {
	Kind      string    `json:"kind"`
	TenantID  string    `json:"tenant_id"`
	SensorID  string    `json:"sensor_id,omitempty"`
	CommandID string    `json:"command_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Templates lists every template of the command, in the command's
	// order.
	Templates []ManifestTemplate `json:"templates"`
}

// ManifestTemplate is one template in a TemplateManifest.
type ManifestTemplate struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TemplateType string `json:"template_type"`
	SHA256       string `json:"sha256"` // hex, of the decoded content
}

// TemplateKeyID names a template-signing public key: the first 16 hex
// characters of its SHA-256.
func TemplateKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// TemplateVerifier checks signed template manifests against pinned public
// keys.
type TemplateVerifier struct {
	keys map[string]ed25519.PublicKey // by TemplateKeyID
	now  func() time.Time
}

// NewTemplateVerifier returns a verifier for keys; at least one is needed.
func NewTemplateVerifier(keys ...ed25519.PublicKey) (*TemplateVerifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("no template-signing key")
	}
	v := &TemplateVerifier{keys: make(map[string]ed25519.PublicKey, len(keys)), now: time.Now}
	for i, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("template-signing key %d: %d bytes, want %d", i+1, len(k), ed25519.PublicKeySize)
		}
		v.keys[TemplateKeyID(k)] = append(ed25519.PublicKey(nil), k...)
	}
	return v, nil
}

// ParseTemplateSigningKeys reads a comma- or space-separated list of
// base64 (standard or URL alphabet, padded or not) Ed25519 public keys, the
// form the platform shows them in and SENSOR_TEMPLATE_SIGNING_KEYS takes.
// Several keys let an operator pin the next key before a rotation.
func ParseTemplateSigningKeys(s string) (*TemplateVerifier, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
	keys := make([]ed25519.PublicKey, 0, len(fields))
	for i, f := range fields {
		raw, err := decodeBase64Any(f)
		if err != nil {
			return nil, fmt.Errorf("template-signing key %d: not base64: %w", i+1, err)
		}
		keys = append(keys, raw)
	}
	return NewTemplateVerifier(keys...)
}

func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return nil, err
}

// KeyIDs returns the pinned keys' ids.
func (v *TemplateVerifier) KeyIDs() []string {
	ids := make([]string, 0, len(v.keys))
	for id := range v.keys {
		ids = append(ids, id)
	}
	return ids
}

// TemplateBinding is what a manifest must be bound to: the command that
// carries the templates and, when the sensor knows it, its own id.
type TemplateBinding struct {
	CommandID string
	SensorID  string // "" when the sensor does not know its id
}

// Verify checks env against the pinned keys and returns its manifest. The
// signature is checked over the exact payload bytes before they are
// parsed. The manifest must then be a v1 template manifest for b.CommandID
// (and b.SensorID when set), issued no later than now (plus a small clock
// allowance) and not expired, and list exactly templates — the same count,
// and at each position the same id, name, type and SHA-256 of the decoded
// content (contents, decoded by the caller, in the same order).
func (v *TemplateVerifier) Verify(env *SignedEnvelope, b TemplateBinding, templates []EmbeddedTemplate, contents [][]byte) (*TemplateManifest, error) {
	if v == nil || len(v.keys) == 0 {
		return nil, ErrNoTemplateKeys
	}
	if env == nil || len(env.Signatures) == 0 {
		return nil, ErrTemplatesUnsigned
	}
	if env.PayloadType != TemplateManifestPayloadType {
		return nil, fmt.Errorf("template manifest has payload type %q, want %q", env.PayloadType, TemplateManifestPayloadType)
	}
	if len(env.Payload) == 0 || len(env.Payload) > MaxTemplateManifestBytes {
		return nil, errors.New("template manifest is empty or too large")
	}
	pae := DSSEPreAuthEncoding(env.PayloadType, env.Payload)
	verified := false
	for _, s := range env.Signatures {
		if key, ok := v.keys[s.KeyID]; ok && len(s.Sig) == ed25519.SignatureSize && ed25519.Verify(key, pae, s.Sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("template manifest signature is not valid for any pinned key")
	}

	// Only now parse what was signed.
	var m TemplateManifest
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("template manifest: %w", err)
	}
	if m.Kind != TemplateManifestKind {
		return nil, fmt.Errorf("template manifest kind %q, want %q", m.Kind, TemplateManifestKind)
	}
	if m.CommandID == "" || m.CommandID != b.CommandID {
		return nil, fmt.Errorf("template manifest is for command %q, not this command %q", m.CommandID, b.CommandID)
	}
	if b.SensorID != "" && m.SensorID != b.SensorID {
		return nil, fmt.Errorf("template manifest is for sensor %q, not this sensor", m.SensorID)
	}
	now := v.now()
	if m.ExpiresAt.IsZero() || !now.Before(m.ExpiresAt) {
		return nil, fmt.Errorf("template manifest expired at %s", m.ExpiresAt.Format(time.RFC3339))
	}
	if m.IssuedAt.After(now.Add(templateClockSkew)) {
		return nil, fmt.Errorf("template manifest is issued in the future (%s)", m.IssuedAt.Format(time.RFC3339))
	}
	if len(m.Templates) != len(templates) || len(contents) != len(templates) {
		return nil, fmt.Errorf("template manifest lists %d templates, the command carries %d", len(m.Templates), len(templates))
	}
	for i := range templates {
		want := m.Templates[i]
		got := templates[i]
		sum := sha256.Sum256(contents[i])
		if want.ID != got.ID || want.Name != got.Name || want.TemplateType != got.TemplateType ||
			!strings.EqualFold(want.SHA256, hex.EncodeToString(sum[:])) {
			return nil, fmt.Errorf("template %q does not match the signed manifest", got.Name)
		}
	}
	return &m, nil
}
