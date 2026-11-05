package sealedmsg

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/openctemio/contract/secretref"
)

// taskSecretsVector is testdata/task-secrets-vector-v1.json: a sealed task
// secrets answer the platform's implementation produced. It is never
// regenerated: both implementations open the same bytes.
type taskSecretsVector struct {
	SensorID    string `json:"sensor_id"`
	CommandID   string `json:"command_id"`
	LeaseEpoch  int64  `json:"lease_epoch"`
	RequestBody string `json:"request_body"`
	InfoHex     string `json:"info_hex"`
	PrivateKey  string `json:"private_key_b64url"`
	PublicKey   string `json:"public_key_b64url"`
	KeyID       string `json:"key_id"`
	Plaintext   string `json:"plaintext"`
	Sealed      string `json:"sealed_b64url"`
}

func loadTaskSecretsVector(t *testing.T) (taskSecretsVector, *PrivateKey, []byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/task-secrets-vector-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v taskSecretsVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	privB, err := base64.RawURLEncoding.DecodeString(v.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey(privB)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(v.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	info := secretref.Info(v.SensorID, v.CommandID, v.LeaseEpoch, []byte(v.RequestBody))
	return v, priv, info, sealed
}

// TestTaskSecretsVectorOpens: the cross-implementation vector opens with
// its key and info, the info the contract builds is the vector's, and the
// reply key and key id in the request match the key pair.
func TestTaskSecretsVectorOpens(t *testing.T) {
	v, priv, info, sealed := loadTaskSecretsVector(t)
	if hex.EncodeToString(info) != v.InfoHex {
		t.Fatalf("secretref.Info differs from the vector's info")
	}
	pub := priv.Public().Bytes()
	if base64.RawURLEncoding.EncodeToString(pub) != v.PublicKey || secretref.KeyID(pub) != v.KeyID {
		t.Fatalf("the vector's public key or key id is not its private key's")
	}
	var req secretref.FetchRequest
	if err := json.Unmarshal([]byte(v.RequestBody), &req); err != nil || req.ReplyKey != v.PublicKey || req.LeaseEpoch != v.LeaseEpoch {
		t.Fatalf("the vector's request does not carry its reply key and epoch: %v", err)
	}
	pt, err := OpenWithKey(priv, info, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(pt) != v.Plaintext {
		t.Fatalf("plaintext differs")
	}
}

// TestTaskSecretsVectorRefusesChanges: a changed info byte, a changed
// sealed byte or another key does not open.
func TestTaskSecretsVectorRefusesChanges(t *testing.T) {
	_, priv, info, sealed := loadTaskSecretsVector(t)
	for _, idx := range []int{0, len(info) / 2, len(info) - 1} {
		bad := bytes.Clone(info)
		bad[idx] ^= 1
		if _, err := OpenWithKey(priv, bad, sealed); !errors.Is(err, ErrOpen) {
			t.Fatalf("info byte %d changed: %v", idx, err)
		}
	}
	for _, idx := range []int{0, len(sealed) / 2, len(sealed) - 1} {
		bad := bytes.Clone(sealed)
		bad[idx] ^= 1
		if _, err := OpenWithKey(priv, info, bad); !errors.Is(err, ErrOpen) {
			t.Fatalf("sealed byte %d changed: %v", idx, err)
		}
	}
	other, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithKey(other, info, sealed); !errors.Is(err, ErrOpen) {
		t.Fatalf("another key opened the answer: %v", err)
	}
	if _, err := OpenWithKey(nil, info, sealed); err == nil {
		t.Fatal("a nil key opened the answer")
	}
}

// TestSealToKeyRoundTrip: SealToKey and OpenWithKey agree; info binds the
// answer.
func TestSealToKeyRoundTrip(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	info := secretref.Info("s", "c", 2, []byte(`{}`))
	ct, err := SealToKey(k.Public().Bytes(), info, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := OpenWithKey(k, info, ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	if _, err := OpenWithKey(k, secretref.Info("s", "c", 3, []byte(`{}`)), ct); !errors.Is(err, ErrOpen) {
		t.Fatalf("another epoch opened: %v", err)
	}
	if _, err := SealToKey([]byte("short"), info, nil); err == nil {
		t.Fatal("a malformed public key sealed")
	}
}
