package sensorkit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The secret fingerprint key is created once in the state directory, 32
// random bytes, private, and read back unchanged; without a state directory
// there is no key; a short key file is refused.
func TestSecretFingerprintKey(t *testing.T) {
	if key, err := loadSecretFingerprintKey(""); key != nil || err != nil {
		t.Fatalf("no state dir: %x %v", key, err)
	}
	dir := t.TempDir()
	a, err := loadSecretFingerprintKey(dir)
	if err != nil || len(a) != secretFingerprintKeyBytes {
		t.Fatalf("created %d bytes, %v", len(a), err)
	}
	st, err := os.Stat(filepath.Join(dir, SecretFingerprintKeyFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", st, err)
	}
	b, err := loadSecretFingerprintKey(dir)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("the key changed between loads")
	}
	other := t.TempDir()
	if c, _ := loadSecretFingerprintKey(other); bytes.Equal(a, c) {
		t.Fatal("two installations share a key")
	}
	short := t.TempDir()
	_ = os.WriteFile(filepath.Join(short, SecretFingerprintKeyFile), []byte("short"), 0o600)
	if _, err := loadSecretFingerprintKey(short); err == nil {
		t.Fatal("a short key was accepted")
	}
}
