package credentials

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	t.Run("Set and Get", func(t *testing.T) {
		cred := &Credential{
			Type:  CredentialTypeAPIKey,
			Value: "test-api-key",
		}

		err := store.Set(ctx, "test-key", cred)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		got, err := store.Get(ctx, "test-key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if got.Value != "test-api-key" {
			t.Errorf("Value = %v, want %v", got.Value, "test-api-key")
		}
		if got.Key != "test-key" {
			t.Errorf("Key = %v, want %v", got.Key, "test-key")
		}
	})

	t.Run("Get non-existent", func(t *testing.T) {
		_, err := store.Get(ctx, "non-existent")
		if err != ErrCredentialNotFound {
			t.Errorf("Get non-existent = %v, want ErrCredentialNotFound", err)
		}
	})

	t.Run("Exists", func(t *testing.T) {
		exists, err := store.Exists(ctx, "test-key")
		if err != nil {
			t.Fatalf("Exists failed: %v", err)
		}
		if !exists {
			t.Error("Exists should return true for existing key")
		}

		exists, err = store.Exists(ctx, "non-existent")
		if err != nil {
			t.Fatalf("Exists failed: %v", err)
		}
		if exists {
			t.Error("Exists should return false for non-existent key")
		}
	})

	t.Run("List", func(t *testing.T) {
		store.Set(ctx, "prefix-a", &Credential{Value: "a"})
		store.Set(ctx, "prefix-b", &Credential{Value: "b"})
		store.Set(ctx, "other-c", &Credential{Value: "c"})

		keys, err := store.List(ctx, "prefix-")
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if len(keys) != 2 {
			t.Errorf("List = %d items, want 2", len(keys))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := store.Delete(ctx, "test-key")
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = store.Get(ctx, "test-key")
		if err != ErrCredentialNotFound {
			t.Error("Get after delete should return ErrCredentialNotFound")
		}
	})

	t.Run("Delete non-existent", func(t *testing.T) {
		err := store.Delete(ctx, "non-existent")
		if err != ErrCredentialNotFound {
			t.Errorf("Delete non-existent = %v, want ErrCredentialNotFound", err)
		}
	})
}

func TestEnvStore(t *testing.T) {
	ctx := context.Background()
	store := NewEnvStore("TEST_")

	t.Run("Get from environment", func(t *testing.T) {
		os.Setenv("TEST_MY_API_KEY", "secret-value")
		defer os.Unsetenv("TEST_MY_API_KEY")

		cred, err := store.Get(ctx, "my.api.key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if cred.Value != "secret-value" {
			t.Errorf("Value = %v, want %v", cred.Value, "secret-value")
		}
	})

	t.Run("Get non-existent", func(t *testing.T) {
		_, err := store.Get(ctx, "non-existent")
		if err != ErrCredentialNotFound {
			t.Errorf("Get non-existent = %v, want ErrCredentialNotFound", err)
		}
	})

	t.Run("Set is read-only", func(t *testing.T) {
		err := store.Set(ctx, "key", &Credential{Value: "value"})
		if err != ErrReadOnly {
			t.Errorf("Set = %v, want ErrReadOnly", err)
		}
	})

	t.Run("Delete is read-only", func(t *testing.T) {
		err := store.Delete(ctx, "key")
		if err != ErrReadOnly {
			t.Errorf("Delete = %v, want ErrReadOnly", err)
		}
	})

	t.Run("Exists", func(t *testing.T) {
		os.Setenv("TEST_EXISTS_KEY", "value")
		defer os.Unsetenv("TEST_EXISTS_KEY")

		exists, err := store.Exists(ctx, "exists.key")
		if err != nil {
			t.Fatalf("Exists failed: %v", err)
		}
		if !exists {
			t.Error("Exists should return true for existing env var")
		}
	})

	t.Run("Custom mapping", func(t *testing.T) {
		store := NewEnvStoreWithMapping("", map[string]string{
			"github.token": "GITHUB_TOKEN",
		})

		os.Setenv("GITHUB_TOKEN", "gh-token")
		defer os.Unsetenv("GITHUB_TOKEN")

		cred, err := store.Get(ctx, "github.token")
		if err != nil {
			t.Fatalf("Get with mapping failed: %v", err)
		}

		if cred.Value != "gh-token" {
			t.Errorf("Value = %v, want %v", cred.Value, "gh-token")
		}
	})
}

func TestFileStore(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "credentials.json")

	store, err := NewFileStore(filePath)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	t.Run("Set and Get", func(t *testing.T) {
		cred := &Credential{
			Type:  CredentialTypeToken,
			Value: "test-token",
		}

		err := store.Set(ctx, "test-key", cred)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		got, err := store.Get(ctx, "test-key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if got.Value != "test-token" {
			t.Errorf("Value = %v, want %v", got.Value, "test-token")
		}
	})

	t.Run("Persistence", func(t *testing.T) {
		// Create new store pointing to same file
		store2, err := NewFileStore(filePath)
		if err != nil {
			t.Fatalf("NewFileStore failed: %v", err)
		}

		got, err := store2.Get(ctx, "test-key")
		if err != nil {
			t.Fatalf("Get from new store failed: %v", err)
		}

		if got.Value != "test-token" {
			t.Errorf("Persisted value = %v, want %v", got.Value, "test-token")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := store.Delete(ctx, "test-key")
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = store.Get(ctx, "test-key")
		if err != ErrCredentialNotFound {
			t.Error("Get after delete should return ErrCredentialNotFound")
		}
	})
}

func TestChainedStore(t *testing.T) {
	ctx := context.Background()

	env := NewEnvStore("CHAIN_")
	mem := NewMemoryStore()

	// Set up env var
	os.Setenv("CHAIN_ENV_KEY", "env-value")
	defer os.Unsetenv("CHAIN_ENV_KEY")

	// Set up memory store
	mem.Set(ctx, "mem-key", &Credential{Value: "mem-value"})
	mem.Set(ctx, "env.key", &Credential{Value: "mem-override"}) // This should NOT be used

	chain := NewChainedStore(env, mem)

	t.Run("Get from first store", func(t *testing.T) {
		cred, err := chain.Get(ctx, "env.key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		// Should get from env store first
		if cred.Value != "env-value" {
			t.Errorf("Value = %v, want %v (from env)", cred.Value, "env-value")
		}
	})

	t.Run("Fallback to second store", func(t *testing.T) {
		cred, err := chain.Get(ctx, "mem-key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if cred.Value != "mem-value" {
			t.Errorf("Value = %v, want %v", cred.Value, "mem-value")
		}
	})

	t.Run("Not found in any store", func(t *testing.T) {
		_, err := chain.Get(ctx, "non-existent")
		if err != ErrCredentialNotFound {
			t.Errorf("Get non-existent = %v, want ErrCredentialNotFound", err)
		}
	})

	t.Run("Set to first writable store", func(t *testing.T) {
		err := chain.Set(ctx, "new-key", &Credential{Value: "new-value"})
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		// Should be in memory store (env is read-only)
		cred, err := mem.Get(ctx, "new-key")
		if err != nil {
			t.Fatalf("Get from mem failed: %v", err)
		}

		if cred.Value != "new-value" {
			t.Errorf("Value = %v, want %v", cred.Value, "new-value")
		}
	})

	t.Run("Exists checks all stores", func(t *testing.T) {
		exists, err := chain.Exists(ctx, "env.key")
		if err != nil {
			t.Fatalf("Exists failed: %v", err)
		}
		if !exists {
			t.Error("Exists should return true for key in env store")
		}

		exists, err = chain.Exists(ctx, "mem-key")
		if err != nil {
			t.Fatalf("Exists failed: %v", err)
		}
		if !exists {
			t.Error("Exists should return true for key in mem store")
		}
	})

	t.Run("List combines all stores", func(t *testing.T) {
		keys, err := chain.List(ctx, "")
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		// Should have keys from both stores
		if len(keys) < 2 {
			t.Errorf("List = %d items, want >= 2", len(keys))
		}
	})
}

func TestCredential(t *testing.T) {
	t.Run("IsExpired with nil", func(t *testing.T) {
		cred := &Credential{Value: "test"}
		if cred.IsExpired() {
			t.Error("Credential with nil ExpiresAt should not be expired")
		}
	})

	t.Run("IsExpired with future date", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		cred := &Credential{Value: "test", ExpiresAt: &future}
		if cred.IsExpired() {
			t.Error("Credential with future expiry should not be expired")
		}
	})

	t.Run("IsExpired with past date", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour)
		cred := &Credential{Value: "test", ExpiresAt: &past}
		if !cred.IsExpired() {
			t.Error("Credential with past expiry should be expired")
		}
	})
}

func TestDefaultStore(t *testing.T) {
	// Default should be EnvStore
	store := GetDefaultStore()
	if store == nil {
		t.Error("Default store should not be nil")
	}

	// Set a custom store
	custom := NewMemoryStore()
	SetDefaultStore(custom)

	if GetDefaultStore() != custom {
		t.Error("Default store should be the custom store")
	}

	// Set nil should reset to EnvStore with OPENCTEMIO_ prefix
	SetDefaultStore(nil)
	if _, ok := GetDefaultStore().(*EnvStore); !ok {
		t.Error("Default store should be EnvStore after setting nil")
	}
}

func TestStoreFromContext(t *testing.T) {
	custom := NewMemoryStore()
	ctx := WithStore(context.Background(), custom)

	if StoreFromContext(ctx) != custom {
		t.Error("StoreFromContext should return the custom store")
	}

	// Without context, should return default
	if StoreFromContext(context.Background()) != GetDefaultStore() {
		t.Error("StoreFromContext should return default when not set")
	}
}

func TestGetValue(t *testing.T) {
	ctx := context.Background()

	// Set up env var
	os.Setenv("OPENCTEMIO_TEST_VALUE", "my-value")
	defer os.Unsetenv("OPENCTEMIO_TEST_VALUE")

	value, err := GetValue(ctx, "test.value")
	if err != nil {
		t.Fatalf("GetValue failed: %v", err)
	}

	if value != "my-value" {
		t.Errorf("GetValue = %v, want %v", value, "my-value")
	}
}

// =============================================================================
// Key Validation Tests
// =============================================================================

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid simple", "api-key", false},
		{"valid with dots", "github.api.token", false},
		{"valid with underscores", "my_secret_key", false},
		{"valid alphanumeric", "key123", false},
		{"empty", "", true},
		{"path traversal dotdot", "../etc/passwd", true},
		{"path traversal slash", "foo/bar", true},
		{"path traversal backslash", "foo\\bar", true},
		{"starts with dot", ".hidden", true},
		{"starts with dash", "-invalid", true},
		{"special chars", "key@#$", true},
		{"too long", string(make([]byte, 300)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// AES Encryption Tests
// =============================================================================

func TestAESEncryptor(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		for _, size := range []int{16, 24, 32} {
			key := make([]byte, size)
			_, err := NewAESEncryptor(key)
			if err != nil {
				t.Errorf("NewAESEncryptor with %d byte key failed: %v", size, err)
			}
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		key := make([]byte, 15)
		_, err := NewAESEncryptor(key)
		if err == nil {
			t.Error("NewAESEncryptor should fail with 15 byte key")
		}
	})

	t.Run("encrypt decrypt roundtrip", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}

		enc, err := NewAESEncryptor(key)
		if err != nil {
			t.Fatalf("NewAESEncryptor failed: %v", err)
		}

		plaintext := []byte("secret data")
		ciphertext, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		// Ciphertext should be different from plaintext
		if string(ciphertext) == string(plaintext) {
			t.Error("Ciphertext should not equal plaintext")
		}

		decrypted, err := enc.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("different ciphertexts for same plaintext", func(t *testing.T) {
		key := make([]byte, 32)
		enc, _ := NewAESEncryptor(key)

		plaintext := []byte("same data")
		ct1, _ := enc.Encrypt(plaintext)
		ct2, _ := enc.Encrypt(plaintext)

		// Should produce different ciphertexts due to random nonce
		if string(ct1) == string(ct2) {
			t.Error("Same plaintext should produce different ciphertexts")
		}
	})

	t.Run("decrypt with wrong key fails", func(t *testing.T) {
		key1 := make([]byte, 32)
		key2 := make([]byte, 32)
		key2[0] = 1 // Different key

		enc1, _ := NewAESEncryptor(key1)
		enc2, _ := NewAESEncryptor(key2)

		ciphertext, _ := enc1.Encrypt([]byte("secret"))

		_, err := enc2.Decrypt(ciphertext)
		if err == nil {
			t.Error("Decrypt with wrong key should fail")
		}
	})

	t.Run("decrypt short ciphertext fails", func(t *testing.T) {
		key := make([]byte, 32)
		enc, _ := NewAESEncryptor(key)

		_, err := enc.Decrypt([]byte("short"))
		if err == nil {
			t.Error("Decrypt with short ciphertext should fail")
		}
	})
}

// =============================================================================
// Encrypted File Store Tests
// =============================================================================

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{"equal strings", "secret123", "secret123", true},
		{"different strings", "secret123", "secret456", false},
		{"different lengths", "short", "longer", false},
		{"empty strings", "", "", true},
		{"one empty", "secret", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecureCompare(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("SecureCompare(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestSecureClear(t *testing.T) {
	t.Run("clears credential fields", func(t *testing.T) {
		cred := &Credential{
			Key:            "test-key",
			Value:          "secret-value",
			SecondaryValue: "secondary-secret",
			Metadata:       map[string]string{"foo": "bar"},
		}

		SecureClear(cred)

		if cred.Key != "" {
			t.Errorf("Key should be empty after SecureClear")
		}
		if cred.Value != "" {
			t.Errorf("Value should be empty after SecureClear")
		}
		if cred.SecondaryValue != "" {
			t.Errorf("SecondaryValue should be empty after SecureClear")
		}
		if cred.Metadata != nil {
			t.Errorf("Metadata should be nil after SecureClear")
		}
	})

	t.Run("handles nil credential", func(t *testing.T) {
		// Should not panic
		SecureClear(nil)
	})
}

func TestEncryptedFileStore(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "credentials.enc")

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	encryptor, _ := NewAESEncryptor(key)

	t.Run("nil encryptor fails", func(t *testing.T) {
		_, err := NewEncryptedFileStore(filePath, nil)
		if err == nil {
			t.Error("NewEncryptedFileStore with nil encryptor should fail")
		}
	})

	store, err := NewEncryptedFileStore(filePath, encryptor)
	if err != nil {
		t.Fatalf("NewEncryptedFileStore failed: %v", err)
	}

	t.Run("Set and Get", func(t *testing.T) {
		cred := &Credential{
			Type:  CredentialTypeAPIKey,
			Value: "encrypted-secret",
		}

		err := store.Set(ctx, "api.key", cred)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		got, err := store.Get(ctx, "api.key")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if got.Value != "encrypted-secret" {
			t.Errorf("Value = %v, want %v", got.Value, "encrypted-secret")
		}
	})

	t.Run("key validation on Get", func(t *testing.T) {
		_, err := store.Get(ctx, "../invalid")
		if err == nil {
			t.Error("Get with invalid key should fail")
		}
	})

	t.Run("key validation on Set", func(t *testing.T) {
		err := store.Set(ctx, "../invalid", &Credential{Value: "test"})
		if err == nil {
			t.Error("Set with invalid key should fail")
		}
	})

	t.Run("Persistence with encryption", func(t *testing.T) {
		// Create new store with same key
		store2, err := NewEncryptedFileStore(filePath, encryptor)
		if err != nil {
			t.Fatalf("NewEncryptedFileStore failed: %v", err)
		}

		got, err := store2.Get(ctx, "api.key")
		if err != nil {
			t.Fatalf("Get from new store failed: %v", err)
		}

		if got.Value != "encrypted-secret" {
			t.Errorf("Persisted value = %v, want %v", got.Value, "encrypted-secret")
		}
	})

	t.Run("Cannot decrypt with wrong key", func(t *testing.T) {
		wrongKey := make([]byte, 32)
		wrongKey[0] = 99
		wrongEnc, _ := NewAESEncryptor(wrongKey)

		_, err := NewEncryptedFileStore(filePath, wrongEnc)
		if err == nil {
			t.Error("Should fail to load with wrong encryption key")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := store.Delete(ctx, "api.key")
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = store.Get(ctx, "api.key")
		if err != ErrCredentialNotFound {
			t.Error("Get after delete should return ErrCredentialNotFound")
		}
	})

	t.Run("List", func(t *testing.T) {
		store.Set(ctx, "prefix.a", &Credential{Value: "a"})
		store.Set(ctx, "prefix.b", &Credential{Value: "b"})
		store.Set(ctx, "other.c", &Credential{Value: "c"})

		keys, err := store.List(ctx, "prefix.")
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if len(keys) != 2 {
			t.Errorf("List = %d items, want 2", len(keys))
		}
	})

	t.Run("Exists", func(t *testing.T) {
		exists, err := store.Exists(ctx, "prefix.a")
		if err != nil {
			t.Fatalf("Exists failed: %v", err)
		}
		if !exists {
			t.Error("Exists should return true for existing key")
		}

		exists, err = store.Exists(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("Exists failed: %v", err)
		}
		if exists {
			t.Error("Exists should return false for non-existent key")
		}
	})
}
