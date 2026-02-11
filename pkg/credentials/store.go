// Package credentials provides credential management for the OpenCTEM SDK.
// It includes interfaces for credential storage and retrieval, with
// implementations for environment variables, files, and external vaults.
package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Store Interface
// =============================================================================

// Store is the interface for credential storage and retrieval.
// Implement this interface to use custom credential backends (Vault, AWS Secrets Manager, etc.).
type Store interface {
	// Get retrieves a credential by key.
	Get(ctx context.Context, key string) (*Credential, error)

	// Set stores a credential.
	Set(ctx context.Context, key string, cred *Credential) error

	// Delete removes a credential.
	Delete(ctx context.Context, key string) error

	// List returns all credential keys matching a prefix.
	List(ctx context.Context, prefix string) ([]string, error)

	// Exists checks if a credential exists.
	Exists(ctx context.Context, key string) (bool, error)
}

// =============================================================================
// Credential Types
// =============================================================================

// Credential represents a stored credential.
type Credential struct {
	// Key is the credential identifier
	Key string `json:"key"`

	// Type categorizes the credential (api_key, token, password, certificate, etc.)
	Type CredentialType `json:"type"`

	// Value is the actual credential value
	Value string `json:"value"`

	// SecondaryValue holds additional values (e.g., client_secret for OAuth)
	SecondaryValue string `json:"secondary_value,omitempty"`

	// Metadata holds additional credential information
	Metadata map[string]string `json:"metadata,omitempty"`

	// ExpiresAt is the credential expiration time (if applicable)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// CreatedAt is when the credential was stored
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the credential was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// CredentialType represents the type of credential.
type CredentialType string

const (
	CredentialTypeAPIKey      CredentialType = "api_key"
	CredentialTypeToken       CredentialType = "token"
	CredentialTypePassword    CredentialType = "password"
	CredentialTypeOAuth       CredentialType = "oauth"
	CredentialTypeCertificate CredentialType = "certificate"
	CredentialTypeSSHKey      CredentialType = "ssh_key"
	CredentialTypeSecret      CredentialType = "secret"
)

// IsExpired checks if the credential has expired.
func (c *Credential) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// =============================================================================
// Environment Store - Reads from environment variables
// =============================================================================

// EnvStore implements Store using environment variables.
// It's the simplest store implementation and suitable for CI/CD environments.
type EnvStore struct {
	// Prefix is prepended to all key lookups (e.g., "OPENCTEM_")
	Prefix string

	// Mapping overrides key-to-env-var mapping
	Mapping map[string]string
}

// NewEnvStore creates a new environment variable credential store.
func NewEnvStore(prefix string) *EnvStore {
	return &EnvStore{
		Prefix:  prefix,
		Mapping: make(map[string]string),
	}
}

// NewEnvStoreWithMapping creates a new environment store with custom mapping.
func NewEnvStoreWithMapping(prefix string, mapping map[string]string) *EnvStore {
	return &EnvStore{
		Prefix:  prefix,
		Mapping: mapping,
	}
}

func (s *EnvStore) envKey(key string) string {
	if mapped, ok := s.Mapping[key]; ok {
		return mapped
	}
	// Convert key to uppercase with underscores
	envKey := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	envKey = strings.ReplaceAll(envKey, "-", "_")
	if s.Prefix != "" {
		return s.Prefix + envKey
	}
	return envKey
}

func (s *EnvStore) Get(ctx context.Context, key string) (*Credential, error) {
	envKey := s.envKey(key)
	value := os.Getenv(envKey)
	if value == "" {
		return nil, ErrCredentialNotFound
	}

	return &Credential{
		Key:       key,
		Type:      CredentialTypeSecret,
		Value:     value,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (s *EnvStore) Set(ctx context.Context, key string, cred *Credential) error {
	return ErrReadOnly
}

func (s *EnvStore) Delete(ctx context.Context, key string) error {
	return ErrReadOnly
}

func (s *EnvStore) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	searchPrefix := s.envKey(prefix)

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && strings.HasPrefix(parts[0], searchPrefix) {
			keys = append(keys, parts[0])
		}
	}

	return keys, nil
}

func (s *EnvStore) Exists(ctx context.Context, key string) (bool, error) {
	envKey := s.envKey(key)
	_, exists := os.LookupEnv(envKey)
	return exists, nil
}

// =============================================================================
// Memory Store - In-memory credential storage
// =============================================================================

// MemoryStore implements Store using in-memory storage.
// Useful for testing and development.
type MemoryStore struct {
	mu          sync.RWMutex
	credentials map[string]*Credential
}

// NewMemoryStore creates a new in-memory credential store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		credentials: make(map[string]*Credential),
	}
}

func (s *MemoryStore) Get(ctx context.Context, key string) (*Credential, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, ok := s.credentials[key]
	if !ok {
		return nil, ErrCredentialNotFound
	}

	// Return a copy
	credCopy := *cred
	return &credCopy, nil
}

func (s *MemoryStore) Set(ctx context.Context, key string, cred *Credential) error {
	if err := ValidateKey(key); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cred.Key = key
	cred.UpdatedAt = now
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = now
	}

	// Store a copy
	credCopy := *cred
	s.credentials[key] = &credCopy

	return nil
}

func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.credentials[key]
	if !ok {
		return ErrCredentialNotFound
	}

	// Secure memory clearing before deletion
	SecureClear(cred)
	delete(s.credentials, key)
	return nil
}

func (s *MemoryStore) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []string
	for key := range s.credentials {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (s *MemoryStore) Exists(ctx context.Context, key string) (bool, error) {
	if err := ValidateKey(key); err != nil {
		return false, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.credentials[key]
	return ok, nil
}

// =============================================================================
// File Store - File-based credential storage
// =============================================================================

// FileStore implements Store using a JSON file.
// Suitable for local development, NOT recommended for production.
type FileStore struct {
	mu       sync.RWMutex
	filePath string
	data     map[string]*Credential
}

// NewFileStore creates a new file-based credential store.
func NewFileStore(filePath string) (*FileStore, error) {
	store := &FileStore{
		filePath: filePath,
		data:     make(map[string]*Credential),
	}

	// Load existing data if file exists
	if _, err := os.Stat(filePath); err == nil {
		if err := store.load(); err != nil {
			return nil, fmt.Errorf("failed to load credentials file: %w", err)
		}
	}

	return store, nil
}

func (s *FileStore) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &s.data)
}

func (s *FileStore) save() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, data, 0600)
}

func (s *FileStore) Get(ctx context.Context, key string) (*Credential, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, ok := s.data[key]
	if !ok {
		return nil, ErrCredentialNotFound
	}

	credCopy := *cred
	return &credCopy, nil
}

func (s *FileStore) Set(ctx context.Context, key string, cred *Credential) error {
	if err := ValidateKey(key); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cred.Key = key
	cred.UpdatedAt = now
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = now
	}

	credCopy := *cred
	s.data[key] = &credCopy

	return s.save()
}

func (s *FileStore) Delete(ctx context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.data[key]
	if !ok {
		return ErrCredentialNotFound
	}

	// Secure memory clearing before deletion
	SecureClear(cred)
	delete(s.data, key)
	return s.save()
}

func (s *FileStore) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []string
	for key := range s.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (s *FileStore) Exists(ctx context.Context, key string) (bool, error) {
	if err := ValidateKey(key); err != nil {
		return false, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.data[key]
	return ok, nil
}

// =============================================================================
// Chained Store - Fallback chain of stores
// =============================================================================

// ChainedStore implements Store by checking multiple stores in order.
// Useful for layering local overrides on top of a central store.
type ChainedStore struct {
	stores []Store
}

// NewChainedStore creates a new chained credential store.
// Stores are checked in order - first match wins.
func NewChainedStore(stores ...Store) *ChainedStore {
	return &ChainedStore{stores: stores}
}

func (s *ChainedStore) Get(ctx context.Context, key string) (*Credential, error) {
	for _, store := range s.stores {
		cred, err := store.Get(ctx, key)
		if err == nil {
			return cred, nil
		}
		if err != ErrCredentialNotFound {
			return nil, err
		}
	}
	return nil, ErrCredentialNotFound
}

func (s *ChainedStore) Set(ctx context.Context, key string, cred *Credential) error {
	// Set to the first writable store
	for _, store := range s.stores {
		err := store.Set(ctx, key, cred)
		if err == nil {
			return nil
		}
		if err != ErrReadOnly {
			return err
		}
	}
	return ErrReadOnly
}

func (s *ChainedStore) Delete(ctx context.Context, key string) error {
	// Delete from the first writable store that has it
	for _, store := range s.stores {
		exists, err := store.Exists(ctx, key)
		if err != nil {
			continue
		}
		if !exists {
			continue
		}

		err = store.Delete(ctx, key)
		if err == nil {
			return nil
		}
		if err != ErrReadOnly {
			return err
		}
	}
	return ErrCredentialNotFound
}

func (s *ChainedStore) List(ctx context.Context, prefix string) ([]string, error) {
	seen := make(map[string]bool)
	var keys []string

	for _, store := range s.stores {
		storeKeys, err := store.List(ctx, prefix)
		if err != nil {
			continue
		}
		for _, key := range storeKeys {
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}

	return keys, nil
}

func (s *ChainedStore) Exists(ctx context.Context, key string) (bool, error) {
	for _, store := range s.stores {
		exists, err := store.Exists(ctx, key)
		if err != nil {
			continue
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// =============================================================================
// Global Default Store
// =============================================================================

var defaultStore Store
var defaultStoreMu sync.RWMutex

func init() {
	// Default to environment store with OPENCTEMIO_ prefix
	defaultStore = NewEnvStore("OPENCTEMIO_")
}

// SetDefaultStore sets the global default credential store.
func SetDefaultStore(store Store) {
	defaultStoreMu.Lock()
	defer defaultStoreMu.Unlock()
	if store == nil {
		store = NewEnvStore("OPENCTEMIO_")
	}
	defaultStore = store
}

// GetDefaultStore returns the global default credential store.
func GetDefaultStore() Store {
	defaultStoreMu.RLock()
	defer defaultStoreMu.RUnlock()
	return defaultStore
}

// Get retrieves a credential from the default store.
func Get(ctx context.Context, key string) (*Credential, error) {
	return GetDefaultStore().Get(ctx, key)
}

// MustGet retrieves a credential from the default store, panicking on error.
func MustGet(ctx context.Context, key string) *Credential {
	cred, err := Get(ctx, key)
	if err != nil {
		panic(fmt.Sprintf("credential %q not found: %v", key, err))
	}
	return cred
}

// GetValue retrieves just the value from the default store.
func GetValue(ctx context.Context, key string) (string, error) {
	cred, err := GetDefaultStore().Get(ctx, key)
	if err != nil {
		return "", err
	}
	return cred.Value, nil
}

// =============================================================================
// Context-based Store
// =============================================================================

type contextKey string

const storeContextKey contextKey = "openctem_credential_store"

// WithStore returns a new context with the store attached.
func WithStore(ctx context.Context, store Store) context.Context {
	return context.WithValue(ctx, storeContextKey, store)
}

// StoreFromContext returns the store from the context, or the default.
func StoreFromContext(ctx context.Context) Store {
	if store, ok := ctx.Value(storeContextKey).(Store); ok {
		return store
	}
	return GetDefaultStore()
}

// =============================================================================
// Errors
// =============================================================================

// Common errors for credential operations.
var (
	ErrCredentialNotFound = fmt.Errorf("credential not found")
	ErrReadOnly           = fmt.Errorf("store is read-only")
	ErrInvalidCredential  = fmt.Errorf("invalid credential")
	ErrInvalidKey         = fmt.Errorf("invalid credential key")
	ErrEncryptionFailed   = fmt.Errorf("encryption failed")
	ErrDecryptionFailed   = fmt.Errorf("decryption failed")
)

// =============================================================================
// Secure Memory Operations
// =============================================================================

// SecureClear overwrites sensitive credential data with zeros.
// This helps prevent credential leakage through memory dumps.
// Note: Due to Go's string immutability, this may not fully clear
// all copies of the string data, but it clears the primary references.
func SecureClear(cred *Credential) {
	if cred == nil {
		return
	}
	// Clear the string data by overwriting with zeros
	// This is a best-effort approach in Go due to string immutability
	clearString(&cred.Value)
	clearString(&cred.SecondaryValue)
	clearString(&cred.Key)
	cred.Metadata = nil
	cred.ExpiresAt = nil
}

// clearString attempts to clear a string's data.
// Due to Go's string immutability, this creates a new empty string.
func clearString(s *string) {
	*s = ""
}

// SecureCompare performs a constant-time comparison of two credential values.
// This prevents timing attacks when comparing secrets.
func SecureCompare(a, b string) bool {
	// Use constant-time comparison to prevent timing attacks
	if len(a) != len(b) {
		// Still do a comparison to maintain constant time
		_ = subtleConstantTimeCompare([]byte(a), []byte(strings.Repeat("x", len(a))))
		return false
	}
	// Handle empty strings
	if len(a) == 0 {
		return true
	}
	return subtleConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// subtleConstantTimeCompare is a constant-time bytes comparison.
// Returns 1 if equal, 0 otherwise.
func subtleConstantTimeCompare(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}
	if len(x) == 0 {
		return 1
	}
	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}
	// If v is 0 (all bytes equal), return 1; otherwise return 0
	if v == 0 {
		return 1
	}
	return 0
}

// =============================================================================
// Key Validation
// =============================================================================

// keyPattern defines valid credential key format.
// Keys must be alphanumeric with dots, dashes, and underscores.
// No path traversal characters allowed.
var keyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// ValidateKey checks if a credential key is valid and safe.
// Returns ErrInvalidKey if the key contains unsafe characters.
func ValidateKey(key string) error {
	if key == "" {
		return ErrInvalidKey
	}
	if len(key) > 256 {
		return fmt.Errorf("%w: key too long (max 256 characters)", ErrInvalidKey)
	}
	// Check for path traversal attempts
	if strings.Contains(key, "..") || strings.Contains(key, "/") || strings.Contains(key, "\\") {
		return fmt.Errorf("%w: path traversal not allowed", ErrInvalidKey)
	}
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("%w: invalid characters in key", ErrInvalidKey)
	}
	return nil
}

// =============================================================================
// Encryption Support
// =============================================================================

// Encryptor provides encryption/decryption for credential values.
type Encryptor interface {
	// Encrypt encrypts plaintext and returns ciphertext.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext and returns plaintext.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// AESEncryptor implements Encryptor using AES-GCM.
type AESEncryptor struct {
	key []byte
}

// NewAESEncryptor creates a new AES-GCM encryptor.
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func NewAESEncryptor(key []byte) (*AESEncryptor, error) {
	switch len(key) {
	case 16, 24, 32:
		return &AESEncryptor{key: key}, nil
	default:
		return nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}
}

// NewAESEncryptorFromEnv creates an AES encryptor from an environment variable.
// The key should be base64-encoded.
func NewAESEncryptorFromEnv(envVar string) (*AESEncryptor, error) {
	keyStr := os.Getenv(envVar)
	if keyStr == "" {
		return nil, fmt.Errorf("encryption key not found in environment variable %s", envVar)
	}
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}
	return NewAESEncryptor(key)
}

func (e *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (e *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecryptionFailed)
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// =============================================================================
// Encrypted File Store
// =============================================================================

// EncryptedFileStore implements Store using an encrypted JSON file.
// This is a secure alternative to FileStore for storing credentials at rest.
type EncryptedFileStore struct {
	mu        sync.RWMutex
	filePath  string
	encryptor Encryptor
	data      map[string]*Credential
}

// NewEncryptedFileStore creates a new encrypted file-based credential store.
func NewEncryptedFileStore(filePath string, encryptor Encryptor) (*EncryptedFileStore, error) {
	if encryptor == nil {
		return nil, fmt.Errorf("encryptor is required")
	}

	store := &EncryptedFileStore{
		filePath:  filePath,
		encryptor: encryptor,
		data:      make(map[string]*Credential),
	}

	// Load existing data if file exists
	if _, err := os.Stat(filePath); err == nil {
		if err := store.load(); err != nil {
			return nil, fmt.Errorf("failed to load encrypted credentials file: %w", err)
		}
	}

	return store, nil
}

func (s *EncryptedFileStore) load() error {
	ciphertext, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	plaintext, err := s.encryptor.Decrypt(ciphertext)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, &s.data)
}

func (s *EncryptedFileStore) save() error {
	plaintext, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}

	ciphertext, err := s.encryptor.Encrypt(plaintext)
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, ciphertext, 0600)
}

func (s *EncryptedFileStore) Get(ctx context.Context, key string) (*Credential, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, ok := s.data[key]
	if !ok {
		return nil, ErrCredentialNotFound
	}

	credCopy := *cred
	return &credCopy, nil
}

func (s *EncryptedFileStore) Set(ctx context.Context, key string, cred *Credential) error {
	if err := ValidateKey(key); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cred.Key = key
	cred.UpdatedAt = now
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = now
	}

	credCopy := *cred
	s.data[key] = &credCopy

	return s.save()
}

func (s *EncryptedFileStore) Delete(ctx context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[key]; !ok {
		return ErrCredentialNotFound
	}

	delete(s.data, key)
	return s.save()
}

func (s *EncryptedFileStore) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []string
	for key := range s.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (s *EncryptedFileStore) Exists(ctx context.Context, key string) (bool, error) {
	if err := ValidateKey(key); err != nil {
		return false, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.data[key]
	return ok, nil
}

// =============================================================================
// Interface Compliance
// =============================================================================

var (
	_ Store     = (*EnvStore)(nil)
	_ Store     = (*MemoryStore)(nil)
	_ Store     = (*FileStore)(nil)
	_ Store     = (*ChainedStore)(nil)
	_ Store     = (*EncryptedFileStore)(nil)
	_ Encryptor = (*AESEncryptor)(nil)
)
