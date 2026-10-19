package localstore

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// SensorTenant is the tenant of an organization sensor's own records (it
// works for one organization). A shared sensor uses the organization id of
// each job's verified signed statement.
const SensorTenant = "_sensor"

// Limits.
const (
	// maxRecordBytes bounds one record's plaintext: the store holds small
	// state (journal entries, policy snapshots, indexes), not results.
	maxRecordBytes = 16 << 20
	// maxNameLen bounds tenant, namespace and record names.
	maxNameLen = 128
	// maxCorruptKept bounds the quarantine.
	maxCorruptKept = 200

	masterKeyName   = "master.key"
	masterKeyHeader = "openctem-store-key-v1\n"
	metaName        = "meta.rec"
	lockName        = ".lock"
	dirKeys         = "keys"
	dirKV           = "kv"
	dirCorrupt      = "corrupt"
	dirTmp          = "tmp"
	recExt          = ".rec"
	keyExt          = ".key"
)

// Errors.
var (
	// ErrLocked: another process holds the store directory.
	ErrLocked = errors.New("localstore: directory is in use by another process")
	// ErrClosed: the store was closed.
	ErrClosed = errors.New("localstore: closed")
	// ErrKeyMissing: the master key is missing while the store holds wrapped
	// tenant keys sealed with one. Open refuses rather than create a new key.
	ErrKeyMissing = errors.New("localstore: master key is missing but sealed tenant keys exist")
	// ErrKeyFile: the master key file is unusable (wrong format, a mode that
	// lets others write or read it, another owner).
	ErrKeyFile = errors.New("localstore: master key file refused")
	// ErrNotFound: no such record.
	ErrNotFound = errors.New("localstore: record not found")
	// ErrExpired: the record's expiry passed. Its data is not returned:
	// callers holding scope-bearing data fail closed.
	ErrExpired = errors.New("localstore: record expired")
	// ErrTampered: the record failed authentication and was quarantined.
	ErrTampered = errors.New("localstore: record failed authentication (quarantined)")
	// ErrTooLarge: a record larger than the store accepts.
	ErrTooLarge = errors.New("localstore: record too large")
	// ErrDiskFull: the volume is below the critical free-space mark and the
	// write was not marked critical.
	ErrDiskFull = errors.New("localstore: disk space critically low")
	// ErrInvalidName: a tenant, namespace or record name outside the
	// allowed form.
	ErrInvalidName = errors.New("localstore: invalid name")
)

// nameRE is the form of tenant, namespace and record names: a file name on
// every platform, never "." or "..", never hidden.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

func validName(s string) error {
	if len(s) > maxNameLen || !nameRE.MatchString(s) || strings.Contains(s, "..") {
		return fmt.Errorf("%w: %q", ErrInvalidName, s)
	}
	return nil
}

// TamperEvent describes a record that failed authentication.
type TamperEvent struct {
	At        time.Time `json:"at"`
	Tenant    string    `json:"tenant,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name,omitempty"`
	Reason    string    `json:"reason"`
}

// Options configure a Store. Dir is required.
type Options struct {
	// Dir is the store directory, created 0700 if missing.
	Dir string
	// KeyFile is the master key file. Set it to a mounted secret to keep
	// the key off the data volume; it must then exist (unless CreateKey).
	// Empty: <Dir>/master.key, created on first use.
	KeyFile string
	// CreateKey creates a missing KeyFile (ignored for the default file,
	// which is always created).
	CreateKey bool
	// MinFreeBytes and MinFreeFraction set DiskLow: free space below
	// max(MinFreeBytes, MinFreeFraction of the volume). Defaults 256 MiB and
	// 5 %.
	MinFreeBytes    int64
	MinFreeFraction float64
	// CriticalFreeBytes sets DiskCritical. Default 64 MiB.
	CriticalFreeBytes int64
	// OnTamper is called (without locks held) for every record that failed
	// authentication. Turn it into a heartbeat signal.
	OnTamper func(TamperEvent)
	// Logf receives the store's log lines. Default: the standard logger.
	Logf func(format string, args ...any)

	now   func() time.Time
	space func(dir string) (space, bool)
}

// Stats are the store's counters since Open.
type Stats struct {
	// Boot is the boot generation: incremented by every Open and kept in a
	// sealed record. The platform remembers the last one it saw; a value
	// that goes back means an old copy of the store was restored.
	Boot uint64 `json:"boot"`
	// KeyOnDataVolume: the master key is the default file inside Dir.
	KeyOnDataVolume bool `json:"key_on_data_volume"`
	// Tampered counts records that failed authentication.
	Tampered   int64        `json:"tampered"`
	LastTamper *TamperEvent `json:"last_tamper,omitempty"`
	// Erased counts tenants erased.
	Erased int64 `json:"erased"`
}

// Store is an open local store. Safe for concurrent use.
type Store struct {
	opts   Options
	dir    string
	master cipher.AEAD
	unlock func()

	mu      sync.Mutex
	closed  bool
	tenants map[string]cipher.AEAD
	stats   Stats
}

// Open opens (creating if needed) the store directory, takes its lock,
// loads the master key and increments the boot generation.
func Open(opts Options) (*Store, error) {
	if strings.TrimSpace(opts.Dir) == "" {
		return nil, errors.New("localstore: Dir is required")
	}
	o := opts.withDefaults()
	dir := filepath.Clean(o.Dir)
	for _, d := range []string{dir, filepath.Join(dir, dirKeys), filepath.Join(dir, dirKV), filepath.Join(dir, dirCorrupt), filepath.Join(dir, dirTmp)} {
		if err := os.MkdirAll(d, dirMode); err != nil {
			return nil, fmt.Errorf("localstore: %w", err)
		}
		if err := os.Chmod(d, dirMode); err != nil { //nolint:gosec // a private store directory
			return nil, fmt.Errorf("localstore: %w", err)
		}
	}
	unlock, err := lockDir(filepath.Join(dir, lockName))
	if err != nil {
		return nil, err
	}
	s := &Store{opts: o, dir: dir, unlock: unlock, tenants: map[string]cipher.AEAD{}}
	if err := s.init(); err != nil {
		unlock()
		return nil, err
	}
	return s, nil
}

func (o Options) withDefaults() Options {
	if o.MinFreeBytes <= 0 {
		o.MinFreeBytes = 256 << 20
	}
	if o.MinFreeFraction <= 0 {
		o.MinFreeFraction = 0.05
	}
	if o.CriticalFreeBytes <= 0 {
		o.CriticalFreeBytes = 64 << 20
	}
	if o.Logf == nil {
		lg := log.New(os.Stderr, "", log.LstdFlags)
		o.Logf = func(format string, args ...any) { lg.Printf("[localstore] "+format, args...) }
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.space == nil {
		o.space = diskSpace
	}
	return o
}

func (s *Store) init() error {
	_ = s.cleanTmp()
	keyFile := s.opts.KeyFile
	create := s.opts.CreateKey
	if keyFile == "" {
		keyFile = filepath.Join(s.dir, masterKeyName)
		create = true
		s.stats.KeyOnDataVolume = true
	}
	key, err := loadKey(keyFile)
	if errors.Is(err, fs.ErrNotExist) {
		if s.hasWrappedKeys() {
			return ErrKeyMissing
		}
		if !create {
			return fmt.Errorf("%w: %s does not exist", ErrKeyFile, keyFile)
		}
		key, err = createKey(keyFile, filepath.Join(s.dir, dirTmp))
	}
	if err != nil {
		return err
	}
	if s.master, err = newAEAD(key); err != nil {
		return err
	}
	clear(key)
	return s.bumpBoot()
}

// cleanTmp removes leftovers of interrupted writes.
func (s *Store) cleanTmp() error {
	entries, err := os.ReadDir(filepath.Join(s.dir, dirTmp))
	if err != nil {
		return err
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(s.dir, dirTmp, e.Name()))
	}
	return nil
}

func (s *Store) hasWrappedKeys() bool {
	entries, _ := os.ReadDir(filepath.Join(s.dir, dirKeys))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), keyExt) {
			return true
		}
	}
	return false
}

// loadKey reads and checks a master key file.
func loadKey(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrKeyFile, path)
	}
	// Group read is tolerated (a Kubernetes secret mounted with fsGroup);
	// group write, any access by others, or another owner is not.
	if fi.Mode().Perm()&0o037 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o; use 0600 or 0400", ErrKeyFile, path, fi.Mode().Perm())
	}
	if fileOwnedByOther(fi) {
		return nil, fmt.Errorf("%w: %s belongs to another user", ErrKeyFile, path)
	}
	data, err := readBounded(path, 4096)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrKeyFile, path, err)
	}
	return parseKey(data)
}

func parseKey(data []byte) ([]byte, error) {
	rest, ok := strings.CutPrefix(string(data), masterKeyHeader)
	if !ok {
		return nil, fmt.Errorf("%w: not a store key file", ErrKeyFile)
	}
	key, err := hex.DecodeString(strings.TrimSpace(rest))
	if err != nil || len(key) != keyLen {
		return nil, fmt.Errorf("%w: malformed key", ErrKeyFile)
	}
	return key, nil
}

// FormatKey returns the master key file content for key (32 bytes), for an
// operator who provisions the key as a secret.
func FormatKey(key []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("localstore: key must be %d bytes", keyLen)
	}
	return []byte(masterKeyHeader + hex.EncodeToString(key) + "\n"), nil
}

func createKey(path, tmpDir string) ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("localstore: generate key: %w", err)
	}
	content, _ := FormatKey(key)
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, fmt.Errorf("localstore: key dir: %w", err)
	}
	// O_EXCL through a link: two processes creating a shared key file at
	// once must not end up with different keys.
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(tmpDir, "key."+hex.EncodeToString(rnd[:])+".tmp")
	if err := os.WriteFile(tmp, content, fileMode); err != nil {
		return nil, fmt.Errorf("localstore: write key: %w", err)
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return loadKey(path)
		}
		if err := os.Rename(tmp, path); err != nil {
			return nil, fmt.Errorf("localstore: install key: %w", err)
		}
	}
	_ = syncDir(filepath.Dir(path))
	return key, nil
}

type metaRecord struct {
	Boot    uint64    `json:"boot"`
	Created time.Time `json:"created"`
}

func (s *Store) bumpBoot() error {
	path := filepath.Join(s.dir, metaName)
	b := binding{purpose: "meta"}
	var m metaRecord
	data, err := readBounded(path, 4096)
	switch {
	case err == nil:
		pt, oerr := open(s.master, kindMeta, b, data)
		if oerr == nil && json.Unmarshal(pt, &m) == nil {
			break
		}
		m = metaRecord{}
		s.quarantine(path, TamperEvent{Name: metaName, Reason: "boot record failed authentication"})
	case errors.Is(err, fs.ErrNotExist):
		if s.hasWrappedKeys() {
			s.tamper(TamperEvent{Name: metaName, Reason: "boot record missing while tenant keys exist"})
		}
	default:
		return fmt.Errorf("localstore: read boot record: %w", err)
	}
	if m.Created.IsZero() {
		m.Created = s.opts.now().UTC()
	}
	m.Boot++
	pt, _ := json.Marshal(m)
	rec, err := seal(s.master, kindMeta, b, pt)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, dirTmp), path, rec); err != nil {
		return fmt.Errorf("localstore: write boot record: %w", err)
	}
	s.stats.Boot = m.Boot
	return nil
}

// Close releases the lock. Records already written stay.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.tenants = nil
	s.unlock()
	return nil
}

// Dir is the store directory.
func (s *Store) Dir() string { return s.dir }

// Stats returns the counters.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	if st.LastTamper != nil {
		ev := *st.LastTamper
		st.LastTamper = &ev
	}
	return st
}

func (s *Store) keyPath(tenant string) string {
	return filepath.Join(s.dir, dirKeys, tenant+keyExt)
}

// tenantAEAD returns the tenant's data key, creating it on first use.
func (s *Store) tenantAEAD(tenant string) (cipher.AEAD, error) {
	if err := validName(tenant); err != nil {
		return nil, err
	}
	a, err := s.tenantAEADLocked(tenant)
	if errors.Is(err, errAuth) {
		// A wrapped key that does not open under this master key is never
		// replaced silently: that would orphan the tenant's records.
		s.tamper(TamperEvent{Tenant: tenant, Reason: "tenant key failed authentication"})
		return nil, fmt.Errorf("%w: tenant key of %s", ErrTampered, tenant)
	}
	return a, err
}

func (s *Store) tenantAEADLocked(tenant string) (cipher.AEAD, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if a, ok := s.tenants[tenant]; ok {
		return a, nil
	}
	key, err := s.loadTenantKey(tenant)
	if errors.Is(err, fs.ErrNotExist) {
		// No key: any data left for the tenant was erased (or its key was
		// removed by someone else); it can never be read again, so it goes.
		s.removeTenantData(tenant)
		key = make([]byte, keyLen)
		if _, err = rand.Read(key); err != nil {
			return nil, fmt.Errorf("localstore: generate tenant key: %w", err)
		}
		err = s.writeTenantKey(tenant, key)
	}
	if err != nil {
		return nil, err
	}
	a, err := newAEAD(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	s.tenants[tenant] = a
	return a, nil
}

// loadTenantKey unwraps a tenant's data key; errAuth when it does not open.
func (s *Store) loadTenantKey(tenant string) ([]byte, error) {
	data, err := readBounded(s.keyPath(tenant), 1024)
	if err != nil {
		return nil, err
	}
	key, err := open(s.master, kindWrappedKey, binding{purpose: "tenant-key", tenant: tenant}, data)
	if err != nil || len(key) != keyLen {
		return nil, errAuth
	}
	return key, nil
}

func (s *Store) writeTenantKey(tenant string, key []byte) error {
	rec, err := seal(s.master, kindWrappedKey, binding{purpose: "tenant-key", tenant: tenant}, key)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, dirTmp), s.keyPath(tenant), rec)
}

// AdoptTenantKey makes key (32 bytes) the tenant's data key when the tenant
// has none yet: an existing outbox key becomes the organization sensor's
// key without re-encrypting anything. It refuses to replace a key.
func (s *Store) AdoptTenantKey(tenant string, key []byte) error {
	if err := validName(tenant); err != nil {
		return err
	}
	if len(key) != keyLen {
		return fmt.Errorf("localstore: key must be %d bytes", keyLen)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, err := os.Stat(s.keyPath(tenant)); err == nil {
		return fmt.Errorf("localstore: tenant %s already has a key", tenant)
	}
	if err := s.writeTenantKey(tenant, key); err != nil {
		return err
	}
	a, err := newAEAD(key)
	if err != nil {
		return err
	}
	s.tenants[tenant] = a
	return nil
}

// Tenants lists the tenants that have a data key, sorted.
func (s *Store) Tenants() []string {
	entries, _ := os.ReadDir(filepath.Join(s.dir, dirKeys))
	var out []string
	for _, e := range entries {
		if t, ok := strings.CutSuffix(e.Name(), keyExt); ok && validName(t) == nil {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// EraseTenant crypto-erases a tenant: its wrapped data key is deleted (and
// the deletion fsynced) before its records are removed, so a record that
// survives anywhere can no longer be decrypted. Erasing a tenant without
// data is not an error.
func (s *Store) EraseTenant(tenant string) error {
	if err := validName(tenant); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	delete(s.tenants, tenant)
	if err := os.Remove(s.keyPath(tenant)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("localstore: erase key of %s: %w", tenant, err)
	}
	if err := syncDir(filepath.Join(s.dir, dirKeys)); err != nil {
		return fmt.Errorf("localstore: erase key of %s: %w", tenant, err)
	}
	s.removeTenantData(tenant)
	s.stats.Erased++
	s.opts.Logf("tenant %s erased (data key deleted, records removed)", tenant)
	return nil
}

// removeTenantData removes a tenant's records (best effort). Called with
// s.mu held.
func (s *Store) removeTenantData(tenant string) {
	_ = os.RemoveAll(filepath.Join(s.dir, dirKV, tenant))
	_ = syncDir(filepath.Join(s.dir, dirKV))
}

// tamper records a tamper event (s.mu must not be held).
func (s *Store) tamper(ev TamperEvent) {
	if ev.At.IsZero() {
		ev.At = s.opts.now().UTC()
	}
	s.mu.Lock()
	s.stats.Tampered++
	e := ev
	s.stats.LastTamper = &e
	s.mu.Unlock()
	s.opts.Logf("tamper: %s (tenant %q, namespace %q, name %q)", ev.Reason, ev.Tenant, ev.Namespace, ev.Name)
	if s.opts.OnTamper != nil {
		s.opts.OnTamper(ev)
	}
}

// quarantine moves a record that failed authentication to corrupt/ and
// records the event (s.mu must not be held).
func (s *Store) quarantine(path string, ev TamperEvent) {
	cdir := filepath.Join(s.dir, dirCorrupt)
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	dst := filepath.Join(cdir, fmt.Sprintf("%d-%s-%s", s.opts.now().UnixNano(), hex.EncodeToString(rnd[:]), filepath.Base(path)))
	if err := os.Rename(path, dst); err != nil {
		_ = os.Remove(path)
	}
	_ = syncDir(filepath.Dir(path))
	s.trimCorrupt()
	s.tamper(ev)
}

func (s *Store) trimCorrupt() {
	cdir := filepath.Join(s.dir, dirCorrupt)
	entries, err := os.ReadDir(cdir)
	if err != nil || len(entries) <= maxCorruptKept {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries[:len(entries)-maxCorruptKept] {
		_ = os.Remove(filepath.Join(cdir, e.Name()))
	}
}
