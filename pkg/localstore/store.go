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
	// ErrKeyExists: AdoptTenantKey for a tenant that already has a key.
	ErrKeyExists = errors.New("localstore: tenant already has a data key")
	// ErrTenantErased: the tenant was erased after this handle was made;
	// get a new handle (which starts the tenant over with a new key).
	ErrTenantErased = errors.New("localstore: tenant was erased")
	// ErrRollback: a guarded record is older than the store's own counter
	// for it, was removed, or cannot be checked because the counters were
	// lost (an old copy of a record or of the store was put back, or a file
	// was deleted). Fail closed; a guarded Put makes the record valid again.
	ErrRollback = errors.New("localstore: guarded record rolled back, removed or unverifiable")
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
	// BootReset: the boot record was lost or went back at this Open (the
	// platform cannot trust the generation as a counter this time; report
	// it in the heartbeat). Every guarded record then reads as ErrRollback
	// until it is written again.
	BootReset bool `json:"boot_reset,omitempty"`
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
	// gen counts the erasures of each tenant: a Sealer or KV handle made
	// before an erasure is refused afterwards (ErrTenantErased) instead of
	// silently creating a new key.
	gen   map[string]uint64
	stats Stats

	// metaMu guards meta (the sealed meta.rec): the boot generation and the
	// per-record counters of guarded records (see Guarded).
	metaMu   sync.Mutex
	meta     metaRecord
	reported map[string]bool
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
	s := &Store{opts: o, dir: dir, unlock: unlock, tenants: map[string]cipher.AEAD{}, gen: map[string]uint64{}, reported: map[string]bool{}}
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
	if err := mkdirSynced(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("localstore: key dir: %w", err)
	}
	// O_EXCL through a link: two processes creating a shared key file at
	// once must not end up with different keys. The temporary file sits
	// next to the key (a KeyFile on another volume, the recommended setup,
	// cannot be linked or renamed across devices) and is fsynced before it
	// is linked: wrapped keys written right after must never outlive an
	// empty key file after a crash.
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(rnd[:])+".tmp")
	if err := writeSynced(tmp, content); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("localstore: write key: %w", err)
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return loadKey(path)
		}
		return nil, fmt.Errorf("localstore: install key: %w", err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("localstore: install key: %w", err)
	}
	return key, nil
}

type metaRecord struct {
	Boot    uint64    `json:"boot"`
	Created time.Time `json:"created"`
	// Guard is the latest counter of each guarded record, by
	// tenant/namespace/name.
	Guard map[string]uint64 `json:"guard,omitempty"`
	// Lost lists the guarded records whose counter is unknown since the
	// meta record was lost or went back: they read as ErrRollback until
	// they are written again.
	Lost map[string]bool `json:"lost,omitempty"`
}

func guardKey(tenant, namespace, name string) string { return tenant + "/" + namespace + "/" + name }

func (s *Store) bumpBoot() error {
	path := filepath.Join(s.dir, metaName)
	b := binding{purpose: "meta"}
	var m metaRecord
	reset := false
	data, err := readBounded(path, 1<<20)
	switch {
	case err == nil:
		pt, oerr := open(s.master, kindMeta, b, data)
		if oerr == nil && json.Unmarshal(pt, &m) == nil {
			break
		}
		m = metaRecord{}
		reset = true
		s.quarantine(path, TamperEvent{Name: metaName, Reason: "boot record failed authentication"})
	case errors.Is(err, fs.ErrNotExist):
		if s.hasWrappedKeys() {
			reset = true
			s.tamper(TamperEvent{Name: metaName, Reason: "boot record missing while tenant keys exist"})
		}
	default:
		return fmt.Errorf("localstore: read boot record: %w", err)
	}
	// Every record was written in a boot generation at or below the meta
	// record's. One above it proves meta.rec went back (an old copy of the
	// store or of the file was put back), which hides rolled-back records.
	var maxBoot uint64
	lost := map[string]bool{}
	s.scanRecords(func(tenant, ns, name string, rm recordMeta) {
		maxBoot = max(maxBoot, rm.Boot)
		if rm.Guarded {
			lost[guardKey(tenant, ns, name)] = true
		}
	})
	if !reset && maxBoot > m.Boot {
		reset = true
		s.tamper(TamperEvent{Name: metaName, Reason: fmt.Sprintf("boot generation %d is behind a record written in generation %d: an older copy of the store was restored", m.Boot, maxBoot)})
	}
	if reset {
		// The counters are gone or stale: the boot generation restarts above
		// the highest one any record carries (it never goes back), and every
		// guarded record is unverifiable until it is written again.
		m.Boot = max(m.Boot, maxBoot)
		s.stats.BootReset = true
		m.Guard = nil
		m.Lost = nil
		if len(lost) > 0 {
			m.Lost = lost
		}
	}
	if m.Created.IsZero() {
		m.Created = s.opts.now().UTC()
	}
	m.Boot++
	s.metaMu.Lock()
	s.meta = m
	err = s.writeMetaLocked()
	s.metaMu.Unlock()
	if err != nil {
		return err
	}
	s.stats.Boot = m.Boot
	return nil
}

// writeMetaLocked seals and writes meta.rec (s.metaMu held).
func (s *Store) writeMetaLocked() error {
	pt, err := json.Marshal(s.meta)
	if err != nil {
		return err
	}
	rec, err := seal(s.master, kindMeta, binding{purpose: "meta"}, pt)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, dirTmp), filepath.Join(s.dir, metaName), rec); err != nil {
		return fmt.Errorf("localstore: write boot record: %w", err)
	}
	return nil
}

// scanRecords calls f with the header of every record that opens, of
// every tenant that has a key (records that do not open are left for the
// read that finds them).
func (s *Store) scanRecords(f func(tenant, namespace, name string, m recordMeta)) {
	for _, tenant := range s.Tenants() {
		a, err := s.tenantAEAD(tenant)
		if err != nil {
			continue
		}
		nss, _ := os.ReadDir(filepath.Join(s.dir, dirKV, tenant))
		for _, ns := range nss {
			if !ns.IsDir() || validName(ns.Name()) != nil {
				continue
			}
			files, _ := os.ReadDir(filepath.Join(s.dir, dirKV, tenant, ns.Name()))
			for _, fe := range files {
				name, ok := strings.CutSuffix(fe.Name(), recExt)
				if !ok || !fe.Type().IsRegular() || validName(name) != nil {
					continue
				}
				raw, err := readBounded(filepath.Join(s.dir, dirKV, tenant, ns.Name(), fe.Name()), maxRecordBytes+headerLen+nonceLen+64)
				if err != nil {
					continue
				}
				pt, err := open(a, kindKV, binding{purpose: "kv", tenant: tenant, namespace: ns.Name(), name: name}, raw)
				if err != nil {
					continue
				}
				if m, _, err := decodeRecord(pt); err == nil {
					f(tenant, ns.Name(), name, m)
				}
			}
		}
	}
}

// reportRollback reports a rolled-back guarded record once per record.
func (s *Store) reportRollback(tenant, namespace, name, why string) {
	key := guardKey(tenant, namespace, name)
	s.metaMu.Lock()
	seen := s.reported[key]
	s.reported[key] = true
	s.metaMu.Unlock()
	if !seen {
		s.tamper(TamperEvent{Tenant: tenant, Namespace: namespace, Name: name, Reason: why})
	}
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
	return s.tenantAEADGen(tenant, nil)
}

// tenantGen is the tenant's erasure count, which a handle remembers.
func (s *Store) tenantGen(tenant string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen[tenant]
}

// tenantAEADGen is tenantAEAD for a handle made at erasure count *gen: it
// refuses (ErrTenantErased) when the tenant was erased since. nil gen is an
// explicit request that may create the key.
func (s *Store) tenantAEADGen(tenant string, gen *uint64) (cipher.AEAD, error) {
	if err := validName(tenant); err != nil {
		return nil, err
	}
	a, err := s.tenantAEADLocked(tenant, gen)
	if errors.Is(err, errAuth) {
		// A wrapped key that does not open under this master key is never
		// replaced silently: that would orphan the tenant's records.
		s.tamper(TamperEvent{Tenant: tenant, Reason: "tenant key failed authentication"})
		return nil, fmt.Errorf("%w: tenant key of %s", ErrTampered, tenant)
	}
	return a, err
}

func (s *Store) tenantAEADLocked(tenant string, gen *uint64) (cipher.AEAD, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if gen != nil && s.gen[tenant] != *gen {
		return nil, ErrTenantErased
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
		return fmt.Errorf("%w: %s", ErrKeyExists, tenant)
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

// HasTenant reports whether the tenant has a data key, without creating
// one (for readers of files that name their tenant: a crafted name never
// makes the store create a key).
func (s *Store) HasTenant(tenant string) bool {
	if validName(tenant) != nil {
		return false
	}
	_, err := os.Stat(s.keyPath(tenant))
	return err == nil
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
	s.gen[tenant]++
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
	s.forgetGuards(tenant)
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

// forgetGuards drops the counters of a tenant's guarded records (the
// tenant was erased; a new start must not read as a rollback). s.mu may be
// held.
func (s *Store) forgetGuards(tenant string) {
	prefix := tenant + "/"
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	changed := false
	for _, m := range []any{s.meta.Guard, s.meta.Lost} {
		switch mm := m.(type) {
		case map[string]uint64:
			for k := range mm {
				if strings.HasPrefix(k, prefix) {
					delete(mm, k)
					changed = true
				}
			}
		case map[string]bool:
			for k := range mm {
				if strings.HasPrefix(k, prefix) {
					delete(mm, k)
					changed = true
				}
			}
		}
	}
	for k := range s.reported {
		if strings.HasPrefix(k, prefix) {
			delete(s.reported, k)
		}
	}
	if changed {
		_ = s.writeMetaLocked()
	}
}
