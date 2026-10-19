package localstore

import (
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// KV is one tenant's namespace of sealed records. Each record is one file,
// written atomically and authenticated on every read. Safe for concurrent
// use; a record is replaced as a whole.
type KV struct {
	s         *Store
	tenant    string
	namespace string
	dir       string
	gen       uint64
}

// KV returns the tenant's namespace (creating the tenant's data key on
// first use).
func (s *Store) KV(tenant, namespace string) (*KV, error) {
	if err := validName(tenant); err != nil {
		return nil, err
	}
	if err := validName(namespace); err != nil {
		return nil, err
	}
	if _, err := s.tenantAEAD(tenant); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.dir, dirKV, tenant, namespace)
	if err := mkdirSynced(dir); err != nil {
		return nil, fmt.Errorf("localstore: %w", err)
	}
	return &KV{s: s, tenant: tenant, namespace: namespace, dir: dir, gen: s.tenantGen(tenant)}, nil
}

// recordMeta is the plaintext header of a KV record.
type recordMeta struct {
	WrittenAt time.Time `json:"written_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Boot      uint64    `json:"boot"`
	// Seq and Guarded belong to guarded records (see Guarded).
	Seq     uint64 `json:"seq,omitempty"`
	Guarded bool   `json:"guarded,omitempty"`
}

// PutOption changes how Put writes a record.
type PutOption func(*putOptions)

type putOptions struct {
	expiresAt time.Time
	ttl       time.Duration
	critical  bool
	guarded   bool
}

// WithExpiry makes Get answer ErrExpired once d has passed.
func WithExpiry(d time.Duration) PutOption {
	return func(o *putOptions) { o.ttl = d }
}

// WithExpiresAt makes Get answer ErrExpired from t on.
func WithExpiresAt(t time.Time) PutOption {
	return func(o *putOptions) { o.expiresAt = t }
}

// Critical marks a write that must go through even when the disk is
// critically low (journal and state updates that keep the sensor
// consistent). Keep such records small.
func Critical() PutOption { return func(o *putOptions) { o.critical = true } }

// Guarded makes the store itself remember how many times the record was
// written (in its sealed meta record), so an older copy put back, or the
// record being deleted behind the store's back, is detected: Get answers
// ErrRollback and the event is reported through OnTamper. Use it for the
// few records whose rollback is an attack (the pack revocation list, the
// policy cache); it costs one extra small write. The counters themselves
// are protected by the master key; if meta.rec is lost or restored, every
// guarded record reads as ErrRollback until it is written again.
func Guarded() PutOption { return func(o *putOptions) { o.guarded = true } }

// Info describes a record without returning its data.
type Info struct {
	Name      string    `json:"name"`
	WrittenAt time.Time `json:"written_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Boot      uint64    `json:"boot"`
}

func (kv *KV) path(name string) string { return filepath.Join(kv.dir, name+recExt) }

func (kv *KV) binding(name string) binding {
	return binding{purpose: "kv", tenant: kv.tenant, namespace: kv.namespace, name: name}
}

// Put writes (replaces) a record.
func (kv *KV) Put(name string, data []byte, opts ...PutOption) error {
	if err := validName(name); err != nil {
		return err
	}
	var po putOptions
	for _, o := range opts {
		o(&po)
	}
	if !po.critical && kv.s.Disk().Level == DiskCritical {
		return ErrDiskFull
	}
	aead, err := kv.s.tenantAEADGen(kv.tenant, &kv.gen)
	if err != nil {
		return err
	}
	now := kv.s.opts.now().UTC()
	m := recordMeta{WrittenAt: now, Boot: kv.s.Stats().Boot}
	switch {
	case po.ttl > 0:
		m.ExpiresAt = now.Add(po.ttl)
	case !po.expiresAt.IsZero():
		m.ExpiresAt = po.expiresAt.UTC()
	}
	pt, err := encodeRecord(m, data)
	if err != nil {
		return err
	}
	if po.guarded {
		return kv.putGuarded(aead, m, name, data)
	}
	rec, err := seal(aead, kindKV, kv.binding(name), pt)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(kv.s.dir, dirTmp), kv.path(name), rec); err != nil {
		return fmt.Errorf("localstore: write %s/%s/%s: %w", kv.tenant, kv.namespace, name, err)
	}
	return nil
}

// putGuarded writes the record with the next counter, then records the
// counter in the meta record. A crash between the two leaves a record ahead
// of the meta record, which reads fine (only a lower counter is a rollback).
func (kv *KV) putGuarded(aead cipher.AEAD, m recordMeta, name string, data []byte) error {
	s := kv.s
	key := guardKey(kv.tenant, kv.namespace, name)
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	m.Guarded, m.Seq = true, s.meta.Guard[key]+1
	pt, err := encodeRecord(m, data)
	if err != nil {
		return err
	}
	rec, err := seal(aead, kindKV, kv.binding(name), pt)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.dir, dirTmp), kv.path(name), rec); err != nil {
		return fmt.Errorf("localstore: write %s/%s/%s: %w", kv.tenant, kv.namespace, name, err)
	}
	if s.meta.Guard == nil {
		s.meta.Guard = map[string]uint64{}
	}
	s.meta.Guard[key] = m.Seq
	delete(s.meta.Lost, key)
	delete(s.reported, key)
	return s.writeMetaLocked()
}

// guardState says what the meta record expects of a record: its counter,
// whether it is guarded at all, and whether the counter is lost.
func (kv *KV) guardState(name string) (seq uint64, guarded, lost bool) {
	key := guardKey(kv.tenant, kv.namespace, name)
	kv.s.metaMu.Lock()
	defer kv.s.metaMu.Unlock()
	seq, guarded = kv.s.meta.Guard[key]
	return seq, guarded, kv.s.meta.Lost[key]
}

// Get reads a record. ErrNotFound when absent, ErrExpired when its expiry
// passed (no data is returned: fail closed), ErrTampered when it failed
// authentication (it was quarantined and reported).
func (kv *KV) Get(name string) ([]byte, error) {
	_, data, err := kv.read(name, true)
	return data, err
}

// Stat returns a record's Info (ErrExpired is not returned: Info carries
// the expiry).
func (kv *KV) Stat(name string) (Info, error) {
	m, _, err := kv.read(name, false)
	if err != nil && !errors.Is(err, ErrExpired) {
		return Info{}, err
	}
	return Info{Name: name, WrittenAt: m.WrittenAt, ExpiresAt: m.ExpiresAt, Boot: m.Boot}, nil
}

func (kv *KV) read(name string, wantData bool) (recordMeta, []byte, error) {
	if err := validName(name); err != nil {
		return recordMeta{}, nil, err
	}
	aead, err := kv.s.tenantAEADGen(kv.tenant, &kv.gen)
	if err != nil {
		return recordMeta{}, nil, err
	}
	path := kv.path(name)
	raw, err := readBounded(path, maxRecordBytes+headerLen+nonceLen+64)
	if errors.Is(err, fs.ErrNotExist) {
		if _, guarded, lost := kv.guardState(name); guarded || lost {
			kv.s.reportRollback(kv.tenant, kv.namespace, name, "guarded record is missing")
			return recordMeta{}, nil, ErrRollback
		}
		return recordMeta{}, nil, ErrNotFound
	}
	if err != nil && !errors.Is(err, errAuth) {
		return recordMeta{}, nil, fmt.Errorf("localstore: read %s/%s/%s: %w", kv.tenant, kv.namespace, name, err)
	}
	var pt []byte
	if err == nil {
		pt, err = open(aead, kindKV, kv.binding(name), raw)
	}
	var m recordMeta
	var data []byte
	if err == nil {
		m, data, err = decodeRecord(pt)
	}
	if err != nil {
		kv.s.quarantine(path, TamperEvent{Tenant: kv.tenant, Namespace: kv.namespace, Name: name, Reason: "record failed authentication"})
		return recordMeta{}, nil, ErrTampered
	}
	if seq, guarded, lost := kv.guardState(name); guarded || lost {
		if lost || !m.Guarded || m.Seq < seq {
			kv.s.reportRollback(kv.tenant, kv.namespace, name, "guarded record is older than the store's counter or its counter is lost")
			return recordMeta{}, nil, ErrRollback
		}
	}
	if !m.ExpiresAt.IsZero() && !kv.s.opts.now().Before(m.ExpiresAt) {
		return m, nil, ErrExpired
	}
	if !wantData {
		data = nil
	}
	return m, data, nil
}

// Delete removes a record (allowed whatever the disk level). Deleting an
// absent record is not an error.
func (kv *KV) Delete(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	// A guarded record's counter goes first: the deletion is ours, not a
	// rollback.
	key := guardKey(kv.tenant, kv.namespace, name)
	kv.s.metaMu.Lock()
	if _, ok := kv.s.meta.Guard[key]; ok || kv.s.meta.Lost[key] {
		delete(kv.s.meta.Guard, key)
		delete(kv.s.meta.Lost, key)
		delete(kv.s.reported, key)
		if err := kv.s.writeMetaLocked(); err != nil {
			kv.s.metaMu.Unlock()
			return err
		}
	}
	kv.s.metaMu.Unlock()
	if err := os.Remove(kv.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(kv.dir)
}

// List returns the record names, sorted.
func (kv *KV) List() ([]string, error) {
	entries, err := os.ReadDir(kv.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), recExt); ok && e.Type().IsRegular() && validName(n) == nil {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// SweepExpired deletes the expired records and returns how many went.
// Records that fail authentication are quarantined on the way.
func (kv *KV) SweepExpired() (int, error) {
	names, err := kv.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range names {
		if _, _, err := kv.read(name, false); errors.Is(err, ErrExpired) {
			if kv.Delete(name) == nil {
				n++
			}
		}
	}
	return n, nil
}

// encodeRecord builds a KV record's plaintext: u32 meta length, the meta
// JSON, the data.
func encodeRecord(m recordMeta, data []byte) ([]byte, error) {
	mj, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	// Each part is bounded on its own first, so the sum below cannot overflow.
	if len(data) > maxRecordBytes || len(mj) > maxRecordBytes || len(data)+len(mj)+4 > maxRecordBytes {
		return nil, ErrTooLarge
	}
	out := make([]byte, 4, 4+len(mj)+len(data))
	binary.BigEndian.PutUint32(out, uint32(len(mj))) //nolint:gosec // bounded above
	out = append(out, mj...)
	return append(out, data...), nil
}

// decodeRecord splits a KV record's plaintext. It never panics on any
// input (fuzzed).
func decodeRecord(pt []byte) (recordMeta, []byte, error) {
	var m recordMeta
	if len(pt) < 4 {
		return m, nil, errAuth
	}
	n := binary.BigEndian.Uint32(pt)
	if n == 0 || int64(n) > int64(len(pt))-4 {
		return m, nil, errAuth
	}
	if err := json.Unmarshal(pt[4:4+n], &m); err != nil {
		return m, nil, errAuth
	}
	return m, append([]byte(nil), pt[4+n:]...), nil
}
