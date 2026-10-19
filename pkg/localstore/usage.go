package localstore

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Class is a kind of data the store and its neighbors keep on disk; the
// janitor reports and limits bytes per class.
type Class string

// Classes.
const (
	ClassOutbox      Class = "outbox"
	ClassDeadLetter  Class = "dead_letter"
	ClassJournal     Class = "journal"
	ClassWorkspace   Class = "workspace"
	ClassContentPack Class = "content_pack"
	ClassLog         Class = "log"
	// ClassState is every other store namespace (policy and scope cache,
	// pack index, revocations): small, kept for offline operation.
	ClassState Class = "state"
)

// UsageEntry is the bytes one namespace of one tenant holds.
type UsageEntry struct {
	Tenant    string `json:"tenant"`
	Namespace string `json:"namespace"`
	Class     Class  `json:"class"`
	Bytes     int64  `json:"bytes"`
	Records   int    `json:"records"`
}

// Usage is what the store holds, per tenant and namespace.
type Usage struct {
	Entries []UsageEntry    `json:"entries"`
	ByClass map[Class]int64 `json:"by_class"`
	Total   int64           `json:"total"`
}

func classOfNamespace(ns string) Class {
	if ns == journalNamespace {
		return ClassJournal
	}
	return ClassState
}

// Usage measures the records on disk, per tenant and namespace and summed
// per class. It reads directory entries only (no decryption).
func (s *Store) Usage() Usage {
	u := Usage{ByClass: map[Class]int64{}}
	kv := filepath.Join(s.dir, dirKV)
	tenants, _ := os.ReadDir(kv)
	for _, t := range tenants {
		if !t.IsDir() || validName(t.Name()) != nil {
			continue
		}
		nss, _ := os.ReadDir(filepath.Join(kv, t.Name()))
		for _, n := range nss {
			if !n.IsDir() || validName(n.Name()) != nil {
				continue
			}
			e := UsageEntry{Tenant: t.Name(), Namespace: n.Name(), Class: classOfNamespace(n.Name())}
			files, _ := os.ReadDir(filepath.Join(kv, t.Name(), n.Name()))
			for _, f := range files {
				if !strings.HasSuffix(f.Name(), recExt) || !f.Type().IsRegular() {
					continue
				}
				if info, err := f.Info(); err == nil {
					e.Bytes += info.Size()
					e.Records++
				}
			}
			u.Entries = append(u.Entries, e)
			u.ByClass[e.Class] += e.Bytes
			u.Total += e.Bytes
		}
	}
	sort.Slice(u.Entries, func(i, j int) bool {
		if u.Entries[i].Tenant != u.Entries[j].Tenant {
			return u.Entries[i].Tenant < u.Entries[j].Tenant
		}
		return u.Entries[i].Namespace < u.Entries[j].Namespace
	})
	return u
}

// CompactJournal removes the journal tombstones (finished or interrupted
// jobs) older than retention (0: DefaultJournalRetention) of every tenant,
// at most limit of them (0: no limit), and returns how many went. Open
// jobs are never touched. It stops when ctx ends.
func (s *Store) CompactJournal(ctx context.Context, retention time.Duration, limit int) (int, error) {
	if retention <= 0 {
		retention = DefaultJournalRetention
	}
	journalMu.Lock()
	defer journalMu.Unlock()
	now := s.opts.now().UTC()
	removed := 0
	for _, tenant := range s.Tenants() {
		j, err := s.Journal(tenant)
		if err != nil {
			continue
		}
		names, err := j.kv.List()
		if err != nil {
			return removed, err
		}
		for _, name := range names {
			if ctx.Err() != nil || (limit > 0 && removed >= limit) {
				return removed, ctx.Err()
			}
			r, err := j.load(name)
			if err != nil || !r.tombstone() {
				continue
			}
			at := r.InterruptedAt
			if r.Finished {
				at = r.FinishedAt
			}
			if now.Sub(at) > retention && j.kv.Delete(name) == nil {
				removed++
			}
		}
	}
	return removed, nil
}

// freeFraction is the free share of the store's volume (ok false when
// unknown).
func (s *Store) freeFraction() (frac float64, free uint64, ok bool) {
	sp, ok := s.opts.space(s.dir)
	if !ok || sp.totalBytes == 0 {
		return 0, 0, false
	}
	return float64(sp.freeBytes) / float64(sp.totalBytes), sp.freeBytes, true
}
