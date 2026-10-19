package outbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

// Per-tenant sealing (file format version 2), used when Config.Store is
// set (openctem research 194 §5.4 (1)).
//
// A shared sensor holds the results of many organizations. With a store,
// every item and state file is sealed under the data key of the item's
// tenant (Meta.TenantID; SensorTenant for an organization sensor), so the
// results of one organization can be crypto-erased (DropTenant, then
// localstore.Store.EraseTenant) and a file copied from one organization's
// item onto another's does not open.
//
//	magic   4 bytes  "OCOB"
//	version 1 byte   0x02
//	type    1 byte   'I' (item) or 'S' (state)
//	        2 bytes  tenant id length (big endian)
//	tenant  n bytes
//	sealed  localstore.Sealer(tenant, "outbox").Seal(type ":" id, plaintext)
//
// Version 1 files (one outbox key for everything) are still read with the
// outbox key, which the store adopts as the organization sensor's data key
// when it has none.
const (
	fileVersion2  = 2
	sealerPurpose = "outbox"
	maxTenantLen  = 128
)

// fileSealer seals and opens outbox files.
type fileSealer interface {
	seal(t byte, id, tenant string, plaintext []byte) ([]byte, error)
	open(t byte, id string, data []byte) ([]byte, error)
}

// legacySealer adapts the version 1 sealer to fileSealer.
type legacySealer struct{ s *sealer }

func (l legacySealer) seal(t byte, id, _ string, pt []byte) ([]byte, error) {
	return l.s.seal(t, id, pt)
}
func (l legacySealer) open(t byte, id string, data []byte) ([]byte, error) {
	return l.s.open(t, id, data)
}

// tenantSealer writes version 2 files and reads both versions.
type tenantSealer struct {
	legacy *sealer
	store  *localstore.Store
}

func tenantOf(tenant string) string {
	if tenant == "" {
		return localstore.SensorTenant
	}
	return tenant
}

func blobName(t byte, id string) string { return string(t) + ":" + id }

func (z tenantSealer) seal(t byte, id, tenant string, pt []byte) ([]byte, error) {
	if len(pt) > maxItemBytes {
		return nil, errItemTooLarge
	}
	tenant = tenantOf(tenant)
	if len(tenant) > maxTenantLen {
		return nil, fmt.Errorf("outbox: tenant id longer than %d bytes", maxTenantLen)
	}
	s, err := z.store.Sealer(tenant, sealerPurpose)
	if err != nil {
		return nil, fmt.Errorf("outbox: tenant key: %w", err)
	}
	blob, err := s.Seal(blobName(t, id), pt)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 8+len(tenant)+len(blob))
	out = append(out, fileMagic...)
	out = append(out, fileVersion2, t)
	out = binary.BigEndian.AppendUint16(out, uint16(len(tenant))) //nolint:gosec // bounded above
	out = append(out, tenant...)
	return append(out, blob...), nil
}

func (z tenantSealer) open(t byte, id string, data []byte) ([]byte, error) {
	if len(data) < headerLen || string(data[:4]) != fileMagic {
		return nil, errCorrupt
	}
	switch data[4] {
	case fileVersion:
		if z.legacy == nil {
			return nil, errCorrupt
		}
		return z.legacy.open(t, id, data)
	case fileVersion2:
	default:
		return nil, errCorrupt
	}
	if data[5] != t {
		return nil, errCorrupt
	}
	n := int(binary.BigEndian.Uint16(data[6:8]))
	if n == 0 || n > maxTenantLen || 8+n > len(data) {
		return nil, errCorrupt
	}
	tenant := string(data[8 : 8+n])
	if !z.store.HasTenant(tenant) {
		// No key: the tenant was erased, or the name is made up. Never
		// create a key for a name read from a file.
		return nil, errCorrupt
	}
	s, err := z.store.Sealer(tenant, sealerPurpose)
	if err != nil {
		return nil, errCorrupt
	}
	pt, err := s.Open(blobName(t, id), data[8+n:])
	if err != nil {
		return nil, errCorrupt
	}
	return pt, nil
}

// legacyItems counts the version 1 items (pending and dead letters): the
// only ones that need the outbox key once a store seals new items.
func legacyItems(dir string) int { return countItems(dir, fileVersion) }

// countItems counts the items (pending and dead letters) of one file
// format version.
func countItems(dir string, version byte) int {
	n := 0
	for _, sub := range []string{dirPending, dirDead} {
		names, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range names {
			id, ok := strings.CutSuffix(e.Name(), itemExt)
			if !ok || !validID(id) {
				continue
			}
			f, err := os.Open(filepath.Join(dir, sub, e.Name())) //nolint:gosec // outbox directory
			if err != nil {
				continue
			}
			var hdr [5]byte
			_, rerr := f.Read(hdr[:])
			_ = f.Close()
			if rerr == nil && string(hdr[:4]) == fileMagic && hdr[4] == version {
				n++
			}
		}
	}
	return n
}

// DropTenant removes every pending item and dead letter of a tenant (on a
// shared sensor, an organization that left) and returns how many went.
// Call localstore.Store.EraseTenant afterwards to crypto-erase what a copy
// of the files may still hold.
func (o *Outbox) DropTenant(tenant string) (int, error) {
	if tenant == "" {
		return 0, errors.New("outbox: tenant required")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for id, e := range o.entries {
		if e.meta.TenantID != tenant || e.inflight {
			continue
		}
		dir := o.pendingDir
		if e.dead != nil {
			dir = o.deadDir
		}
		for _, ext := range []string{itemExt, stateExt, reasonExt} {
			_ = os.Remove(filepath.Join(dir, id+ext))
		}
		delete(o.entries, id)
		o.finishLocked(id, Result{Evicted: true})
		n++
	}
	if n > 0 {
		_ = syncDir(o.pendingDir)
		_ = syncDir(o.deadDir)
		o.cfg.Logf("dropped %d item(s) of tenant %s", n, tenant)
		o.signalLocked()
	}
	return n, nil
}
