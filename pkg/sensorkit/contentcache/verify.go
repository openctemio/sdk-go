package contentcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

// Verification on load (openctem research 194 §5.4 (3)). A pack is checked
// when it is installed and again every time a task loads it: whoever can
// write the cache directory between the two (another process of the
// sensor's user, an offline edit of the volume, a restored snapshot) must
// not change what a task runs.
//
// On load the cache re-verifies the stored DSSE statement against the
// pinned keys (a key no longer pinned no longer works), checks that it
// names the pack's digest and this organization, and checks the files:
//
//   - with an IndexSealer (Options.Index), against the index sealed at
//     install time, when the archive had just been verified against the
//     signed digest: same set of files, same sizes, same sha256;
//   - without one, by rebuilding the canonical archive from the files and
//     comparing its digest with the signed one (platform packs are
//     canonical).
//
// Hashing a large pack on every task would be slow, so a pack whose file
// metadata (path, size, mode, modification and change time, inode) is
// unchanged since its last full check is trusted for ReverifyEvery; the
// change time cannot be set back by an unprivileged writer. Any mismatch
// refuses the load (ErrVerify), removes the pack when no task holds it, and
// is counted.
//
// Revocations are persisted (Options.State) and only ever grow, so a
// revoked pack stays refused across restarts and while the platform cannot
// be reached. A revocation record that fails authentication, or a missing
// record while packs are held (the first Sync always writes one), makes
// every load fail (ErrRevocationsUnknown) until the next Sync from the
// platform: the cache cannot tell what was revoked, so it fails closed.
// An older copy of the record put back in place is not detected here; the
// next Sync re-adds what it lacks.

// IndexSealer seals the file index of an installed pack (a
// *localstore.Sealer).
type IndexSealer interface {
	Seal(name string, plaintext []byte) ([]byte, error)
	Open(name string, blob []byte) ([]byte, error)
}

// DefaultReverifyEvery is how long a full check of an unchanged pack holds.
const DefaultReverifyEvery = 6 * time.Hour

// sealedIndexFile is the sealed index written at install time.
const sealedIndexFile = ".openctem-index.sealed"

// statementFile is the stored DSSE statement of a pack.
const statementFile = ".statement.json"

// revocationsName is the State record holding the revocation set.
const revocationsName = "revoked"

// maxRevocations bounds the persisted set (about 7 MB of digests).
const maxRevocations = 100_000

// ErrRevocationsUnknown: the persisted revocation set failed
// authentication; nothing loads until the platform's next Sync.
var ErrRevocationsUnknown = errors.New("content pack revocations unknown (refusing until the next sync)")

// verified is the outcome of the last full check of a held pack.
type verified struct {
	fingerprint string
	at          time.Time
}

// loadRevocations reads the persisted revocation set into c.banned.
func (c *Cache) loadRevocations() {
	if c.opts.State == nil {
		return
	}
	data, err := c.opts.State.Get(revocationsName)
	switch {
	case errors.Is(err, localstore.ErrNotFound):
		return
	case err != nil:
		c.revocationsUnknown = true
		return
	}
	var list []string
	if json.Unmarshal(data, &list) != nil {
		c.revocationsUnknown = true
		return
	}
	for _, d := range list {
		if digestRE.MatchString(d) {
			c.banned[d] = true
		}
	}
	c.revocationsPersisted = true
}

// saveRevocations persists the revocation set (c.mu held). Failing to
// persist is reported in the sync, never silently ignored.
func (c *Cache) saveRevocations() error {
	if c.opts.State == nil {
		return nil
	}
	list := make([]string, 0, len(c.banned))
	for d := range c.banned {
		list = append(list, d)
	}
	sort.Strings(list)
	if len(list) > maxRevocations {
		return fmt.Errorf("content cache: %d revocations, more than the %d kept", len(list), maxRevocations)
	}
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return c.opts.State.Put(revocationsName, data, localstore.Critical())
}

// sealIndex writes the sealed index of files into a staging directory.
func (c *Cache) sealIndex(staging, digest string, files []file) error {
	if c.opts.Index == nil {
		return nil
	}
	idx := make([]IndexEntry, 0, len(files))
	for _, f := range files {
		idx = append(idx, IndexEntry{Path: f.path, SHA256: sha256Hex(f.data), Size: int64(len(f.data))})
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i].Path < idx[j].Path })
	pt, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	blob, err := c.opts.Index.Seal(digest, pt)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(staging, sealedIndexFile), blob, 0o400)
}

// heldFile is one file of a stored pack, as found on disk.
type heldFile struct {
	rel  string
	abs  string
	info fs.FileInfo
}

// walkPack lists a stored pack's content files (everything but the cache's
// own records) and refuses anything that is not a regular file or a
// directory.
func walkPack(dir string) ([]heldFile, error) {
	var out []heldFile
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		switch {
		case d.IsDir():
			return nil
		case !info.Mode().IsRegular():
			return fmt.Errorf("%s is not a regular file", rel)
		case rel == statementFile || rel == indexFile || rel == sealedIndexFile:
			return nil
		}
		out = append(out, heldFile{rel: rel, abs: p, info: info})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, err
}

// fingerprintOf summarizes the metadata of a pack's files.
func fingerprintOf(dir string, files []heldFile) string {
	h := sha256.New()
	for _, extra := range []string{statementFile, sealedIndexFile} {
		if info, err := os.Lstat(filepath.Join(dir, extra)); err == nil {
			_, _ = fmt.Fprintf(h, "%s|%s\n", extra, statMeta(info))
		}
	}
	for _, f := range files {
		_, _ = fmt.Fprintf(h, "%s|%s\n", f.rel, statMeta(f.info))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// verifyHeld checks a held pack (see the comment at the top). It returns
// nil when the pack may be loaded.
func (c *Cache) verifyHeld(digest, dir string) error {
	files, err := walkPack(dir)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrVerify, digest, err)
	}
	fp := fingerprintOf(dir, files)
	now := c.now()
	c.mu.Lock()
	v, ok := c.verified[digest]
	c.mu.Unlock()
	if ok && v.fingerprint == fp && now.Sub(v.at) < c.opts.ReverifyEvery {
		return nil
	}
	if err := c.verifyFull(digest, dir, files); err != nil {
		return err
	}
	c.mu.Lock()
	c.verified[digest] = verified{fingerprint: fp, at: now}
	c.mu.Unlock()
	c.stats.add(func(s *Stats) { s.FullVerifications++ })
	return nil
}

func (c *Cache) verifyFull(digest, dir string, files []heldFile) error {
	envBytes, err := readSmall(filepath.Join(dir, statementFile), 2<<20)
	if err != nil {
		return fmt.Errorf("%w: %s: statement: %w", ErrVerify, digest, err)
	}
	// The scope picks the pinned key set; verifyStatement then checks the
	// signature, that the statement's scope agrees, the digest and the
	// organization.
	scope := ScopeTenant
	var env struct {
		Payload []byte `json:"payload"`
	}
	var probe struct {
		Scope string `json:"scope"`
	}
	if json.Unmarshal(envBytes, &env) == nil && json.Unmarshal(env.Payload, &probe) == nil && probe.Scope == ScopePlatform {
		scope = ScopePlatform
	}
	if _, err := c.verifyStatement(Pack{Digest: digest, Scope: scope, Signature: envBytes}); err != nil {
		return err
	}
	loaded := make([]file, 0, len(files))
	for _, f := range files {
		data, err := readSmall(f.abs, c.opts.Limits.MaxFileSize)
		if err != nil {
			return fmt.Errorf("%w: %s: %s: %w", ErrVerify, digest, f.rel, err)
		}
		loaded = append(loaded, file{path: f.rel, data: data})
	}
	if c.opts.Index != nil {
		return c.checkSealedIndex(digest, dir, loaded)
	}
	canonical, err := canonicalTar(loaded)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrVerify, digest, err)
	}
	if "sha256:"+sha256Hex(canonical) != digest {
		return fmt.Errorf("%w: %s: the files on disk do not match the signed digest", ErrVerify, digest)
	}
	return nil
}

func (c *Cache) checkSealedIndex(digest, dir string, loaded []file) error {
	blob, err := readSmall(filepath.Join(dir, sealedIndexFile), 64<<20)
	if err != nil {
		return fmt.Errorf("%w: %s: sealed index: %w", ErrVerify, digest, err)
	}
	pt, err := c.opts.Index.Open(digest, blob)
	if err != nil {
		return fmt.Errorf("%w: %s: sealed index: %w", ErrVerify, digest, err)
	}
	var idx []IndexEntry
	if err := json.Unmarshal(pt, &idx); err != nil {
		return fmt.Errorf("%w: %s: sealed index: %w", ErrVerify, digest, err)
	}
	if len(idx) != len(loaded) {
		return fmt.Errorf("%w: %s: %d files on disk, %d at install", ErrVerify, digest, len(loaded), len(idx))
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i].Path < idx[j].Path })
	for i, f := range loaded { // both sorted by path
		e := idx[i]
		if e.Path != f.path || e.Size != int64(len(f.data)) || e.SHA256 != sha256Hex(f.data) {
			return fmt.Errorf("%w: %s: %s changed since install", ErrVerify, digest, f.path)
		}
	}
	return nil
}

// readSmall reads a file of at most limit bytes, refusing symbolic links.
func readSmall(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	f, err := os.Open(path) //nolint:gosec // a file of the cache's own pack directory
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}

// refuseTampered removes a pack that failed its load check when no task
// holds it, and counts the failure.
func (c *Cache) refuseTampered(digest string) {
	c.mu.Lock()
	delete(c.verified, digest)
	c.mu.Unlock()
	c.stats.add(func(s *Stats) { s.VerifyFailures++ })
	c.remove(digest)
}
