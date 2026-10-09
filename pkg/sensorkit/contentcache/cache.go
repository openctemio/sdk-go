// Package contentcache is the sensor's cache of content packs (api
// docs/rfcs/RFC-061-content-packs.md §3.4): immutable archives of templates,
// rules and wordlists, addressed by their sha256 digest and signed by the
// platform.
//
// A pack is stored only after:
//   - the downloaded bytes hash to the digest;
//   - its DSSE statement verifies against a key the operator pinned (the
//     tenant content key for an organization's pack, the platform content
//     key for a platform pack; a key the platform merely sends is never
//     trusted), and names the same digest, and, for an organization's pack,
//     this sensor's organization;
//   - the archive passes the canonical rules again (regular files only,
//     clean relative paths, size and count caps).
//
// It is unpacked read-only under <root>/packs/sha256-<hex>/. Tasks read a
// pack through the tool host's per-task read grants (K1); the root itself
// is private to the sensor.
//
// Stability: Experimental (docs/STABILITY.md).
package contentcache

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Scopes of a pack.
const (
	ScopeTenant   = "tenant"
	ScopePlatform = "platform"
)

// StatementPayloadType and StatementKind are the platform's pack statement.
const (
	StatementPayloadType = "application/vnd.openctem.content-pack+json"
	StatementKind        = "openctem.content-pack/v1"
)

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Errors.
var (
	ErrNotHeld  = errors.New("content pack not in the cache")
	ErrRevoked  = errors.New("content pack revoked")
	ErrVerify   = errors.New("content pack refused")
	ErrTooLarge = errors.New("content pack larger than allowed")
)

// Pack is one pack of the platform's desired set.
type Pack struct {
	Digest string `json:"digest"`
	// Scope is tenant (an organization's pack) or platform.
	Scope string `json:"scope"`
	Size  int64  `json:"size"`
	// Signature is the platform's DSSE envelope of the pack statement.
	Signature json.RawMessage `json:"signature"`
}

// Statement is the signed description of a pack.
type Statement struct {
	Kind     string `json:"kind"`
	Scope    string `json:"scope,omitempty"`
	TenantID string `json:"tenant_id"`
	PackID   string `json:"pack_id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Content  string `json:"content_kind"`
	Digest   string `json:"digest"`
	Size     int64  `json:"size"`
	Files    int    `json:"files"`
	Tier     string `json:"tier"`
}

// Fetcher downloads a pack's canonical archive by digest.
type Fetcher interface {
	Fetch(ctx context.Context, digest string) (io.ReadCloser, error)
}

// Options configure a Cache.
type Options struct {
	// TenantID is the sensor's organization: an organization's pack must
	// name it.
	TenantID string
	// TenantKeys and PlatformKeys are the pinned content-signing keys.
	TenantKeys, PlatformKeys []ed25519.PublicKey
	// Budget is the bytes the cache may hold (0: 8 GiB). Least recently
	// used packs outside the desired set and not in use go first.
	Budget int64
	// Limits bound one archive (zero: DefaultLimits).
	Limits Limits
	Fetch  Fetcher
}

// Cache is the content pack cache of one sensor.
type Cache struct {
	root   string
	opts   Options
	mu     sync.Mutex
	inUse  map[string]int
	used   map[string]time.Time
	banned map[string]bool // revoked
	now    func() time.Time
}

// Open opens (creating) a cache rooted at root, private to the sensor.
func Open(root string, opts Options) (*Cache, error) {
	if opts.Budget <= 0 {
		opts.Budget = 8 << 30
	}
	if opts.Limits == (Limits{}) {
		opts.Limits = DefaultLimits
	}
	for _, d := range []string{root, filepath.Join(root, "packs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil { //nolint:gosec // the private cache root, a directory
			return nil, err
		}
	}
	c := &Cache{root: root, opts: opts, inUse: map[string]int{}, used: map[string]time.Time{}, banned: map[string]bool{}, now: time.Now}
	// Leftover staging from an interrupted install goes.
	entries, _ := os.ReadDir(filepath.Join(root, "packs"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".staging-") {
			_ = removeTree(filepath.Join(root, "packs", e.Name()))
		}
	}
	return c, nil
}

// Root is the cache root (a tool host's ContentRoot).
func (c *Cache) Root() string { return c.root }

func (c *Cache) dir(digest string) string {
	return filepath.Join(c.root, "packs", "sha256-"+strings.TrimPrefix(digest, "sha256:"))
}

// Path is the directory of a held pack.
func (c *Cache) Path(digest string) (string, bool) {
	if !digestRE.MatchString(digest) {
		return "", false
	}
	d := c.dir(digest)
	if st, err := os.Stat(d); err != nil || !st.IsDir() {
		return "", false
	}
	return d, true
}

// Held lists the digests in the cache, sorted.
func (c *Cache) Held() []string {
	entries, _ := os.ReadDir(filepath.Join(c.root, "packs"))
	var out []string
	for _, e := range entries {
		if hexd, ok := strings.CutPrefix(e.Name(), "sha256-"); ok && e.IsDir() {
			out = append(out, "sha256:"+hexd)
		}
	}
	sort.Strings(out)
	return out
}

// Acquire marks a held pack in use by one task and returns its directory
// and the release; a pack in use is never removed.
func (c *Cache) Acquire(digest string) (string, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.banned[digest] {
		return "", nil, fmt.Errorf("%w: %s", ErrRevoked, digest)
	}
	p, ok := c.Path(digest)
	if !ok {
		return "", nil, fmt.Errorf("%w: %s", ErrNotHeld, digest)
	}
	c.inUse[digest]++
	c.used[digest] = c.now()
	var once sync.Once
	return p, func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.inUse[digest]--; c.inUse[digest] <= 0 {
				delete(c.inUse, digest)
			}
		})
	}, nil
}

// Install downloads, verifies and stores one pack; a held pack is kept.
func (c *Cache) Install(ctx context.Context, p Pack) (string, error) {
	if !digestRE.MatchString(p.Digest) {
		return "", fmt.Errorf("%w: invalid digest", ErrVerify)
	}
	c.mu.Lock()
	banned := c.banned[p.Digest]
	c.mu.Unlock()
	if banned {
		return "", fmt.Errorf("%w: %s", ErrRevoked, p.Digest)
	}
	if d, ok := c.Path(p.Digest); ok {
		return d, nil
	}
	st, err := c.verifyStatement(p)
	if err != nil {
		return "", err
	}
	if st.Size > c.opts.Limits.MaxUpload {
		return "", fmt.Errorf("%w: %d bytes", ErrTooLarge, st.Size)
	}
	if c.opts.Fetch == nil {
		return "", errors.New("content cache: no fetcher")
	}
	rc, err := c.opts.Fetch.Fetch(ctx, p.Digest)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", p.Digest, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, st.Size+1))
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", p.Digest, err)
	}
	if int64(len(data)) != st.Size {
		return "", fmt.Errorf("%w: %s is %d bytes, the statement says %d", ErrVerify, p.Digest, len(data), st.Size)
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != p.Digest {
		return "", fmt.Errorf("%w: %s does not match its digest", ErrVerify, p.Digest)
	}
	files, err := readArchive(data, c.opts.Limits)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrVerify, p.Digest, err)
	}
	return c.store(p.Digest, files, p.Signature)
}

// verifyStatement checks the pack's DSSE statement against the pinned key
// of its scope and returns it.
func (c *Cache) verifyStatement(p Pack) (*Statement, error) {
	var keys []ed25519.PublicKey
	switch p.Scope {
	case ScopeTenant:
		keys = c.opts.TenantKeys
	case ScopePlatform:
		keys = c.opts.PlatformKeys
	default:
		return nil, fmt.Errorf("%w: unknown scope %q", ErrVerify, p.Scope)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no pinned %s content key", ErrVerify, p.Scope)
	}
	var env core.SignedEnvelope
	if err := json.Unmarshal(p.Signature, &env); err != nil || env.PayloadType != StatementPayloadType {
		return nil, fmt.Errorf("%w: not a pack statement", ErrVerify)
	}
	pae := core.DSSEPreAuthEncoding(env.PayloadType, env.Payload)
	ok := false
	for _, sig := range env.Signatures {
		for _, k := range keys {
			if sig.KeyID == core.TemplateKeyID(k) && ed25519.Verify(k, pae, sig.Sig) {
				ok = true
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("%w: not signed by a pinned %s content key", ErrVerify, p.Scope)
	}
	var st Statement
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		return nil, fmt.Errorf("%w: statement: %w", ErrVerify, err)
	}
	switch {
	case st.Kind != StatementKind:
		return nil, fmt.Errorf("%w: unknown statement kind", ErrVerify)
	case st.Digest != p.Digest:
		return nil, fmt.Errorf("%w: the statement names another digest", ErrVerify)
	case p.Scope == ScopePlatform && st.Scope != ScopePlatform:
		return nil, fmt.Errorf("%w: not a platform statement", ErrVerify)
	case p.Scope == ScopeTenant && (st.Scope != "" || c.opts.TenantID == "" || st.TenantID != c.opts.TenantID):
		return nil, fmt.Errorf("%w: the pack is not this organization's", ErrVerify)
	case st.Size <= 0:
		return nil, fmt.Errorf("%w: no size", ErrVerify)
	}
	return &st, nil
}

// store unpacks files read-only into the pack's directory (staging, then
// one rename).
func (c *Cache) store(digest string, files []file, statement []byte) (string, error) {
	packs := filepath.Join(c.root, "packs")
	staging, err := os.MkdirTemp(packs, ".staging-")
	if err != nil {
		return "", err
	}
	defer func() { _ = removeTree(staging) }()
	base := filepath.Clean(staging) + string(os.PathSeparator)
	for _, f := range files {
		dst := filepath.Join(staging, filepath.FromSlash(f.path))
		// readArchive already refused unclean paths; this keeps every write
		// inside the staging directory whatever the entry says.
		if !strings.HasPrefix(dst, base) {
			return "", fmt.Errorf("%w: %q leaves the pack directory", ErrVerify, f.path)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, f.data, 0o400); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(staging, ".statement.json"), statement, 0o400); err != nil {
		return "", err
	}
	if err := sealTree(staging); err != nil {
		return "", err
	}
	dst := c.dir(digest)
	if err := os.Rename(staging, dst); err != nil {
		if _, ok := c.Path(digest); ok { // a concurrent install won
			return dst, nil
		}
		return "", err
	}
	c.mu.Lock()
	c.used[digest] = c.now()
	c.mu.Unlock()
	return dst, nil
}

// sealTree makes directories 0500 (files are written 0400).
func sealTree(root string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o500) //nolint:gosec // a directory: owner read and search only
		}
		return nil
	})
}

// removeTree removes a pack directory made read-only by sealTree.
func removeTree(root string) error {
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700) //nolint:gosec // a directory of the sensor, made writable to remove it
		}
		return nil
	})
	return os.RemoveAll(root)
}

// SyncReport is what one Sync did.
type SyncReport struct {
	Installed []string          `json:"installed,omitempty"`
	Removed   []string          `json:"removed,omitempty"`
	Failed    map[string]string `json:"failed,omitempty"`
}

// Sync makes the cache hold the desired set: missing packs are installed
// (two at a time; a failure leaves the rest and the previous good packs in
// place), revoked digests are removed at once and refused from now on, and
// packs outside the desired set and not in use are removed, least recently
// used first, while the cache is over its budget.
func (c *Cache) Sync(ctx context.Context, desired []Pack, revoked []string) SyncReport {
	rep := SyncReport{Failed: map[string]string{}}
	c.mu.Lock()
	for _, d := range revoked {
		if digestRE.MatchString(d) {
			c.banned[d] = true
		}
	}
	c.mu.Unlock()
	for _, d := range revoked {
		if c.remove(d) {
			rep.Removed = append(rep.Removed, d)
		}
	}

	want := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2)
	for _, p := range desired {
		want[p.Digest] = true
		if _, ok := c.Path(p.Digest); ok {
			continue
		}
		wg.Add(1)
		go func(p Pack) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			_, err := c.Install(ctx, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				rep.Failed[p.Digest] = err.Error()
			} else {
				rep.Installed = append(rep.Installed, p.Digest)
			}
		}(p)
	}
	wg.Wait()
	rep.Removed = append(rep.Removed, c.collect(want)...)
	sort.Strings(rep.Installed)
	return rep
}

// remove deletes a pack that is not in use.
func (c *Cache) remove(digest string) bool {
	c.mu.Lock()
	inUse := c.inUse[digest] > 0
	c.mu.Unlock()
	d, ok := c.Path(digest)
	if !ok || inUse {
		return false
	}
	if removeTree(d) != nil {
		return false
	}
	c.mu.Lock()
	delete(c.used, digest)
	c.mu.Unlock()
	return true
}

// collect removes packs outside keep, not in use, least recently used
// first, until the cache is within its budget.
func (c *Cache) collect(keep map[string]bool) []string {
	type entry struct {
		digest string
		size   int64
		used   time.Time
	}
	var all []entry
	var total int64
	for _, d := range c.Held() {
		p, _ := c.Path(d)
		size := dirSize(p)
		total += size
		c.mu.Lock()
		u := c.used[d]
		c.mu.Unlock()
		all = append(all, entry{d, size, u})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].used.Before(all[j].used) })
	var removed []string
	for _, e := range all {
		if total <= c.opts.Budget {
			break
		}
		if keep[e.digest] {
			continue
		}
		if c.remove(e.digest) {
			total -= e.size
			removed = append(removed, e.digest)
		}
	}
	return removed
}

func dirSize(root string) int64 {
	var n int64
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, ierr := d.Info(); ierr == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}
