package contentcache

import (
	"context"
	"os"
	"sort"
	"time"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

// touch records a pack's last use on its directory (the modification time
// of a sealed pack's directory is otherwise never written), so "unused for
// N days" survives a restart. Best effort.
func touch(dir string, at time.Time) { _ = os.Chtimes(dir, at, at) }

// Bytes is what the held packs occupy.
func (c *Cache) Bytes() int64 {
	var n int64
	for _, d := range c.Held() {
		if p, ok := c.Path(d); ok {
			n += dirSize(p)
		}
	}
	return n
}

// lastUsed is the later of the in-memory use and the directory's recorded
// time.
func (c *Cache) lastUsed(digest, dir string) time.Time {
	c.mu.Lock()
	u := c.used[digest]
	c.mu.Unlock()
	if st, err := os.Stat(dir); err == nil && st.ModTime().After(u) {
		u = st.ModTime()
	}
	return u
}

// Prune removes packs by policy and reports what went: revoked packs at
// once; packs no assignment names that were not used for p.MaxUnused;
// then, while the cache is over p.Budget, least recently used packs
// (those no assignment names first); with p.EvictCold every pack no
// assignment names. A pack in use is never removed (a revoked one goes
// when it is released). Until the first Sync the cache does not know the
// assignments and removes nothing but revoked packs.
func (c *Cache) Prune(ctx context.Context, p localstore.PackPolicy) localstore.PackResult {
	type held struct {
		digest string
		dir    string
		size   int64
		used   time.Time
		wanted bool
		banned bool
	}
	var res localstore.PackResult
	c.mu.Lock()
	desired, known := c.desired, c.desired != nil
	banned := make(map[string]bool, len(c.banned))
	for k, v := range c.banned {
		banned[k] = v
	}
	c.mu.Unlock()
	var all []held
	var total int64
	for _, d := range c.Held() {
		dir, ok := c.Path(d)
		if !ok {
			continue
		}
		h := held{digest: d, dir: dir, size: dirSize(dir), wanted: desired[d], banned: banned[d]}
		h.used = c.lastUsed(d, dir)
		total += h.size
		all = append(all, h)
	}
	now := c.now()
	removed := map[string]bool{}
	drop := func(h held) bool {
		if ctx.Err() != nil || (p.Limit > 0 && res.Removed >= p.Limit) || removed[h.digest] {
			return false
		}
		if !c.remove(h.digest) {
			return false
		}
		removed[h.digest] = true
		total -= h.size
		res.Removed++
		res.Freed += h.size
		return true
	}
	for _, h := range all {
		if h.banned {
			drop(h)
		}
	}
	if known {
		for _, h := range all {
			if !h.wanted && p.MaxUnused > 0 && now.Sub(h.used) > p.MaxUnused {
				drop(h)
			}
		}
		if p.EvictCold {
			for _, h := range all {
				if !h.wanted {
					drop(h)
				}
			}
		}
		// Over budget: unassigned first, then assigned, each least
		// recently used first.
		sort.SliceStable(all, func(i, j int) bool {
			if all[i].wanted != all[j].wanted {
				return !all[i].wanted
			}
			return all[i].used.Before(all[j].used)
		})
		for _, h := range all {
			if total <= p.Budget {
				break
			}
			drop(h)
		}
	}
	res.Bytes = total
	return res
}

// The janitor prunes the cache through this interface.
var _ localstore.PackCache = (*Cache)(nil)
