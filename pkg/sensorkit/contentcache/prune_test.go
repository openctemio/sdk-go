package contentcache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

func pruneFixture(t *testing.T) (*fixture, [3]Pack) {
	t.Helper()
	f := newFixture(t)
	var ps [3]Pack
	for i, n := range []string{"a", "b", "c"} {
		ps[i] = f.pack(t, ScopeTenant, f.tenantK, "tenant-a", map[string]string{n + ".txt": strings.Repeat(n, 1000)})
	}
	rep := f.cache.Sync(context.Background(), ps[:], nil)
	if len(rep.Installed) != 3 {
		t.Fatalf("sync %+v", rep)
	}
	return f, ps
}

func TestPruneUnusedUnreferencedAfterTheLimit(t *testing.T) {
	f, ps := pruneFixture(t)
	now := time.Now()
	f.cache.now = func() time.Time { return now }
	// Only a is assigned now; b and c are not.
	f.cache.Sync(context.Background(), ps[:1], nil)
	for _, p := range ps[1:] { // Sync kept them (within budget); drop the in-memory use
		if _, ok := f.cache.Path(p.Digest); !ok {
			t.Fatalf("setup: %s gone", p.Digest)
		}
	}
	pol := localstore.PackPolicy{Budget: 1 << 30, MaxUnused: 14 * 24 * time.Hour}
	if r := f.cache.Prune(context.Background(), pol); r.Removed != 0 {
		t.Fatalf("recent packs pruned: %+v", r)
	}
	now = now.Add(15 * 24 * time.Hour)
	r := f.cache.Prune(context.Background(), pol)
	if r.Removed != 2 || r.Freed <= 0 {
		t.Fatalf("prune %+v", r)
	}
	if _, ok := f.cache.Path(ps[0].Digest); !ok {
		t.Fatal("an assigned pack was removed for being unused")
	}
	if got := f.cache.Held(); len(got) != 1 {
		t.Fatalf("held %v", got)
	}
}

func TestPruneNeverRemovesAPackInUse(t *testing.T) {
	f, ps := pruneFixture(t)
	f.cache.Sync(context.Background(), nil, nil) // nothing assigned any more... but Sync collects only over budget
	dir, release, err := f.cache.Acquire(ps[1].Digest)
	if err != nil {
		t.Fatal(err)
	}
	// Everything is unassigned, over budget, cold-evicted and revoked: the
	// pack in use stays through all of it.
	f.cache.Sync(context.Background(), nil, []string{ps[1].Digest})
	r := f.cache.Prune(context.Background(), localstore.PackPolicy{Budget: 1, MaxUnused: time.Nanosecond, EvictCold: true})
	if _, ok := f.cache.Path(ps[1].Digest); !ok {
		t.Fatalf("the pack in use was removed (%s): %+v", dir, r)
	}
	if got := f.cache.Held(); len(got) != 1 || got[0] != ps[1].Digest {
		t.Fatalf("held %v", got)
	}
	release()
	// Released and revoked: the next prune takes it at once.
	r = f.cache.Prune(context.Background(), localstore.PackPolicy{Budget: 1 << 30})
	if r.Removed != 1 || len(f.cache.Held()) != 0 {
		t.Fatalf("revoked pack kept after release: %+v", r)
	}
}

func TestPruneOverBudgetLeastRecentlyUsedAndUnassignedFirst(t *testing.T) {
	f, ps := pruneFixture(t)
	now := time.Now()
	f.cache.now = func() time.Time { return now }
	// Use b, then c, then a: a is the most recent. Assign b only.
	for _, i := range []int{1, 2, 0} {
		now = now.Add(time.Minute)
		_, rel, err := f.cache.Acquire(ps[i].Digest)
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	f.cache.Sync(context.Background(), ps[1:2], nil)
	size := f.cache.Bytes() / 3
	// Budget for two packs: the least recently used unassigned one (c) goes.
	r := f.cache.Prune(context.Background(), localstore.PackPolicy{Budget: size*2 + 10, MaxUnused: 365 * 24 * time.Hour})
	if r.Removed != 1 {
		t.Fatalf("prune %+v", r)
	}
	if _, ok := f.cache.Path(ps[2].Digest); ok {
		t.Fatal("the least recently used unassigned pack was kept")
	}
	if _, ok := f.cache.Path(ps[1].Digest); !ok {
		t.Fatal("the assigned pack went before an unassigned one")
	}
}

func TestPruneColdEvictsUnassignedOnly(t *testing.T) {
	f, ps := pruneFixture(t)
	f.cache.Sync(context.Background(), ps[:1], nil)
	r := f.cache.Prune(context.Background(), localstore.PackPolicy{Budget: 1 << 30, MaxUnused: 365 * 24 * time.Hour, EvictCold: true})
	if r.Removed != 2 {
		t.Fatalf("prune %+v", r)
	}
	if got := f.cache.Held(); len(got) != 1 || got[0] != ps[0].Digest {
		t.Fatalf("held %v", got)
	}
}

// Before the first Sync the cache does not know the assignments: it removes
// nothing but revoked packs.
func TestPruneBeforeFirstSyncKeepsEverything(t *testing.T) {
	f, ps := pruneFixture(t)
	f.cache.desired = nil
	r := f.cache.Prune(context.Background(), localstore.PackPolicy{Budget: 1, MaxUnused: time.Nanosecond, EvictCold: true})
	if r.Removed != 0 || len(f.cache.Held()) != 3 {
		t.Fatalf("pruned without knowing the assignments: %+v", r)
	}
	f.cache.banned[ps[0].Digest] = true
	if r := f.cache.Prune(context.Background(), localstore.PackPolicy{Budget: 1 << 30}); r.Removed != 1 {
		t.Fatalf("revoked pack kept: %+v", r)
	}
}

// Last use survives a restart: a pack used a minute ago is not "unused for
// 14 days" just because the process restarted.
func TestPruneLastUseSurvivesRestart(t *testing.T) {
	f, ps := pruneFixture(t)
	_, rel, err := f.cache.Acquire(ps[2].Digest)
	if err != nil {
		t.Fatal(err)
	}
	rel()
	c2, err := Open(f.root, f.cache.opts)
	if err != nil {
		t.Fatal(err)
	}
	c2.Sync(context.Background(), ps[:1], nil)
	c2.now = func() time.Time { return time.Now().Add(15 * 24 * time.Hour) }
	if d, ok := c2.Path(ps[2].Digest); !ok {
		t.Fatal("setup")
	} else if got := c2.lastUsed(ps[2].Digest, d); time.Since(got) > time.Minute {
		t.Fatalf("last use forgotten after restart: %v", got)
	}
}
