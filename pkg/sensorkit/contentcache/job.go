package contentcache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
)

// DefaultClaimTimeout bounds the download of one pack a job needs that the
// cache does not hold (a lazy fetch at claim).
const DefaultClaimTimeout = 2 * time.Minute

var _ core.ContentResolver = (*Cache)(nil)

// ResolveContent makes the cache hold the packs a job pins and marks each in
// use until release is called, so neither the janitor nor a sync removes one
// a running task reads. A pack the cache holds costs no network; a missing
// one is fetched by digest (a single download however many jobs claim it at
// once), checked against the pinned keys, its digest and the archive rules,
// and stored.
//
// A shared sensor (req.Shared) takes platform packs only: one copy serves
// every organization and nothing of one organization's reaches the cache.
// Every item must carry the pack's signature; the statement it holds is
// verified here, so a pack the platform did not sign, or signed for another
// organization, is refused. A pack that cannot be delivered fails with
// core.ErrContentUnavailable; one that fails a check is a content refusal.
func (c *Cache) ResolveContent(ctx context.Context, req core.ContentRequest) (*core.ResolvedContent, func(), error) {
	fail := func(err error) (*core.ResolvedContent, func(), error) { return nil, nil, err }
	byDigest := map[string]Pack{}
	for _, it := range req.Items {
		if req.Shared && it.Scope != ScopePlatform {
			return fail(core.NewContentRefusal("a shared sensor mounts platform packs only"))
		}
		p := Pack{Digest: it.Digest, Scope: it.Scope, Size: it.Size, Signature: it.Signature}
		if prev, ok := byDigest[it.Digest]; ok && prev.Scope != p.Scope {
			return fail(core.NewContentRefusal("pack %s is named with two scopes", it.Digest))
		}
		byDigest[it.Digest] = p
	}
	var releases []func()
	release := func() {
		for _, r := range releases {
			r()
		}
	}
	dirs := map[string]string{}
	for _, it := range req.Items {
		if _, done := dirs[it.Digest]; done {
			continue
		}
		dir, rel, err := c.hold(ctx, byDigest[it.Digest])
		if err != nil {
			release()
			return fail(contentError(it.Slot, err))
		}
		releases = append(releases, rel)
		dirs[it.Digest] = dir
	}
	rc := &core.ResolvedContent{}
	for _, it := range req.Items {
		idx := -1
		for i := range rc.Slots {
			if rc.Slots[i].Slot == it.Slot {
				idx = i
			}
		}
		if idx < 0 {
			rc.Slots = append(rc.Slots, core.ResolvedSlot{Slot: it.Slot})
			idx = len(rc.Slots) - 1
		}
		rc.Slots[idx].MaxLines = max(rc.Slots[idx].MaxLines, it.MaxLines)
		rc.Slots[idx].Packs = append(rc.Slots[idx].Packs, core.ResolvedPack{Digest: it.Digest, Source: it.Pack, Path: dirs[it.Digest], Files: it.Files})
	}
	return rc, release, nil
}

// hold installs the pack when missing (bounded by DefaultClaimTimeout) and
// acquires it. A held pack that fails its load check is removed by Acquire;
// it is then fetched again once.
func (c *Cache) hold(ctx context.Context, p Pack) (string, func(), error) {
	var last error
	for range 2 {
		ictx, cancel := context.WithTimeout(ctx, DefaultClaimTimeout)
		_, err := c.Install(ictx, p)
		cancel()
		if err != nil {
			return "", nil, classify(p.Digest, err)
		}
		dir, rel, err := c.Acquire(p.Digest)
		if err == nil {
			// A held pack is bound to the statement it was installed with;
			// a job that names it with another scope or signature must
			// still pass the check for what it claims.
			if _, serr := c.verifyStatement(p); serr != nil {
				rel()
				return "", nil, serr
			}
			return dir, rel, nil
		}
		last = err
		if !errors.Is(err, ErrNotHeld) && !errors.Is(err, ErrVerify) {
			break
		}
	}
	return "", nil, last
}

// contentError maps a cache error onto the executor's: a delivery failure is
// content_unavailable (the platform requeues), a failed check a refusal.
func contentError(slot string, err error) error {
	switch {
	case errors.Is(err, ErrUnavailable):
		return fmt.Errorf("%w: content slot %s: %w", core.ErrContentUnavailable, slot, err)
	case errors.Is(err, ErrVerify), errors.Is(err, ErrRevoked), errors.Is(err, ErrTooLarge), errors.Is(err, ErrRevocationsUnknown):
		return core.NewContentRefusal("content slot %s: %v", slot, err)
	}
	return fmt.Errorf("content slot %s: %w", slot, err)
}
