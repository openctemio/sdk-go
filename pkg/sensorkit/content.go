package sensorkit

// The sensor's content cache (api RFC-061): packs of templates, rules and
// wordlists addressed by digest and signed by the platform, held once per
// sensor whichever organization's job needs them. The kit opens the cache on
// the local store, pins the content keys the pairing granted, keeps it
// synchronized with the platform's desired set (on a schedule and at once
// when a heartbeat answer carries a new content version), hands it to the
// janitor under the one pack budget, resolves the packs each signed job
// pins, and reports the digests it holds.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/localstore"
	"github.com/openctemio/sdk-go/pkg/sensorkit/contentcache"
)

// EnvContentBudgetMB lowers the bytes the content packs may hold, in MiB. The
// platform's policy (the sensor's pack budget, default 2 GiB) is the budget;
// this setting can only make it smaller, never larger.
const EnvContentBudgetMB = "SENSOR_CONTENT_BUDGET_MB"

// contentSyncEvery is how often the cache refreshes without a push (jittered
// by the cache); a heartbeat answer with a new content version refreshes it
// at once.
const contentSyncEvery = 15 * time.Minute

// contentState is the kit's content cache.
type contentState struct {
	once  sync.Once
	cache *contentcache.Cache
	err   error
	wake  chan struct{}
	fetch *contentFetcherRef

	mu       sync.Mutex
	version  string // desired-set version last synced
	lastErr  string
	lastSync time.Time
}

// contentFetcherRef keeps the fetcher the cache and the sync loop share.
type contentFetcherRef struct{ f *contentcache.HTTPFetcher }

// packBudgetOverride is SENSOR_CONTENT_BUDGET_MB in bytes (0: not set).
func packBudgetOverride() (int64, error) {
	v := strings.TrimSpace(os.Getenv(EnvContentBudgetMB))
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 64 || n > 8<<10 {
		return 0, usageError(fmt.Errorf("%s=%q: want a number of MiB between 64 and %d", EnvContentBudgetMB, v, 8<<10))
	}
	return n << 20, nil
}

// effectivePackPolicy normalizes the store policy and lowers its pack budget
// to the local setting when that is smaller: the platform may raise the
// budget up to the policy's limit, the operator on the host only lower it.
func effectivePackPolicy(p localstore.Policy) localstore.Policy {
	p = p.Normalize()
	if local, err := packBudgetOverride(); err == nil && local > 0 && local < p.PackBudgetBytes {
		p.PackBudgetBytes = local
	}
	return p
}

// contentKeys decodes the content keys the pairing pinned.
func contentKeys(in []jobsig.PublicKey) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, k := range in {
		pub, err := k.Decode()
		if err != nil {
			return nil, err
		}
		out = append(out, pub)
	}
	return out, nil
}

// contentRoot is the content cache directory ("" without a local store):
// next to the store, so it sits on the same data volume.
func (k *Kit) contentRoot() string {
	if k.ls == nil || k.ls.store == nil {
		return ""
	}
	return filepath.Join(filepath.Dir(k.ls.dir), "content")
}

// contentCache opens the content cache once. It is nil when the sensor has no
// local store, no platform connection, or no content key pinned (a sensor
// paired before content delivery): jobs that pin content are then refused,
// and the janitor has no packs to prune.
func (k *Kit) contentCache() *contentcache.Cache {
	ls := k.ls
	if ls == nil || ls.store == nil || k.client == nil {
		return nil
	}
	cs := &ls.content
	cs.once.Do(func() {
		cs.err = k.openContentCache(cs)
		if cs.err != nil {
			_, _ = fmt.Fprintf(k.errw, "Warning: the content cache is off: %v\n", cs.err)
		}
	})
	return cs.cache
}

func (k *Kit) openContentCache(cs *contentState) error {
	id := k.s.identity
	if id == nil || (len(id.ContentPlatformKeys) == 0 && len(id.ContentTenantKeys) == 0) {
		return nil
	}
	platform, err := contentKeys(id.ContentPlatformKeys)
	if err != nil {
		return fmt.Errorf("identity: content_platform_keys: %w; pair again", err)
	}
	tenant, err := contentKeys(id.ContentTenantKeys)
	if err != nil {
		return fmt.Errorf("identity: content_tenant_keys: %w; pair again", err)
	}
	// A shared sensor serves many organizations and holds none of their
	// packs: no organization, no tenant key.
	tenantID := id.TenantID
	if k.s.shared || id.Scope != "" {
		tenantID, tenant = "", nil
	}
	if _, err := packBudgetOverride(); err != nil {
		return err
	}
	sealer, err := k.ls.store.Sealer(localstore.SensorTenant, "content-index")
	if err != nil {
		return err
	}
	state, err := k.ls.store.KV(localstore.SensorTenant, "content")
	if err != nil {
		return err
	}
	k.ls.mu.Lock()
	pol := effectivePackPolicy(k.ls.policy)
	k.ls.mu.Unlock()
	fetch := k.client.ContentFetcher()
	cache, err := contentcache.Open(k.contentRoot(), contentcache.Options{
		TenantID: tenantID, TenantKeys: tenant, PlatformKeys: platform,
		Budget: pol.PackBudgetBytes, Fetch: fetch, Index: sealer, State: state,
	})
	if err != nil {
		return err
	}
	cs.cache, cs.fetch = cache, &contentFetcherRef{f: fetch}
	cs.wake = make(chan struct{}, 1)
	return nil
}

// wakeContent asks the sync loop to refresh now (a heartbeat answer carried
// a new content version). It never blocks.
func (k *Kit) wakeContent(string) {
	if k.ls == nil || k.ls.content.wake == nil {
		return
	}
	select {
	case k.ls.content.wake <- struct{}{}:
	default:
	}
}

// startContentSync keeps the cache holding the platform's desired set until
// ctx ends; it returns the function that waits for it. Without a cache it
// does nothing.
func (k *Kit) startContentSync(ctx context.Context) (stop func()) {
	cache := k.contentCache()
	if cache == nil {
		return func() {}
	}
	cs := &k.ls.content
	done := make(chan struct{})
	go func() {
		defer close(done)
		cache.Prefetch(ctx, cs.fetch.f, contentSyncEvery, cs.wake, func(rep contentcache.SyncReport, err error) {
			cs.mu.Lock()
			defer cs.mu.Unlock()
			msg := ""
			switch {
			case err != nil:
				msg = err.Error()
			case len(rep.Failed) > 0:
				msg = fmt.Sprintf("%d pack(s) could not be installed", len(rep.Failed))
			}
			if err == nil {
				cs.version, cs.lastSync = cs.fetch.f.Version(), time.Now()
			}
			// Say a problem once, not every 15 minutes.
			if msg != "" && msg != cs.lastErr {
				_, _ = fmt.Fprintf(k.errw, "Warning: content sync: %s\n", msg)
			}
			cs.lastErr = msg
			if k.s.verbose && (len(rep.Installed) > 0 || len(rep.Removed) > 0) {
				_, _ = fmt.Fprintf(k.out, "  Content: %d installed, %d removed\n", len(rep.Installed), len(rep.Removed))
			}
		})
	}()
	return func() { <-done }
}

// contentReport is the heartbeat's report of the packs held (nil without a
// cache).
func (k *Kit) contentReport() *core.ContentReport {
	cache := k.contentCache()
	if cache == nil {
		return nil
	}
	held := cache.Held()
	sum := sha256.Sum256([]byte(strings.Join(held, "\n")))
	st := cache.Stats()
	r := &core.ContentReport{
		HeldCount: len(held), HeldSetSHA256: hex.EncodeToString(sum[:]), Bytes: cache.Bytes(),
		Hits: st.Hits, Misses: st.Misses, BytesDownloaded: st.BytesDownloaded, BytesSaved: st.BytesSaved,
		VerifyFailures: st.VerifyFailures,
	}
	r.Held = held
	if len(r.Held) > core.MaxReportedPackDigests {
		r.Held = r.Held[:core.MaxReportedPackDigests]
	}
	cs := &k.ls.content
	cs.mu.Lock()
	r.DesiredVersion = cs.version
	cs.mu.Unlock()
	return r
}
