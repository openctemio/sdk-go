package contentcache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// ManifestVersion is the content manifest schema version this SDK reads.
// A manifest with a higher version is refused (an older sensor or CI never
// guesses at a newer layout); new optional fields do not bump it.
const ManifestVersion = 1

// ErrUnavailable marks a pack the platform could not deliver (network,
// timeout, HTTP error). The task fails fast with content_unavailable and is
// requeued; verification failures are ErrVerify, not this.
var ErrUnavailable = core.NewClassedError("content unavailable", core.FailureContentUnavailable, "")

// ErrUnsupported marks a manifest that requires a feature this SDK version
// does not know (RequiredFeatures). The task fails with content_unsupported,
// distinct from content_unavailable: requeueing to the same sensor cannot
// help, only a sensor or CI client that understands the feature can run it.
var ErrUnsupported = core.NewClassedError("content unsupported", core.FailureContentUnavailable, core.ReasonContentUnsupported)

// KnownFeatures is the set of RequiredFeatures this SDK version understands.
// It is empty: version 1 has no optional behavior a reader must honor yet.
// Add a name here in the same change that implements the feature.
var KnownFeatures = map[string]struct{}{}

// ErrManifest marks a manifest that is malformed or of an unknown version.
var ErrManifest = core.NewClassedError("content manifest refused", core.FailureContentUnavailable, core.ReasonVerificationRefused)

// Manifest limits.
const (
	maxManifestSlots    = 8
	maxManifestSources  = 16
	maxManifestFeatures = 32
	maxManifestRuleIDs  = 20000
	maxRuleIDLen        = 256
	maxManifestBytes    = 8 << 20
)

var (
	sourceSlugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	slotNameRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	kindNameRE   = regexp.MustCompile(`^([a-z][a-z0-9-]{1,40}|x-[a-z0-9-]{1,32}/[a-z][a-z0-9-]{1,40})$`)
)

// ContentManifest is what a run is to scan with, resolved by the platform:
// per tool slot, the ordered snapshots of the rule sources, the rule ids
// switched off and the rules quarantined. The sensor receives it in the
// signed job payload; CI receives the same bytes from its run-token route.
// It is JSON, versioned, and read with unknown fields ignored.
type ContentManifest struct {
	Version int            `json:"version"`
	Slots   []ManifestSlot `json:"slots"`
	// Revoked are digests that must not be used or kept, from any source.
	Revoked []string `json:"revoked,omitempty"`
	// RequiredFeatures names behavior the reader must understand to run the
	// task safely. A reader that does not know one refuses the task with
	// ErrUnsupported instead of running it with partial semantics. Absent or
	// empty means none; it lets later fields be added without bumping Version.
	RequiredFeatures []string `json:"required_features,omitempty"`
}

// ManifestSlot is one tool slot's content.
type ManifestSlot struct {
	// Slot is the slot's name in the tool ("rules").
	Slot string `json:"slot"`
	// Kind is the content kind (semgrep-rules, nuclei-templates, ...).
	Kind string `json:"kind"`
	// Sources are the snapshots in order; the engine reads them in this
	// order (one config each).
	Sources []ManifestSource `json:"sources"`
	// DisabledRules are rule ids switched off for this run (tenant-wide and
	// per-profile disables, already merged).
	DisabledRules []string `json:"disabled_rules,omitempty"`
	// QuarantinedRules are rule ids the platform withdrew for health
	// reasons; the engine must not run them.
	QuarantinedRules []string `json:"quarantined_rules,omitempty"`
}

// ManifestSource is one rule source's snapshot.
type ManifestSource struct {
	// Source is the source's slug (the namespace of its rule ids).
	Source string `json:"source"`
	// Digest is the snapshot's content address ("sha256:<hex>").
	Digest string `json:"digest"`
	// Scope is tenant or platform: which pinned key signs the snapshot.
	Scope string `json:"scope"`
	// Size is the canonical archive's size in bytes.
	Size int64 `json:"size"`
	// Signature is the DSSE envelope of the pack statement.
	Signature json.RawMessage `json:"signature"`
}

// ParseManifest decodes and validates a manifest.
func ParseManifest(data []byte) (*ContentManifest, error) {
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrManifest, maxManifestBytes)
	}
	var m ContentManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks the manifest's shape and bounds.
func (m ContentManifest) Validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrManifest, fmt.Sprintf(format, args...))
	}
	if m.Version < 1 || m.Version > ManifestVersion {
		return bad("version %d is not supported (this SDK reads up to %d)", m.Version, ManifestVersion)
	}
	if len(m.RequiredFeatures) > maxManifestFeatures {
		return bad("at most %d required features", maxManifestFeatures)
	}
	for _, f := range m.RequiredFeatures {
		if _, ok := KnownFeatures[f]; !ok {
			if len(f) > 64 {
				f = f[:64]
			}
			return fmt.Errorf("%w: required feature %q is not known to this SDK", ErrUnsupported, f)
		}
	}
	if len(m.Slots) > maxManifestSlots {
		return bad("at most %d slots", maxManifestSlots)
	}
	for _, d := range m.Revoked {
		if !digestRE.MatchString(d) {
			return bad("revoked entry %q is not a sha256 digest", d)
		}
	}
	slots := map[string]bool{}
	for _, s := range m.Slots {
		if !slotNameRE.MatchString(s.Slot) || slots[s.Slot] {
			return bad("slot %q is invalid or repeated", s.Slot)
		}
		slots[s.Slot] = true
		if !kindNameRE.MatchString(s.Kind) {
			return bad("slot %s: kind %q is invalid", s.Slot, s.Kind)
		}
		if len(s.Sources) > maxManifestSources {
			return bad("slot %s: at most %d sources", s.Slot, maxManifestSources)
		}
		seen := map[string]bool{}
		for _, src := range s.Sources {
			if !sourceSlugRE.MatchString(src.Source) || seen[src.Source] {
				return bad("slot %s: source %q is invalid or repeated", s.Slot, src.Source)
			}
			seen[src.Source] = true
			if !digestRE.MatchString(src.Digest) {
				return bad("slot %s source %s: %q is not a sha256 digest", s.Slot, src.Source, src.Digest)
			}
			if src.Scope != ScopeTenant && src.Scope != ScopePlatform {
				return bad("slot %s source %s: scope must be tenant or platform", s.Slot, src.Source)
			}
			if src.Size <= 0 {
				return bad("slot %s source %s: size must be positive", s.Slot, src.Source)
			}
			if len(src.Signature) == 0 || string(src.Signature) == "null" {
				return bad("slot %s source %s: no signature", s.Slot, src.Source)
			}
		}
		for _, ids := range [][]string{s.DisabledRules, s.QuarantinedRules} {
			if len(ids) > maxManifestRuleIDs {
				return bad("slot %s: at most %d rule ids per list", s.Slot, maxManifestRuleIDs)
			}
			for _, id := range ids {
				if id == "" || len(id) > maxRuleIDLen || strings.ContainsAny(id, "\x00\n\r") {
					return bad("slot %s: invalid rule id", s.Slot)
				}
			}
		}
	}
	return nil
}

// Packs lists the manifest's packs in slot and source order, each digest
// once.
func (m ContentManifest) Packs() []Pack {
	var out []Pack
	seen := map[string]bool{}
	for _, s := range m.Slots {
		for _, src := range s.Sources {
			if seen[src.Digest] {
				continue
			}
			seen[src.Digest] = true
			out = append(out, Pack{Digest: src.Digest, Scope: src.Scope, Size: src.Size, Signature: src.Signature})
		}
	}
	return out
}

// TaskContent turns the manifest into the task's content: one entry per
// slot, the packs in source order with the source slug. Paths are set later
// by Cache.Resolve, never taken from the manifest.
func (m ContentManifest) TaskContent() []tool.TaskContent {
	out := make([]tool.TaskContent, 0, len(m.Slots))
	for _, s := range m.Slots {
		tc := tool.TaskContent{Slot: s.Slot, Mode: tool.ContentCustom}
		for _, src := range s.Sources {
			tc.Packs = append(tc.Packs, tool.ContentPack{Digest: src.Digest, Source: src.Source})
		}
		out = append(out, tc)
	}
	return out
}

// EnsureOptions tune Ensure.
type EnsureOptions struct {
	// PackTimeout bounds the download of one pack (0: 2 minutes).
	PackTimeout time.Duration
}

// EnsureReport is what Ensure did.
type EnsureReport struct {
	// Held are digests already in the cache (no network).
	Held []string `json:"held,omitempty"`
	// Installed are digests fetched, verified and stored.
	Installed []string `json:"installed,omitempty"`
}

// Revoke refuses and removes the given digests from now on (a held pack in
// use goes when released); the set only grows and is persisted when the
// cache has a State.
func (c *Cache) Revoke(digests []string) error {
	c.mu.Lock()
	added := false
	for _, d := range digests {
		if digestRE.MatchString(d) && !c.banned[d] {
			c.banned[d] = true
			added = true
		}
	}
	var err error
	if added || (c.opts.State != nil && !c.revocationsPersisted) {
		if err = c.saveRevocations(); err == nil {
			c.revocationsPersisted = true
		}
	}
	c.mu.Unlock()
	for _, d := range digests {
		c.remove(d)
	}
	return err
}

// Ensure makes the cache hold every pack the manifest names before a task
// runs. Revoked digests (the manifest's and the cache's) are refused before
// any network use; a held digest is never fetched again; a missing one is
// fetched by digest, checked against the pinned keys, its digest and the
// canonical archive rules, and stored. A pack that cannot be delivered
// fails the call with ErrUnavailable (the task is requeued); one that fails
// a check fails it with ErrVerify.
func (c *Cache) Ensure(ctx context.Context, m ContentManifest, opts EnsureOptions) (EnsureReport, error) {
	var rep EnsureReport
	if err := m.Validate(); err != nil {
		return rep, err
	}
	if opts.PackTimeout <= 0 {
		opts.PackTimeout = 2 * time.Minute
	}
	if err := c.Revoke(m.Revoked); err != nil {
		return rep, fmt.Errorf("content: revocations not persisted: %w", err)
	}
	packs := m.Packs()
	c.mu.Lock()
	for _, p := range packs {
		if c.banned[p.Digest] {
			c.mu.Unlock()
			return rep, fmt.Errorf("%w: %s", ErrRevoked, p.Digest)
		}
	}
	c.mu.Unlock()

	var missing []Pack
	for _, p := range packs {
		if _, ok := c.Path(p.Digest); ok {
			rep.Held = append(rep.Held, p.Digest)
			c.stats.add(func(s *Stats) { s.Hits++; s.BytesSaved += p.Size })
			continue
		}
		missing = append(missing, p)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2)
	var firstErr error
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, p := range missing {
		wg.Add(1)
		go func(p Pack) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-cctx.Done():
				return
			}
			defer func() { <-sem }()
			pctx, pcancel := context.WithTimeout(cctx, opts.PackTimeout)
			defer pcancel()
			_, err := c.Install(pctx, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = classify(p.Digest, err)
					cancel()
				}
				return
			}
			rep.Installed = append(rep.Installed, p.Digest)
		}(p)
	}
	wg.Wait()
	sort.Strings(rep.Installed)
	if firstErr == nil && ctx.Err() != nil {
		firstErr = fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
	}
	return rep, firstErr
}

// classify keeps verification and revocation errors as they are and marks
// every other failure (network, timeout, HTTP status) as unavailable.
func classify(digest string, err error) error {
	if errors.Is(err, ErrVerify) || errors.Is(err, ErrRevoked) || errors.Is(err, ErrTooLarge) {
		return err
	}
	return fmt.Errorf("%w: %s: %w", ErrUnavailable, digest, err)
}

// Prepare is the call a runner makes before a task: Ensure, then set the
// task's content from the manifest with the cache's paths. The release must
// be called when the task ends.
func (c *Cache) Prepare(ctx context.Context, m ContentManifest, task *tool.Task, opts EnsureOptions) (func(), error) {
	if _, err := c.Ensure(ctx, m, opts); err != nil {
		return nil, err
	}
	task.Content = m.TaskContent()
	return c.Resolve(task)
}

// Manifest fetches a content manifest from the platform with the same
// authenticated Do the pack routes use (the sensor's route or CI's run
// route). It sends the last ETag for that URL; a 304 returns the last
// manifest with changed false.
func (f *HTTPFetcher) Manifest(ctx context.Context, url string) (*ContentManifest, bool, error) {
	f.mu.Lock()
	last := f.manifests[url]
	f.mu.Unlock()
	hdr := http.Header{}
	if last.m != nil && last.etag != "" {
		hdr.Set("If-None-Match", last.etag)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header = hdr
	if f.Do == nil {
		return nil, false, errors.New("content fetcher: no client")
	}
	resp, err := f.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if resp.StatusCode == http.StatusNotModified && last.m != nil {
		_ = resp.Body.Close()
		return last.m, false, nil
	}
	if err := ok(resp, "content manifest"); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, false, err
	}
	f.mu.Lock()
	if f.manifests == nil {
		f.manifests = map[string]manifestEntry{}
	}
	f.manifests[url] = manifestEntry{etag: resp.Header.Get("ETag"), m: m}
	f.mu.Unlock()
	return m, true, nil
}

type manifestEntry struct {
	etag string
	m    *ContentManifest
}
