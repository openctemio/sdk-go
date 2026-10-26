package contentcache

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HTTPFetcher fetches content from the platform's sensor content routes
// (api /api/v2/sensor/content): the desired-state document, packs by
// digest, a pack's file index and its files by sha256. It is the only
// content source a sensor needs: the platform syncs upstreams once and
// serves every sensor (research/139 §3.4).
type HTTPFetcher struct {
	// BaseURL is the routes' prefix, e.g. https://ctem.example.com/api/v2/sensor/content.
	BaseURL string
	// Do sends an authenticated request (the sensor's client).
	Do func(*http.Request) (*http.Response, error)

	mu      sync.Mutex
	etag    string
	desired *DesiredState
	// manifests holds the last manifest and ETag per URL.
	manifests map[string]manifestEntry
}

// DesiredState is the platform's desired-state document: the packs the
// sensor should hold and the revoked digests.
type DesiredState struct {
	Packs   []Pack   `json:"packs"`
	Revoked []string `json:"revoked,omitempty"`
}

const maxDesiredBytes = 4 << 20
const maxIndexBytes = 16 << 20

var _ IndexFetcher = (*HTTPFetcher)(nil)

func (f *HTTPFetcher) get(ctx context.Context, path string, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(f.BaseURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if f.Do == nil {
		return nil, fmt.Errorf("content fetcher: no client")
	}
	return f.Do(req)
}

func ok(resp *http.Response, what string) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return fmt.Errorf("%s: HTTP %d", what, resp.StatusCode)
}

// Fetch implements Fetcher: the pack's canonical archive.
func (f *HTTPFetcher) Fetch(ctx context.Context, digest string) (io.ReadCloser, error) {
	if !digestRE.MatchString(digest) {
		return nil, fmt.Errorf("%w: invalid digest", ErrVerify)
	}
	resp, err := f.get(ctx, "/packs/"+url.PathEscape(digest), nil)
	if err != nil {
		return nil, err
	}
	if err := ok(resp, "pack "+digest); err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Index implements IndexFetcher.
func (f *HTTPFetcher) Index(ctx context.Context, digest string) ([]IndexEntry, error) {
	if !digestRE.MatchString(digest) {
		return nil, fmt.Errorf("%w: invalid digest", ErrVerify)
	}
	resp, err := f.get(ctx, "/packs/"+url.PathEscape(digest)+"/index", nil)
	if err != nil {
		return nil, err
	}
	if err := ok(resp, "index "+digest); err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var idx []IndexEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIndexBytes)).Decode(&idx); err != nil {
		return nil, fmt.Errorf("index %s: %w", digest, err)
	}
	return idx, nil
}

// FetchFile implements IndexFetcher.
func (f *HTTPFetcher) FetchFile(ctx context.Context, digest, sha256Hex string) (io.ReadCloser, error) {
	if !digestRE.MatchString(digest) || !sha256HexRE.MatchString(sha256Hex) {
		return nil, fmt.Errorf("%w: invalid digest", ErrVerify)
	}
	resp, err := f.get(ctx, "/packs/"+url.PathEscape(digest)+"/files/"+sha256Hex, nil)
	if err != nil {
		return nil, err
	}
	if err := ok(resp, "file "+sha256Hex); err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Desired returns the desired-state document. It sends the last ETag; a
// 304 answer (nothing changed) costs no body and returns the last document.
func (f *HTTPFetcher) Desired(ctx context.Context) (*DesiredState, bool, error) {
	f.mu.Lock()
	etag, last := f.etag, f.desired
	f.mu.Unlock()
	hdr := http.Header{}
	if etag != "" && last != nil {
		hdr.Set("If-None-Match", etag)
	}
	resp, err := f.get(ctx, "/desired", hdr)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode == http.StatusNotModified && last != nil {
		_ = resp.Body.Close()
		return last, false, nil
	}
	if err := ok(resp, "desired content"); err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	var d DesiredState
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDesiredBytes)).Decode(&d); err != nil {
		return nil, false, fmt.Errorf("desired content: %w", err)
	}
	f.mu.Lock()
	f.etag, f.desired = resp.Header.Get("ETag"), &d
	f.mu.Unlock()
	return &d, true, nil
}

// Prefetch keeps the cache holding the desired set: it syncs on a jittered
// schedule (every ±20%, the first run within the first fifth, so a fleet
// does not hit the platform in the same second) and at once on wake (a
// content_changed push). Scans then find their content held and never wait
// on a download. It returns when ctx ends.
func (c *Cache) Prefetch(ctx context.Context, f *HTTPFetcher, every time.Duration, wake <-chan struct{}, report func(SyncReport, error)) {
	if every <= 0 {
		every = 15 * time.Minute
	}
	next := time.Duration(rand.Int64N(int64(every)/5 + 1)) //nolint:gosec // jitter, not a secret
	for {
		t := time.NewTimer(next)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-wake:
			t.Stop()
		case <-t.C:
		}
		d, _, err := f.Desired(ctx)
		var rep SyncReport
		if err == nil {
			rep = c.Sync(ctx, d.Packs, d.Revoked)
		}
		if report != nil {
			report(rep, err)
		}
		next = every*4/5 + time.Duration(rand.Int64N(int64(every)*2/5+1)) //nolint:gosec // jitter, not a secret
	}
}

// Version is the desired-state document's version (its ETag) as last
// fetched, "" before the first fetch.
func (f *HTTPFetcher) Version() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.etag
}
