package contentcache

import "sync"

// Stats are a cache's delivery counters since it was opened (sensor
// metrics, research/139 §3.6).
type Stats struct {
	// Hits counts Install calls for a pack already held: no download.
	Hits int64 `json:"hits"`
	// Misses counts packs installed (downloaded fully or by delta).
	Misses int64 `json:"misses"`
	// DeltaInstalls counts misses installed from held files plus fetched
	// ones.
	DeltaInstalls int64 `json:"delta_installs"`
	// BytesDownloaded is what was fetched from the platform.
	BytesDownloaded int64 `json:"bytes_downloaded"`
	// BytesSaved is what was not fetched: held packs on a hit, held files
	// in a delta install.
	BytesSaved int64 `json:"bytes_saved"`
	// FullVerifications counts full load checks (statement, every file).
	FullVerifications int64 `json:"full_verifications"`
	// VerifyFailures counts loads refused because a held pack no longer
	// matched its signed digest or install-time index, or its statement no
	// longer verified (report it as tampering).
	VerifyFailures int64 `json:"verify_failures"`
}

type statsBox struct {
	mu sync.Mutex
	s  Stats
}

func (b *statsBox) add(f func(*Stats)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f(&b.s)
}

func (b *statsBox) get() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.s
}

// Stats returns the cache's delivery counters.
func (c *Cache) Stats() Stats { return c.stats.get() }
