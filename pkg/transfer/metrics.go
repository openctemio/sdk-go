package transfer

import "github.com/prometheus/client_golang/prometheus"

// Register exposes the fetcher's counters as Prometheus counters named
// <namespace>_transfer_<counter>_total, with a constant label feed.
func (f *Fetcher) Register(reg prometheus.Registerer, namespace, feed string) error {
	counters := []struct {
		name, help string
		get        func(Stats) uint64
	}{
		{"files_fetched", "Files delivered by an origin.", func(s Stats) uint64 { return s.Fetched }},
		{"bytes", "Bytes downloaded.", func(s Stats) uint64 { return s.Bytes }},
		{"cache_hits", "Blobs served from the local cache.", func(s Stats) uint64 { return s.CacheHits }},
		{"not_modified", "Small files answered 304 Not Modified.", func(s Stats) uint64 { return s.NotModified }},
		{"retries", "Attempts after a transient failure.", func(s Stats) uint64 { return s.Retries }},
		{"resumes", "Partial downloads continued with a Range request.", func(s Stats) uint64 { return s.Resumes }},
		{"fallbacks", "Files delivered by an origin other than the first.", func(s Stats) uint64 { return s.Fallbacks }},
		{"failures", "Files no origin delivered.", func(s Stats) uint64 { return s.Failures }},
		{"circuit_skips", "Origins skipped because their circuit was open.", func(s Stats) uint64 { return s.CircuitSkip }},
	}
	for _, c := range counters {
		get := c.get
		cf := prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "transfer", Name: c.name + "_total", Help: c.help,
			ConstLabels: prometheus.Labels{"feed": feed},
		}, func() float64 { return float64(get(f.Stats())) })
		if err := reg.Register(cf); err != nil {
			return err
		}
	}
	return nil
}
