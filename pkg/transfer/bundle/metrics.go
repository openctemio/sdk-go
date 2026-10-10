package bundle

import "github.com/prometheus/client_golang/prometheus"

// Register exposes the consumer's counters as Prometheus counters named
// <namespace>_bundle_<counter>_total, with a constant label feed.
func (c *Consumer) Register(reg prometheus.Registerer, namespace string) error {
	counters := []struct {
		name, help string
		get        func(ConsumerStats) uint64
	}{
		{"runs", "Consumer runs.", func(s ConsumerStats) uint64 { return s.Runs }},
		{"completed", "Bundles applied completely.", func(s ConsumerStats) uint64 { return s.Completed }},
		{"resumes", "Runs that resumed a partially applied bundle.", func(s ConsumerStats) uint64 { return s.Resumes }},
		{"chunks_applied", "Chunks applied.", func(s ConsumerStats) uint64 { return s.ChunksApplied }},
		{"chunks_failed", "Chunks that could not be fetched or applied.", func(s ConsumerStats) uint64 { return s.ChunksFailed }},
		{"records", "Records applied.", func(s ConsumerStats) uint64 { return s.Records }},
		{"refused", "Runs refused by a signature, pin, cap, expiry or rollback check.", func(s ConsumerStats) uint64 { return s.Refused }},
	}
	for _, m := range counters {
		get := m.get
		cf := prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "bundle", Name: m.name + "_total", Help: m.help,
			ConstLabels: prometheus.Labels{"feed": c.cfg.Feed},
		}, func() float64 { return float64(get(c.Stats())) })
		if err := reg.Register(cf); err != nil {
			return err
		}
	}
	return nil
}
