package outbox

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Collector exposes an outbox's Stats as Prometheus metrics. Register it on
// the registry the process exposes:
//
//	prometheus.MustRegister(outbox.NewCollector(o))
type Collector struct {
	o *Outbox

	pendingItems, pendingBytes, oldestAge, deadItems, deadBytes, capBytes *prometheus.Desc
	authPaused, circuitOpen                                               *prometheus.Desc
	evicted, corrupt, delivered, deadTotal, attempts                      *prometheus.Desc
}

// NewCollector returns a collector for o.
func NewCollector(o *Outbox) *Collector {
	d := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc("openctem_sensor_outbox_"+name, help, nil, nil)
	}
	return &Collector{
		o:            o,
		pendingItems: d("pending_items", "Results waiting to be delivered to the platform."),
		pendingBytes: d("pending_bytes", "Bytes on disk of the results waiting to be delivered."),
		oldestAge:    d("oldest_pending_age_seconds", "Age of the oldest result waiting to be delivered."),
		deadItems:    d("dead_letter_items", "Results the platform refused for good, kept in the dead-letter folder."),
		deadBytes:    d("dead_letter_bytes", "Bytes on disk of the dead letters."),
		capBytes:     d("cap_bytes", "Effective byte cap (MaxBytes, lowered by the free-space fraction)."),
		authPaused:   d("auth_paused", "1 while delivery is paused because the platform rejected the API key."),
		circuitOpen:  d("circuit_open", "1 while delivery is paused after consecutive transient failures."),
		evicted:      d("evicted_total", "Results dropped to respect the byte or age cap (LOST results)."),
		corrupt:      d("quarantined_total", "Files that failed authentication and were moved to corrupt/."),
		delivered:    d("delivered_total", "Results the platform acknowledged."),
		deadTotal:    d("dead_lettered_total", "Results moved to the dead-letter folder."),
		attempts:     d("attempts_total", "Delivery attempts."),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.pendingItems, c.pendingBytes, c.oldestAge, c.deadItems, c.deadBytes, c.capBytes,
		c.authPaused, c.circuitOpen, c.evicted, c.corrupt, c.delivered, c.deadTotal, c.attempts} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	s := c.o.Stats()
	b := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}
	g := func(d *prometheus.Desc, v float64) { ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v) }
	k := func(d *prometheus.Desc, v int64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v))
	}
	g(c.pendingItems, float64(s.PendingCount))
	g(c.pendingBytes, float64(s.PendingBytes))
	g(c.oldestAge, s.OldestAge(time.Now()).Seconds())
	g(c.deadItems, float64(s.DeadLetterCount))
	g(c.deadBytes, float64(s.DeadLetterBytes))
	g(c.capBytes, float64(s.CapBytes))
	g(c.authPaused, b(s.AuthPaused))
	g(c.circuitOpen, b(s.CircuitOpen))
	k(c.evicted, s.Evicted)
	k(c.corrupt, s.Corrupt)
	k(c.delivered, s.Delivered)
	k(c.deadTotal, s.DeadLetters)
	k(c.attempts, s.Attempts)
}
