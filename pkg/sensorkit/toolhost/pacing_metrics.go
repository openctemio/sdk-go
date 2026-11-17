package toolhost

import "github.com/prometheus/client_golang/prometheus"

// PacingCollector exposes the process's pacing totals (Pacing) as
// Prometheus metrics. Register it on the registry the process exposes:
//
//	prometheus.MustRegister(toolhost.NewPacingCollector())
//
// The metrics carry no label: no host, tenant or job is named.
type PacingCollector struct {
	tasks, backoffs, opens, gaps, stops, clamped *prometheus.Desc
}

// NewPacingCollector returns the collector.
func NewPacingCollector() *PacingCollector {
	d := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc("openctem_sensor_pacing_"+name, help, nil, nil)
	}
	return &PacingCollector{
		tasks:    d("tasks_total", "Tool tasks that ran under a per-host budget."),
		backoffs: d("backoffs_total", "Times a target host's rate was lowered after push-back (429, 503, resets, timeouts)."),
		opens:    d("circuit_opens_total", "Times a target host's breaker opened or gave the host up."),
		gaps:     d("throttled_hosts_total", "Target hosts reported as a throttled or blocked coverage gap."),
		stops:    d("throttle_stops_total", "Tools stopped because every host of their task throttled the scan."),
		clamped:  d("budget_clamped_total", "Budget values the sensor's own ceiling lowered."),
	}
}

// Describe implements prometheus.Collector.
func (c *PacingCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.tasks, c.backoffs, c.opens, c.gaps, c.stops, c.clamped} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *PacingCollector) Collect(ch chan<- prometheus.Metric) {
	t := Pacing()
	for d, v := range map[*prometheus.Desc]uint64{c.tasks: t.Tasks, c.backoffs: t.Backoffs, c.opens: t.CircuitOpens,
		c.gaps: t.ThrottledGaps, c.stops: t.ThrottleStops, c.clamped: t.Clamped} {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v))
	}
}
