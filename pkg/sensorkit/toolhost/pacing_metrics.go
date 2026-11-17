package toolhost

import "github.com/prometheus/client_golang/prometheus"

// PacingCollector exposes the process's pacing totals (Pacing) as
// Prometheus metrics. Register it on the registry the process exposes:
//
//	prometheus.MustRegister(toolhost.NewPacingCollector())
//
// The metrics carry no label: no host, tenant or job is named.
type PacingCollector struct {
	tasks, limited, backoffs, opens, gaps, clamped *prometheus.Desc
}

// NewPacingCollector returns the collector.
func NewPacingCollector() *PacingCollector {
	d := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc("openctem_sensor_pacing_"+name, help, nil, nil)
	}
	return &PacingCollector{
		tasks:    d("tasks_total", "Tool tasks that ran under a per-host budget."),
		limited:  d("limited_tasks_total", "Tool tasks under a per-host budget that ran without the task forwarder: only the tool's own flags held the budget."),
		backoffs: d("backoffs_total", "Times a target host's rate was lowered after push-back (429, 503, resets, timeouts)."),
		opens:    d("circuit_opens_total", "Times a target host's breaker opened or gave the host up."),
		gaps:     d("throttled_hosts_total", "Target hosts reported as a throttled or blocked coverage gap."),
		clamped:  d("budget_clamped_total", "Values that were asked for (a sensor level, a job's budget, a scan's rate setting) and did not apply because a lower limit won."),
	}
}

// Describe implements prometheus.Collector.
func (c *PacingCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.tasks, c.limited, c.backoffs, c.opens, c.gaps, c.clamped} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *PacingCollector) Collect(ch chan<- prometheus.Metric) {
	t := Pacing()
	for d, v := range map[*prometheus.Desc]uint64{c.tasks: t.Tasks, c.limited: t.Limited, c.backoffs: t.Backoffs, c.opens: t.CircuitOpens,
		c.gaps: t.ThrottledGaps, c.clamped: t.Clamped} {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v))
	}
}
