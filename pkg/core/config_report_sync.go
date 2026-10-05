package core

// Delivery of the config report (config_report.go): sent when it changes or
// the platform asks (heartbeat action send_config_report), its digest on
// every heartbeat. Like the manifest, it never fails a heartbeat.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// ConfigReporter supplies the sensor's current config report, already
// finalized (ConfigReport.Finalize); nil when it has none yet. It is called
// on every heartbeat, so it should be cheap (build once, rebuild on change).
type ConfigReporter interface {
	ConfigReport() *ConfigReport
}

// ConfigReporterFunc adapts a function to ConfigReporter.
type ConfigReporterFunc func() *ConfigReport

// ConfigReport calls f.
func (f ConfigReporterFunc) ConfigReport() *ConfigReport { return f() }

// configReportState is what a BaseSensor knows about its delivered report.
type configReportState struct {
	mu       sync.Mutex
	reporter ConfigReporter
	// local is the digest of the report last delivered, platform the
	// digest the platform returned for it.
	local, platform string
	report          *ConfigReport
	requested       bool
	retryAt         time.Time
	// unsupported: the platform takes no config reports; checked again
	// only when a heartbeat asks for one.
	unsupported bool
}

// configReportRetryDelay is how long a failed delivery waits.
const configReportRetryDelay = time.Minute

// SetConfigReporter makes the sensor deliver r's report to a platform that
// takes config reports, and put its digest on every heartbeat. Call before
// Start.
func (a *BaseSensor) SetConfigReporter(r ConfigReporter) {
	a.configReport.mu.Lock()
	defer a.configReport.mu.Unlock()
	a.configReport.reporter = r
}

// syncConfigReport delivers the report when it is new, changed or asked
// for, and puts the platform's digest and the counts on the heartbeat.
func (a *BaseSensor) syncConfigReport(ctx context.Context, status *SensorStatus) {
	st := &a.configReport
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reporter == nil || status == nil {
		return
	}
	cp, ok := a.pusher.(ConfigReportPusher)
	if !ok {
		return
	}
	r := st.reporter.ConfigReport()
	if r == nil {
		return
	}
	local, err := r.Digest()
	if err != nil {
		return
	}
	if local == st.local && !st.requested {
		if st.platform != "" {
			status.ConfigReport = st.report.Summary(st.platform)
		}
		return
	}
	if st.unsupported && !st.requested {
		return
	}
	now := time.Now()
	if now.Before(st.retryAt) {
		return
	}
	if st.requested && local == st.local {
		r.Trigger = ConfigTriggerRequested
	} else if st.local != "" && r.Trigger == ConfigTriggerStart {
		r.Trigger = ConfigTriggerChange
	}
	ack, err := cp.PutConfigReport(ctx, r)
	switch {
	case errors.Is(err, ErrConfigReportUnsupported):
		st.local, st.platform, st.report, st.requested, st.unsupported = "", "", nil, false, true
		return
	case err != nil:
		st.retryAt = now.Add(configReportRetryDelay)
		if a.verbose {
			fmt.Printf("[%s] Config report not delivered (retry in %s): %v\n", a.name, configReportRetryDelay, err)
		}
		return
	}
	st.local, st.platform, st.report = local, ack.Digest, r
	st.requested, st.unsupported, st.retryAt = false, false, time.Time{}
	status.ConfigReport = r.Summary(ack.Digest)
	if a.verbose || len(ack.Ignored) > 0 {
		fail, warn := r.Counts()
		fmt.Printf("[%s] Config report delivered: %s (%s, %d failed, %d warnings; %d items ignored)\n",
			a.name, shortDigest(ack.Digest), r.ConfigHealth, fail, warn, len(ack.Ignored))
		for _, i := range ack.Ignored {
			fmt.Printf("[%s]   ignored %s: %s\n", a.name, i.Path, i.Reason)
		}
	}
}

// configReportAsked notes a heartbeat answer asking for the report.
func (a *BaseSensor) configReportAsked(hints *HeartbeatHints) {
	if hints == nil || !slices.Contains(hints.Actions, HeartbeatActionSendConfigReport) {
		return
	}
	a.configReport.mu.Lock()
	defer a.configReport.mu.Unlock()
	a.configReport.requested = true
}
