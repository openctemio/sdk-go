package core

import (
	"context"
	"errors"
	"testing"
)

type stubReportPusher struct {
	Pusher // unused methods: nil
	puts   []*ConfigReport
	err    error
}

func (s *stubReportPusher) PutConfigReport(_ context.Context, r *ConfigReport) (*ConfigReportAck, error) {
	if s.err != nil {
		return nil, s.err
	}
	cp := *r
	s.puts = append(s.puts, &cp)
	return &ConfigReportAck{Digest: "sha256:" + string(rune('a'+len(s.puts)))}, nil
}

func TestSyncConfigReport_SendsOnChangeAndOnRequest(t *testing.T) {
	p := &stubReportPusher{}
	a := &BaseSensor{pusher: p, name: "t"}
	report := &ConfigReport{Trigger: ConfigTriggerStart, Checks: []ConfigCheck{{ID: "policy.local", Status: CheckWarn, Code: "absent"}}}
	report.Finalize(nil, 0)
	a.SetConfigReporter(ConfigReporterFunc(func() *ConfigReport { cp := *report; return &cp }))

	st := &SensorStatus{}
	a.syncConfigReport(context.Background(), st)
	if len(p.puts) != 1 || st.ConfigReport == nil || st.ConfigReport.Digest != "sha256:b" || st.ConfigReport.Warn != 1 {
		t.Fatalf("first: puts=%d status=%+v", len(p.puts), st.ConfigReport)
	}
	// Unchanged: no send, the digest is still on the heartbeat.
	st = &SensorStatus{}
	a.syncConfigReport(context.Background(), st)
	if len(p.puts) != 1 || st.ConfigReport == nil || st.ConfigReport.Digest != "sha256:b" {
		t.Fatalf("unchanged: puts=%d status=%+v", len(p.puts), st.ConfigReport)
	}
	// Asked by the platform: sent again, as requested.
	a.configReportAsked(&HeartbeatHints{Actions: []HeartbeatAction{HeartbeatActionSendConfigReport}})
	a.syncConfigReport(context.Background(), &SensorStatus{})
	if len(p.puts) != 2 || p.puts[1].Trigger != ConfigTriggerRequested {
		t.Fatalf("requested: %d %+v", len(p.puts), p.puts)
	}
	// Changed: sent as a change.
	report.Checks = []ConfigCheck{{ID: "policy.local", Status: CheckPass, Code: "enforced", Severity: SeverityInfo}}
	a.syncConfigReport(context.Background(), &SensorStatus{})
	if len(p.puts) != 3 || p.puts[2].Trigger != ConfigTriggerChange {
		t.Fatalf("changed: %d", len(p.puts))
	}
}

func TestSyncConfigReport_UnsupportedStops(t *testing.T) {
	p := &stubReportPusher{err: ErrConfigReportUnsupported}
	a := &BaseSensor{pusher: p, name: "t"}
	a.SetConfigReporter(ConfigReporterFunc(func() *ConfigReport { return &ConfigReport{} }))
	st := &SensorStatus{}
	a.syncConfigReport(context.Background(), st)
	if st.ConfigReport != nil || !a.configReport.unsupported {
		t.Fatal("unsupported must stop sending and report nothing")
	}
	p.err = errors.New("must not be called")
	a.syncConfigReport(context.Background(), st)
	if st.ConfigReport != nil {
		t.Fatal("sent again")
	}
}
