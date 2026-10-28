package client

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// A start failure under host pressure (research/318) goes as its own class
// to a platform that lists "host_pressure", and as infra.tool_crashed to
// one that does not; the attempts and the level travel either way, bounded.
func TestFail_HostPressureClassOnlyWhenOffered(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		class    string
	}{
		{"offered", []string{protov2.FeatureCommands, protov2.FeatureFailureClass, protov2.FeatureHostPressure}, "infra.resource.host_pressure"},
		{"older platform", []string{protov2.FeatureCommands, protov2.FeatureFailureClass}, "infra.tool_crashed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, bodies := refusalServer(t, tc.features)
			c := New(&Config{BaseURL: srv.URL, APIKey: "rda_test", MaxRetries: 0, RetryDelay: time.Millisecond})
			res := &core.CommandResult{Status: "failed", Error: "subfinder: tool_crashed: no handshake within 2m0s; sensor host overloaded (cpu)",
				ErrorCode: "TOOL_EXIT", Failure: &core.Failure{Class: core.FailureHostPressure, Evidence: core.FailureEvidence{
					Tool: "subfinder", Reason: core.ReasonSlowStart, Attempts: 99, Pressure: "overloaded"}}}
			if err := c.ReportCommandResult(context.Background(), "c1", res); err != nil {
				t.Fatal(err)
			}
			f, _ := bodies()[0]["failure"].(map[string]any)
			ev, _ := f["evidence"].(map[string]any)
			if f["class"] != tc.class || ev["pressure"] != "overloaded" || ev["attempts"] != float64(16) || ev["reason"] != "slow_start" {
				t.Fatalf("failure = %v", f)
			}
		})
	}
}
