package resource

import (
	"math"
	"testing"
	"time"
)

func TestCostBookPriorFromHint(t *testing.T) {
	b, _ := NewCostBook("")
	b.SetPrior("zap", ToolCostHint{Cores: 2, MemBytes: 2 * gib, SecondsPerTarget: 30})
	if e := b.Estimate("zap"); e.CPUSeconds != 60 || e.MemBytes != 2*gib || e.ThroughputTargetsPerMin != 2 {
		t.Fatalf("estimate from hint = %+v", e)
	}
	if cores, mem := b.jobDemand("zap"); cores != 2 || mem != 2*gib {
		t.Fatalf("demand from hint = %v/%v", cores, mem)
	}
	// A hint also replaces a built-in default.
	b.SetPrior("nuclei", ToolCostHint{Cores: 0.25, MemBytes: 64 * mib, SecondsPerTarget: 1})
	if cores, mem := b.jobDemand("nuclei"); cores != 0.25 || mem != 64*mib {
		t.Fatalf("hint did not replace the default: %v/%v", cores, mem)
	}
	// Invalid hints are ignored.
	for _, h := range []ToolCostHint{{}, {Cores: -1, MemBytes: 1, SecondsPerTarget: 1}, {Cores: 1, MemBytes: 0, SecondsPerTarget: 1}, {Cores: math.Inf(1), MemBytes: 1, SecondsPerTarget: 1}} {
		b.SetPrior("bad", h)
	}
	b.SetPrior("", ToolCostHint{Cores: 1, MemBytes: 1, SecondsPerTarget: 1})
	if cores, mem := b.jobDemand("bad"); cores != genericDefault.cores || mem != genericDefault.mem {
		t.Fatalf("invalid hint used: %v/%v", cores, mem)
	}
	// The learned history wins over the hint.
	b.Observe(JobSample{Tool: "zap", Targets: 1, Wall: 10 * time.Second, CPUSeconds: 5, PeakRSSBytes: 100 * mib, Outcome: OutcomeSuccess})
	if e := b.Estimate("zap"); e.MemBytes == 2*gib {
		t.Fatalf("history ignored: %+v", e)
	}
}
