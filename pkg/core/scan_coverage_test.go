package core_test

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/mocks"
)

// fixedScanner returns a canned ScanResult.
type fixedScanner struct {
	name string
	res  core.ScanResult
}

func (s *fixedScanner) Name() string                                      { return s.name }
func (s *fixedScanner) Version() string                                   { return "test" }
func (s *fixedScanner) Capabilities() []string                            { return nil }
func (s *fixedScanner) IsInstalled(context.Context) (bool, string, error) { return true, "test", nil }
func (s *fixedScanner) Scan(context.Context, string, *core.ScanOptions) (*core.ScanResult, error) {
	r := s.res
	return &r, nil
}

// cannedParser returns a copy of report for any output.
type cannedParser struct {
	core.BaseParser
	report ctis.Report
}

func (p *cannedParser) Name() string           { return "canned" }
func (p *cannedParser) CanParse(_ []byte) bool { return true }
func (p *cannedParser) Parse(context.Context, []byte, *core.ParseOptions) (*ctis.Report, error) {
	r := p.report
	return &r, nil
}

func pushedCoverage(t *testing.T, res core.ScanResult, parsed ctis.Report) string {
	t.Helper()
	pusher := &mocks.MockPusher{}
	exec := core.NewDefaultCommandExecutor(pusher)
	reg := core.NewParserRegistry()
	reg.Register(&cannedParser{report: parsed})
	exec.SetParserRegistry(reg)
	res.ScannerName = "fakescan"
	if res.RawOutput == nil {
		res.RawOutput = []byte("x")
	}
	exec.AddScanner(&fixedScanner{name: "fakescan", res: res})
	if _, err := exec.Execute(context.Background(), scanCommand(t, "fakescan", "http://203.0.113.10")); err != nil {
		t.Fatal(err)
	}
	if len(pusher.PushFindingsCalls) != 1 {
		t.Fatalf("want one push, got %d", len(pusher.PushFindingsCalls))
	}
	return pusher.PushFindingsCalls[0].Report.Metadata.CoverageType
}

// Every pushed scan report states its coverage (CTIS spec 4.5): a receiver
// must never have to guess, and an absent value is not full.
func TestExecuteScan_ReportStatesCoverage(t *testing.T) {
	base := func() ctis.Report { r := *ctis.NewReport(); return r }

	if got := pushedCoverage(t, core.ScanResult{}, base()); got != "full" {
		t.Errorf("completed run: coverage %q, want full", got)
	}

	if got := pushedCoverage(t, core.ScanResult{Error: "nuclei exited with code 1 (results are partial)"}, base()); got != "partial" {
		t.Errorf("run stopped part-way: coverage %q, want partial", got)
	}

	declaredFull := base()
	declaredFull.Metadata.CoverageType = "full"
	if got := pushedCoverage(t, core.ScanResult{Error: "stopped"}, declaredFull); got != "partial" {
		t.Errorf("parser said full but the run stopped: coverage %q, want partial", got)
	}

	failed := base()
	failed.Properties = ctis.Properties{"failed_targets": []string{"a.example.test"}}
	if got := pushedCoverage(t, core.ScanResult{}, failed); got != "partial" {
		t.Errorf("failed targets: coverage %q, want partial", got)
	}

	incremental := base()
	incremental.Metadata.CoverageType = "incremental"
	if got := pushedCoverage(t, core.ScanResult{}, incremental); got != "incremental" {
		t.Errorf("declared incremental: coverage %q", got)
	}

	repo := base()
	repo.Metadata.Branch = &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}
	if got := pushedCoverage(t, core.ScanResult{}, repo); got != "partial" {
		t.Errorf("repository scan: coverage %q, want partial", got)
	}
}

// A collector's report keeps the coverage the collector declared, else it is
// partial: the runtime cannot know an external source returned everything.
func TestExecuteCollect_ReportStatesCoverage(t *testing.T) {
	declared := ctis.NewReport()
	declared.Metadata.CoverageType = "full"
	unknown := ctis.NewReport()
	pusher := &mocks.MockPusher{}
	exec := core.NewDefaultCommandExecutor(pusher)
	exec.AddCollector(&mocks.MockCollector{
		NameVal: "fakesource",
		CollectFn: func(context.Context, *core.CollectOptions) (*core.CollectResult, error) {
			return &core.CollectResult{Reports: []*ctis.Report{declared, unknown}}, nil
		},
	})
	cmd := &core.Command{ID: "cmd-2", Type: "collect", Payload: []byte(`{"collector":"fakesource"}`)}
	if _, err := exec.Execute(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if len(pusher.PushFindingsCalls) != 2 {
		t.Fatalf("want two pushes, got %d", len(pusher.PushFindingsCalls))
	}
	if got := pusher.PushFindingsCalls[0].Report.Metadata.CoverageType; got != "full" {
		t.Errorf("declared full: got %q", got)
	}
	if got := pusher.PushFindingsCalls[1].Report.Metadata.CoverageType; got != "partial" {
		t.Errorf("undeclared: got %q, want partial", got)
	}
}
