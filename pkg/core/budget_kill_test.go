//go:build unix

package core_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/contract/outcome"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/mocks"
)

// exitLenientScanner is a legacy in-process scanner shaped like the
// sensor's code and recon scanners: it runs a real process through
// core.ExecuteScanner and treats every exit code up to 1 as a completed run
// ("1" meaning "findings found"), so a process killed by a signal (exit -1)
// passes its check. Its output is whatever the process wrote.
type exitLenientScanner struct {
	name string
	argv []string
}

func (s *exitLenientScanner) Name() string           { return s.name }
func (s *exitLenientScanner) Version() string        { return "test" }
func (s *exitLenientScanner) Capabilities() []string { return nil }
func (s *exitLenientScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "test", nil
}
func (s *exitLenientScanner) Scan(ctx context.Context, _ string, _ *core.ScanOptions) (*core.ScanResult, error) {
	res, err := core.ExecuteScanner(ctx, &core.ExecConfig{Binary: s.argv[0], Args: s.argv[1:]})
	if err != nil {
		return nil, err
	}
	if res.ExitCode > 1 {
		return nil, errors.New("tool failed")
	}
	return &core.ScanResult{ScannerName: s.name, ExitCode: res.ExitCode, RawOutput: res.Stdout}, nil
}

// A tool the time budget killed did not finish. The process ends by
// SIGKILL, so the exit status is -1, and the result says the run was
// stopped: a caller can never read it as a clean exit 0.
func TestExecuteScanner_KilledByTimeoutIsStopped(t *testing.T) {
	start := time.Now()
	res, err := core.ExecuteScanner(context.Background(), &core.ExecConfig{
		Binary: "/bin/sh", Args: []string{"-c", "echo partial; sleep 30"}, Timeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("a killed run with output must still return its result: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the timeout did not stop the tool")
	}
	if res.ExitCode == 0 {
		t.Fatalf("a killed run reported exit 0")
	}
	if !errors.Is(res.Error, core.ErrScannerStopped) {
		t.Fatalf("result error = %v, want ErrScannerStopped", res.Error)
	}
	if string(res.Stdout) != "partial\n" {
		t.Fatalf("output written before the kill was lost: %q", res.Stdout)
	}
}

// A completed run is not marked stopped.
func TestExecuteScanner_CompletedRunIsNotStopped(t *testing.T) {
	res, err := core.ExecuteScanner(context.Background(), &core.ExecConfig{
		Binary: "/bin/sh", Args: []string{"-c", "echo done"}, Timeout: 10 * time.Second,
	})
	if err != nil || res.ExitCode != 0 || res.Error != nil {
		t.Fatalf("completed run: exit %d, error %v / %v", res.ExitCode, res.Error, err)
	}
}

// Research 467 F6: a legacy scanner killed by the job's time budget must
// never report a clean run. Before the fix the poller pushed an empty report
// with coverage "full" and marked the target done, which the platform could
// read as "scanned, nothing found" and settle or resolve on.
func TestExecuteScan_BudgetKilledLegacyScannerIsNeverClean(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"no output", []string{"/bin/sh", "-c", "sleep 30"}},
		{"output before the kill", []string{"/bin/sh", "-c", "echo line; sleep 30"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pusher := &mocks.MockPusher{}
			exec := core.NewDefaultCommandExecutor(pusher)
			reg := core.NewParserRegistry()
			reg.Register(&cannedParser{report: *ctis.NewReport()})
			exec.SetParserRegistry(reg)
			exec.AddScanner(&exitLenientScanner{name: "lenient", argv: tc.argv})

			start := time.Now()
			res, err := exec.Execute(context.Background(), budgetCommand(t, "lenient", 1))
			if time.Since(start) > 15*time.Second {
				t.Fatal("the job budget did not stop the tool")
			}
			if err != nil {
				t.Fatalf("a budget-stopped run must deliver what it has: %v", err)
			}
			if len(pusher.PushFindingsCalls) != 1 {
				t.Fatalf("want one push, got %d", len(pusher.PushFindingsCalls))
			}
			if got := pusher.PushFindingsCalls[0].Report.Metadata.CoverageType; got != ctis.CoveragePartial {
				t.Errorf("coverage %q, want partial", got)
			}
			if res.ExitCode == 0 {
				t.Errorf("command result exit code 0 for a killed run")
			}
			for _, o := range res.TargetOutcomes {
				if o.State == outcome.Done {
					t.Errorf("target %s marked done by a killed run", o.Target)
				}
			}
			if len(res.TargetOutcomes) != 1 || res.TargetOutcomes[0].State != outcome.Unfinished {
				t.Errorf("outcomes = %+v, want the target unfinished", res.TargetOutcomes)
			}
		})
	}
}
