package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// --- mocks ------------------------------------------------------------------

// recordingClient records the order of lifecycle calls the poller makes.
type recordingClient struct {
	calls []string
	cmds  []*Command
}

func (c *recordingClient) GetCommands(context.Context) (*GetCommandsResponse, error) {
	return &GetCommandsResponse{Commands: c.cmds}, nil
}
func (c *recordingClient) AcknowledgeCommand(context.Context, string) error {
	c.calls = append(c.calls, "ack")
	return nil
}
func (c *recordingClient) StartCommand(context.Context, string) error {
	c.calls = append(c.calls, "start")
	return nil
}
func (c *recordingClient) ReportCommandResult(context.Context, string, *CommandResult) error {
	c.calls = append(c.calls, "report")
	return nil
}
func (c *recordingClient) ReportCommandProgress(context.Context, string, int, string) error {
	c.calls = append(c.calls, "progress")
	return nil
}

type stubExecutor struct{ result *CommandExecutionResult }

func (e *stubExecutor) Execute(context.Context, *Command) (*CommandExecutionResult, error) {
	return e.result, nil
}

// fakeParser stands in for a non-SARIF parser (e.g. gitleaks native JSON).
type fakeParser struct{ used bool }

func (p *fakeParser) Name() string             { return "fake" }
func (p *fakeParser) SupportedFormats() []string { return []string{"json"} }
func (p *fakeParser) CanParse(data []byte) bool { return len(data) > 0 && data[0] == '[' }
func (p *fakeParser) Parse(context.Context, []byte, *ParseOptions) (*ctis.Report, error) {
	p.used = true
	return &ctis.Report{Findings: []ctis.Finding{{}}}, nil
}

type stubScanner struct{ raw []byte }

func (s *stubScanner) Name() string          { return "gitleaks" }
func (s *stubScanner) Version() string        { return "test" }
func (s *stubScanner) Capabilities() []string { return []string{"secret"} }
func (s *stubScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "test", nil
}
func (s *stubScanner) Scan(context.Context, string, *ScanOptions) (*ScanResult, error) {
	return &ScanResult{RawOutput: s.raw, ScannerName: "gitleaks"}, nil
}

type stubPusher struct{ pushed int }

func (p *stubPusher) PushFindings(_ context.Context, r *ctis.Report) (*PushResult, error) {
	p.pushed += len(r.Findings)
	return &PushResult{Success: true}, nil
}
func (p *stubPusher) PushAssets(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *stubPusher) SendHeartbeat(context.Context, *AgentStatus) error { return nil }
func (p *stubPusher) TestConnection(context.Context) error             { return nil }

// --- tests ------------------------------------------------------------------

// The server state machine is pending -> acknowledged -> running -> completed
// and rejects a completion that isn't "running". If the poller reports a result
// without first calling StartCommand, every daemon command silently fails.
func TestCommandPoller_startsBeforeReport(t *testing.T) {
	client := &recordingClient{}
	poller := NewCommandPoller(client, &stubExecutor{result: &CommandExecutionResult{}}, DefaultCommandPollerConfig())

	poller.activeCmds.Add(1) // executeCommand calls Done()
	poller.executeCommand(context.Background(), &Command{ID: "c1", Type: "health_check"})

	start, report := -1, -1
	for i, c := range client.calls {
		switch c {
		case "start":
			start = i
		case "report":
			report = i
		}
	}
	if start == -1 {
		t.Fatalf("StartCommand never called; command would be rejected as not-running. calls=%v", client.calls)
	}
	if report == -1 {
		t.Fatalf("ReportCommandResult never called. calls=%v", client.calls)
	}
	if start > report {
		t.Fatalf("StartCommand must precede ReportCommandResult; calls=%v", client.calls)
	}
}

// executeScan must convert output with the scanner's own parser, not a hardcoded
// SARIF parser. gitleaks/trivy emit a JSON array, which the SARIF parser cannot
// unmarshal — so a hardcoded SARIF parser drops their findings.
func TestDefaultCommandExecutor_usesRegistryParserNotSARIF(t *testing.T) {
	raw := []byte(`[{"RuleID":"aws-key","Secret":"AKIAEXAMPLE"}]`) // gitleaks-style array
	pusher := &stubPusher{}
	exec := NewDefaultCommandExecutor(pusher)
	exec.AddScanner(&stubScanner{raw: raw})

	fp := &fakeParser{}
	reg := NewParserRegistry()
	reg.Register(fp)
	exec.SetParserRegistry(reg)

	payload, err := json.Marshal(ScanCommandPayload{Scanner: "gitleaks", Target: "/x"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	if _, err := exec.executeScan(context.Background(), &Command{ID: "c1", Type: "scan", Payload: payload}); err != nil {
		t.Fatalf("executeScan errored (a hardcoded SARIF parser fails on a JSON array): %v", err)
	}
	if !fp.used {
		t.Fatal("registry parser was not used — executeScan ignored the parser registry (SARIF hardcoded?)")
	}
	if pusher.pushed != 1 {
		t.Fatalf("expected 1 finding pushed, got %d", pusher.pushed)
	}
}
