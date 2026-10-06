package sensorkit

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/tool"
)

type fakeLogSender struct {
	mu      sync.Mutex
	batches map[string][]protov2.CommandLogsRequest
}

func (f *fakeLogSender) QueueCommandLogs(_ context.Context, id string, b protov2.CommandLogsRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.batches == nil {
		f.batches = map[string][]protov2.CommandLogsRequest{}
	}
	f.batches[id] = append(f.batches[id], b)
	return nil
}

func (f *fakeLogSender) lines(id string) []protov2.CommandLogLine {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []protov2.CommandLogLine
	for i, b := range f.batches[id] {
		if b.Seq != i {
			panic("batches out of seq order")
		}
		out = append(out, b.Lines...)
	}
	return out
}

func TestLogShipperBoundsAndRedacts(t *testing.T) {
	send := &fakeLogSender{}
	s := newLogShipper(send, func(v string) string { return strings.ReplaceAll(v, "sensor-key-123", tool.Redacted) }, nil)
	s.add("", protov2.CommandLogLine{Msg: "no command: dropped"})
	s.add("c1", protov2.CommandLogLine{Level: "weird", Msg: "key sensor-key-123 \u202eevil\u0007",
		Fields: map[string]any{"api_key": "abc", "count": 3, "url": "https://a.example"}})
	for i := range MaxCommandLogLines + 50 {
		s.add("c1", protov2.CommandLogLine{Level: "info", Msg: "line", Fields: map[string]any{"i": i}})
	}
	s.add("c2", protov2.CommandLogLine{Level: "error", Msg: "other command"})
	s.finish(context.Background(), "c1")
	s.finish(context.Background(), "c2")

	got := send.lines("c1")
	if len(got) != MaxCommandLogLines+1 {
		t.Fatalf("c1: %d lines sent, want %d plus the limit note", len(got), MaxCommandLogLines)
	}
	first, last := got[0], got[len(got)-1]
	if first.Level != "info" || first.Msg != "key "+tool.Redacted+" evil" {
		t.Errorf("first line not cleaned and redacted: %+v", first)
	}
	if first.Fields["api_key"] != tool.Redacted || first.Fields["count"] != 3 || first.Fields["url"] != "https://a.example" {
		t.Errorf("fields %+v", first.Fields)
	}
	if last.Level != "warn" || !strings.Contains(last.Msg, "51 further line(s)") {
		t.Errorf("limit note %+v", last)
	}
	for _, b := range send.batches["c1"] {
		if len(b.Lines) > protov2.MaxCommandLogLines {
			t.Fatalf("a batch of %d lines", len(b.Lines))
		}
	}
	if l := send.lines("c2"); len(l) != 1 || l[0].Msg != "other command" {
		t.Fatalf("c2: %+v", l)
	}
	if _, ok := send.batches[""]; ok {
		t.Fatal("a line without a command was sent")
	}
	// A finished command is forgotten: nothing more is kept for it.
	s.mu.Lock()
	n := len(s.cmds)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d commands still buffered", n)
	}
}

// loggingTool logs through the tool contract, including its credential.
var loggingTool = tool.New(tool.Manifest{
	Name: "kit-logging", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces:    []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetNone, Credentials: []tool.CredentialReq{{Name: "api_key", Kind: "api_key"}}},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	key, _ := ctx.Secret("api_key")
	ctx.Log().Info("probing with key "+key.Reveal(), "targets", len(task.Targets))
	for _, t := range task.Targets {
		ctx.TargetDone(t)
	}
	return nil
})

// TestKit_CommandLogs: a tool's log lines and the lines a custom executor
// writes with CommandLogger reach the platform with the command, redacted,
// before the command's result.
func TestKit_CommandLogs(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetLogs(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	opts.ToolCredentials = func(name string) map[string]string {
		return map[string]string{"api_key": "tool-secret-456"}
	}
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.AddTool(loggingTool)
	k.HandleCommand("custom_step", commandExecFunc(func(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
		k.CommandLogger(ctx).Info("custom step done", "token", "t0p-secret", "items", 2)
		return &core.CommandExecutionResult{}, nil
	}))
	scan, custom := "0192a3b4-0000-7000-8000-0000000000f1", "0192a3b4-0000-7000-8000-0000000000f2"
	f.QueueCommandPayload(scan, "scan", scanPayload("kit-logging", "1.1.1.1"))
	f.QueueCommandPayload(custom, "custom_step", json.RawMessage(`{}`))
	stop := runKit(t, k)
	waitCompleted(t, f, scan, out, errw)
	waitCompleted(t, f, custom, out, errw)
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	toolLines := f.CommandLogs(scan)
	if len(toolLines) == 0 {
		t.Fatalf("no tool log lines reached the platform\nstderr:%s", errw.String())
	}
	var found bool
	for _, l := range toolLines {
		if l.Source == "kit-logging" && strings.Contains(l.Msg, "probing with key "+tool.Redacted) {
			found = true
		}
		if strings.Contains(l.Msg, "tool-secret-456") {
			t.Fatalf("a credential reached the platform: %+v", l)
		}
	}
	if !found {
		t.Fatalf("tool lines %+v", toolLines)
	}
	cl := f.CommandLogs(custom)
	if len(cl) != 1 || cl[0].Msg != "custom step done" || cl[0].Fields["token"] != tool.Redacted || cl[0].Fields["items"] != float64(2) {
		t.Fatalf("custom executor lines %+v", cl)
	}
	if strings.Contains(errw.String(), "tool-secret-456") || strings.Contains(errw.String(), "t0p-secret") {
		t.Fatal("a secret reached the sensor's standard error")
	}
	if !strings.Contains(errw.String(), "custom step done") {
		t.Errorf("the local sink lacks the custom line:\n%s", errw.String())
	}
	// Logs are queued ahead of the result: the logs request comes first.
	var logAt, completeAt int
	for i, r := range f.Requests() {
		switch {
		case strings.HasSuffix(r.Path, "/"+custom+"/logs") && logAt == 0:
			logAt = i + 1
		case strings.HasSuffix(r.Path, "/"+custom+"/complete") && completeAt == 0:
			completeAt = i + 1
		}
	}
	if logAt == 0 || completeAt == 0 || logAt > completeAt {
		t.Fatalf("logs request #%d, complete #%d", logAt, completeAt)
	}
}

// Long lines are cut into batches that fit the platform body limit.
func TestLogShipperBatchesFitTheBodyLimit(t *testing.T) {
	send := &fakeLogSender{}
	s := newLogShipper(send, nil, nil)
	long := strings.Repeat("x", maxLogMsgBytes)
	for range 100 {
		s.add("c", protov2.CommandLogLine{Msg: long + "tail"})
	}
	s.finish(context.Background(), "c")
	total := 0
	for _, b := range send.batches["c"] {
		raw, _ := json.Marshal(b)
		if len(raw) > protov2.MaxCommandLogBodyBytes {
			t.Fatalf("batch %d is %d bytes", b.Seq, len(raw))
		}
		total += len(b.Lines)
	}
	if total != 100 || len(send.lines("c")[0].Msg) != maxLogMsgBytes {
		t.Fatalf("%d lines sent; first message %d bytes", total, len(send.lines("c")[0].Msg))
	}
}
