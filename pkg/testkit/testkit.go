// Package testkit runs a tool (pkg/tool) in-process for tests, with the
// rules the runtime applies in production: the manifest must be valid, the
// configuration must match its schema, only declared credentials are
// delivered, every record is checked (CTIS validity, declared output
// types, size and count limits, control characters), and the report is
// assembled and stamped as the runtime does. A tool that the runtime would
// stop fails its unit test.
//
// Stability: Stable (docs/STABILITY.md).
//
//	func TestDotenv(t *testing.T) {
//		res := testkit.Run(t, dotenv.Tool, tool.Task{
//			Targets: []tool.Target{{Ref: "a1", Type: "http_service", Value: srv.URL}},
//		})
//		res.RequireStatus(t, tool.StatusOK)
//		res.Golden(t, "testdata/dotenv.golden.json")
//	}
package testkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Options adjust a run.
type Options struct {
	// Secrets the operator stored. Only those the manifest declares reach
	// the tool, as in production.
	Secrets map[string]string
	// Timeout bounds the run (default: the manifest's timeout).
	Timeout time.Duration
	// Files are written to the task's directory before the run, by path
	// relative to it, as the runtime places a parser's inputs.
	Files map[string][]byte
}

// LogEntry is one message the tool logged (already redacted).
type LogEntry struct {
	Level slog.Level
	Msg   string
	Attrs map[string]any
}

// TargetOutcome is the outcome of one target.
type TargetOutcome struct {
	Ref    string
	State  tool.TargetState
	Class  tool.ErrorClass
	Detail string
}

// Result is a run's outcome.
type Result struct {
	Report  *ctis.Report
	Status  tool.Status
	Err     *tool.Error
	Targets []TargetOutcome
	Stats   toolrt.Stats
	Logs    []LogEntry
	// Artifacts by name.
	Artifacts map[string][]byte
	// Verdicts of a retest task, one per item, as the runtime reports them
	// (no verdict, or Fixed on a target not reported done or in a task that
	// did not finish, is Unverifiable).
	Verdicts []tool.RetestVerdict
}

// Run runs tl on task in-process. The task's ID defaults to "test-task".
func Run(t testing.TB, tl tool.Tool, task tool.Task, opts ...Options) *Result {
	t.Helper()
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	m := tl.Manifest().Normalized()
	if err := m.Validate(); err != nil {
		t.Fatalf("testkit: %v", err)
	}
	if task.ID == "" {
		task.ID = "test-task"
	}
	timeout, _, _, _ := m.Resources.Limits()
	if o.Timeout > 0 {
		timeout = o.Timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	asm := toolrt.NewAssembler(m, task, toolrt.NewChecker(m))
	sink := &sink{asm: asm, artifacts: map[string]*bytes.Buffer{}}
	res := &Result{}
	runErr := configError(m, task)
	if runErr == nil {
		runErr = toolrt.CheckRetest(m, task)
	}
	if runErr == nil {
		runErr = toolrt.CheckWebScope(m, task)
	}
	if runErr == nil {
		secrets := map[string]tool.Secret{}
		for _, c := range m.Permissions.Credentials {
			if v, ok := o.Secrets[c.Name]; ok {
				secrets[c.Name] = tool.NewSecret(v)
			}
		}
		workdir := t.TempDir()
		for name, data := range o.Files {
			if !filepath.IsLocal(name) {
				t.Fatalf("testkit: file %q is not a path inside the task directory", name)
			}
			p := filepath.Join(workdir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatalf("testkit: %v", err)
			}
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatalf("testkit: %v", err)
			}
		}
		tctx := toolrt.NewContext(ctx, toolrt.ContextConfig{Manifest: m, Task: task, Sink: sink,
			Secrets: secrets, Workdir: workdir})
		runErr = safeRun(tl, tctx, task)
	}
	if runErr != nil && ctx.Err() == context.DeadlineExceeded && runErr.Class != tool.Timeout {
		runErr = &tool.Error{Class: tool.Timeout, Retryable: true, Detail: "deadline exceeded", Err: runErr}
	}
	res.Err = runErr
	res.Status = asm.Status(runErr)
	res.Verdicts = asm.Verdicts(runErr)
	res.Report = asm.Report(time.Now().UTC())
	res.Stats = asm.Checker().Stats()
	toolrt.Stamp(res.Report, toolrt.Provenance{
		Tool: m.Name, ToolVersion: m.Version, ManifestDigest: m.Digest(), Protocol: tool.ProtocolVersion,
		Execution: "in-process (testkit)", TaskID: task.ID, Attempt: task.Attempt, Status: res.Status,
		Records: res.Stats.Records, Quarantined: res.Stats.Quarantined, Invalid: res.Stats.Invalid, Capped: res.Stats.Capped,
	})
	for _, r := range asm.Results() {
		to := TargetOutcome{Ref: r.Target.Ref, State: r.State}
		if r.Error != nil {
			to.Class, to.Detail = r.Error.Class, r.Error.Detail
		}
		res.Targets = append(res.Targets, to)
	}
	sink.mu.Lock()
	res.Logs = sink.logs
	res.Artifacts = map[string][]byte{}
	for k, v := range sink.artifacts {
		res.Artifacts[k] = v.Bytes()
	}
	sink.mu.Unlock()
	return res
}

// configError validates the task's configuration as the runtime does
// before a tool runs.
func configError(m tool.Manifest, task tool.Task) *tool.Error {
	schema, err := m.ConfigSchema()
	if err != nil {
		return tool.AsError(tool.Invalid("config schema: %v", err))
	}
	raw := bytes.TrimSpace(task.Config)
	if schema == nil {
		if len(raw) > 0 && !bytes.Equal(raw, []byte("{}")) && !bytes.Equal(raw, []byte("null")) {
			return tool.AsError(tool.Invalid("the tool takes no configuration"))
		}
		return nil
	}
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if err := schema.ValidateJSON(raw); err != nil {
		return tool.AsError(tool.Invalid("%v", err))
	}
	return nil
}

// safeRun turns a panic in the tool into a tool error, as a crashed
// adapter process is one.
func safeRun(tl tool.Tool, ctx tool.Context, task tool.Task) (err *tool.Error) {
	defer func() {
		if r := recover(); r != nil {
			err = &tool.Error{Class: tool.ToolCrashed, Retryable: true, Detail: fmt.Sprintf("panic: %v", r)}
		}
	}()
	return tool.AsError(toolrt.Invoke(tl, ctx, task))
}

// RequireStatus fails the test unless the run ended with st.
func (r *Result) RequireStatus(t testing.TB, st tool.Status) {
	t.Helper()
	if r.Status != st {
		t.Fatalf("status %s, want %s (error: %v, targets: %+v, stats: %+v)", r.Status, st, r.Err, r.Targets, r.Stats)
	}
}

// Golden compares the normalized report with the file at path. With
// OPENCTEM_UPDATE_GOLDEN=1 it rewrites the file instead.
func (r *Result) Golden(t testing.TB, path string) {
	t.Helper()
	Golden(t, r.Report, path)
}

// Golden compares a normalized report with the file at path (see
// Result.Golden).
func Golden(t testing.TB, report *ctis.Report, path string) {
	t.Helper()
	got, err := Normalize(report)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("OPENCTEM_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v (OPENCTEM_UPDATE_GOLDEN=1 writes it)", path, err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatalf("report differs from %s (OPENCTEM_UPDATE_GOLDEN=1 rewrites it)\n--- got\n%s", path, got)
	}
}

// volatile keys are removed by Normalize wherever they appear.
var volatile = map[string]bool{
	"timestamp": true, "duration_ms": true, "discovered_at": true, "first_seen": true, "last_seen": true,
	"started_at": true, "finished_at": true, "scanned_at": true, "detected_at": true,
	"first_seen_at": true, "last_seen_at": true, "created_at": true, "updated_at": true,
}

// Normalize returns a report as stable, indented JSON: times and durations
// removed, metadata.id removed, the runtime's provenance replaced by a
// placeholder. Two runs of a deterministic tool normalize identically.
func Normalize(report *ctis.Report) ([]byte, error) {
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if root, ok := v.(map[string]any); ok {
		if md, ok := root["metadata"].(map[string]any); ok {
			delete(md, "id")
			if props, ok := md["properties"].(map[string]any); ok {
				if _, ok := props[toolrt.ProvenanceKey]; ok {
					props[toolrt.ProvenanceKey] = "<provenance>"
				}
			}
		}
	}
	v = dropVolatile(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func dropVolatile(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if volatile[k] {
				delete(x, k)
				continue
			}
			x[k] = dropVolatile(e)
		}
	case []any:
		for i, e := range x {
			x[i] = dropVolatile(e)
		}
	}
	return v
}

// sink feeds an Assembler, as the runtime's adapter host does.
type sink struct {
	asm       *toolrt.Assembler
	mu        sync.Mutex
	logs      []LogEntry
	artifacts map[string]*bytes.Buffer
}

func (s *sink) Asset(a ctis.Asset) error { return s.asm.Asset(a) }

func (s *sink) Finding(ref string, f ctis.Finding) error { return s.asm.Finding(ref, f) }

func (s *sink) Dependency(_ string, d ctis.Dependency) error { return s.asm.Dependency(d) }

func (s *sink) Info(info *tool.ReportInfo) error {
	checked, err := s.asm.Checker().Info(info)
	if err != nil {
		return err
	}
	s.asm.SetInfo(checked)
	return nil
}

func (s *sink) Target(ref string, st tool.TargetState, err *tool.Error) {
	_ = s.asm.Target(ref, st, err)
}

func (s *sink) Progress(int, int, string) {}

func (s *sink) Verdict(ref string, r tool.VerdictReport) { _ = s.asm.Verdict(ref, r) }

func (s *sink) Log(level slog.Level, msg string, attrs map[string]any) {
	s.mu.Lock()
	s.logs = append(s.logs, LogEntry{Level: level, Msg: msg, Attrs: attrs})
	s.mu.Unlock()
}

// MaxArtifactBytes bounds an artifact in the test kit (as the runtime does).
const MaxArtifactBytes = 64 << 20

func (s *sink) Artifact(name, _ string) (io.WriteCloser, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, errors.New("artifact name must be a plain file name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.artifacts[name]; dup {
		return nil, fmt.Errorf("artifact %q already exists", name)
	}
	b := &bytes.Buffer{}
	s.artifacts[name] = b
	return &cappedWriter{w: b, mu: &s.mu, left: MaxArtifactBytes}, nil
}

type cappedWriter struct {
	w    *bytes.Buffer
	mu   *sync.Mutex
	left int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if int64(len(p)) > c.left {
		return 0, errors.New("artifact larger than the limit")
	}
	c.left -= int64(len(p))
	return c.w.Write(p)
}

func (c *cappedWriter) Close() error { return nil }
