package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// T is what the tool suite reports to: *testing.T, or the conformance
// command's printer.
type T interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// ToolSuiteOptions configure RunToolSuite.
type ToolSuiteOptions struct {
	// Timeout bounds each check (zero: 30s).
	Timeout time.Duration
	// Credentials are what an operator would store for the tool; only
	// those the manifest declares are delivered.
	Credentials map[string]string
	// Update rewrites each fixture's expect file with what the tool
	// produced (also OPENCTEM_UPDATE_GOLDEN=1).
	Update bool
}

// conformanceRuntime names the suite in its hello.
const conformanceRuntime = "openctem-conformance"

// RunToolSuite checks a tool that runs as its own program (a tool.yaml with
// a run section, any language) against adapter protocol v1, the way the
// sensor's runtime will run it:
//
//   - Manifest: the tool.yaml loads strictly and validates, and has a run
//     section.
//   - Handshake: the program answers the runtime's hello with protocol 1,
//     ignores a message type it does not know, and answers describe with
//     exactly its tool.yaml (the run section aside).
//   - Validate: a configuration with an unknown key is refused.
//   - StdoutIsProtocol: everything it writes to standard output is a
//     protocol message (diagnostics belong on standard error).
//   - ExitsOnEOF: it exits, with status 0, when its input ends.
//   - Cancel: after run and cancel it sends its result, or exits, within the
//     10-second grace.
//   - Fixtures: each self-test fixture (manifest selftest: a task file and
//     the CTIS it must produce) runs through the runtime's own host, with
//     every runtime check, and produces exactly the expected normalized
//     report, with no invalid message.
//
// Use it from go test (conformance.RunToolSuite(t, "tool.yaml",
// conformance.ToolSuiteOptions{})) or with the command
// cmd/openctem-conformance.
func RunToolSuite(t T, manifestPath string, opts ToolSuiteOptions) {
	t.Helper()
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if os.Getenv("OPENCTEM_UPDATE_GOLDEN") == "1" {
		opts.Update = true
	}
	if abs, err := filepath.Abs(manifestPath); err == nil {
		manifestPath = abs // the program runs in its task directory
	}
	m, err := tool.LoadManifestFile(manifestPath)
	if err != nil {
		t.Fatalf("Manifest: %v", err)
		return
	}
	m = m.Normalized()
	if m.Run == nil || len(m.Run.Argv) == 0 {
		t.Fatalf("Manifest: %s has no run section (a tool compiled into a sensor is tested with pkg/testkit)", manifestPath)
		return
	}
	if m.Run.Profile == tool.ProfileExec {
		t.Logf("%s uses the exec profile: no adapter protocol to check; running its fixtures only", m.Name)
	} else {
		s := &toolSuite{t: t, m: m, dir: filepath.Dir(manifestPath), opts: opts}
		s.handshake()
		s.cancel()
	}
	runFixtures(t, m, filepath.Dir(manifestPath), opts)
}

type toolSuite struct {
	t    T
	m    tool.Manifest
	dir  string
	opts ToolSuiteOptions
}

// adapterProc is one running adapter, spoken to line by line.
type adapterProc struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	lines  chan []byte
	stderr *bytes.Buffer
	mu     sync.Mutex
	raw    [][]byte
	// exited is closed when the program exited; exitErr is Wait's error.
	exited  chan struct{}
	exitErr error
}

func (s *toolSuite) start() (*adapterProc, error) {
	argv := append([]string(nil), s.m.Run.Argv...)
	if !filepath.IsAbs(argv[0]) && strings.ContainsRune(argv[0], filepath.Separator) {
		argv[0] = filepath.Join(s.dir, argv[0])
	}
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // the tool under test, from its own manifest
	cmd.Dir = s.dir
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	p := &adapterProc{cmd: cmd, in: in, lines: make(chan []byte, 256), stderr: &bytes.Buffer{}, exited: make(chan struct{})}
	cmd.Stderr = &lockedWriter{w: p.stderr, mu: &p.mu}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		r := bufio.NewReaderSize(out, 64<<10)
		for {
			line, err := r.ReadBytes('\n')
			if len(bytes.TrimSpace(line)) > 0 {
				line = bytes.TrimRight(line, "\r\n")
				p.mu.Lock()
				p.raw = append(p.raw, line)
				p.mu.Unlock()
				p.lines <- line
			}
			if err != nil {
				close(p.lines)
				return
			}
		}
	}()
	go func() {
		p.exitErr = cmd.Wait()
		close(p.exited)
	}()
	return p, nil
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func (p *adapterProc) send(msg string) error {
	_, err := io.WriteString(p.in, msg+"\n")
	return err
}

// next returns the next message of the given types, skipping logs,
// progress and heartbeats.
func (p *adapterProc) next(timeout time.Duration, types ...string) (map[string]any, error) {
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				return nil, errors.New("the program closed its output")
			}
			var msg map[string]any
			if err := json.Unmarshal(line, &msg); err != nil {
				continue // reported by the StdoutIsProtocol check
			}
			typ, _ := msg["type"].(string)
			for _, want := range types {
				if typ == want {
					return msg, nil
				}
			}
		case <-deadline:
			return nil, fmt.Errorf("no %s within %s", strings.Join(types, " or "), timeout)
		}
	}
}

func (p *adapterProc) kill() {
	_ = p.in.Close()
	select {
	case <-p.exited:
	case <-time.After(2 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
}

func (p *adapterProc) stderrText() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.TrimSpace(p.stderr.String())
}

func (s *toolSuite) hello(p *adapterProc) error {
	hello := fmt.Sprintf(`{"v":1,"type":"hello","protocol":[1],"runtime":{"name":%q},"limits":{"max_line":1048576,"max_records":%d,"max_output_bytes":%d,"max_artifact_bytes":%d},"features":["artifacts","progress","credentials","target_status","report_info"]}`,
		conformanceRuntime, tool.DefaultMaxRecords, tool.DefaultMaxOutputBytes, toolhost.MaxArtifactBytes)
	if err := p.send(hello); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}
	msg, err := p.next(s.opts.Timeout, "hello")
	if err != nil {
		return err
	}
	if v, _ := msg["protocol"].(float64); v != 1 {
		return fmt.Errorf("hello answered protocol %v, want 1", msg["protocol"])
	}
	return nil
}

// handshake runs the Handshake, Validate, StdoutIsProtocol and ExitsOnEOF
// checks on one process.
func (s *toolSuite) handshake() {
	t := s.t
	p, err := s.start()
	if err != nil {
		t.Fatalf("Handshake: start %v: %v", s.m.Run.Argv, err)
		return
	}
	defer p.kill()
	if err := s.hello(p); err != nil {
		t.Errorf("Handshake: %v (stderr: %s)", err, p.stderrText())
		return
	}
	// A newer runtime's message: ignored, not fatal.
	if err := p.send(`{"v":1,"type":"x_conformance_future","x":1}`); err != nil {
		t.Errorf("Handshake: the program stopped reading after an unknown message: %v", err)
		return
	}
	if err := p.send(`{"v":1,"type":"describe"}`); err != nil {
		t.Errorf("Handshake: write describe: %v", err)
		return
	}
	msg, err := p.next(s.opts.Timeout, "manifest")
	if err != nil {
		t.Errorf("Handshake: describe: %v (stderr: %s)", err, p.stderrText())
		return
	}
	raw, _ := json.Marshal(msg["manifest"])
	var self tool.Manifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	want := s.m
	want.Run = nil
	if err := d.Decode(&self); err != nil {
		t.Errorf("Handshake: the described manifest does not decode: %v", err)
	} else if self.Run = nil; self.Normalized().Digest() != want.Digest() {
		t.Errorf("Handshake: the program describes itself differently from its tool.yaml (the runtime refuses it)")
	}

	if err := p.send(`{"v":1,"type":"validate","task":{"id":"conformance-validate","config":{"x_conformance_unknown_key":1}}}`); err != nil {
		t.Errorf("Validate: write: %v", err)
		return
	}
	if v, err := p.next(s.opts.Timeout, "validation"); err != nil {
		t.Errorf("Validate: %v", err)
	} else if ok, _ := v["ok"].(bool); ok {
		t.Errorf("Validate: a configuration with an unknown key was accepted")
	}

	_ = p.in.Close()
	select {
	case <-p.exited:
		var ee *exec.ExitError
		if errors.As(p.exitErr, &ee) {
			t.Errorf("ExitsOnEOF: exit status %d when its input ended, want 0 (stderr: %s)", ee.ExitCode(), p.stderrText())
		}
	case <-time.After(s.opts.Timeout):
		t.Errorf("ExitsOnEOF: still running %s after its input ended", s.opts.Timeout)
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
	for line := range p.lines {
		_ = line // drain
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, line := range p.raw {
		var env struct {
			V    int    `json:"v"`
			Type string `json:"type"`
		}
		if json.Unmarshal(line, &env) != nil || env.V != 1 || env.Type == "" {
			t.Errorf("StdoutIsProtocol: standard output carried %.120q (diagnostics go to standard error)", line)
			return
		}
	}
}

// cancel runs the Cancel check: run the first fixture's task (or a task on
// one placeholder target), cancel at once, expect the result or the exit
// within the grace.
func (s *toolSuite) cancel() {
	t := s.t
	task := tool.Task{ID: "conformance-cancel"}
	if len(s.m.Selftest) > 0 {
		if ft, err := loadFixtureTask(s.dir, s.m.Selftest[0]); err == nil {
			task = ft
			task.ID = "conformance-cancel"
		}
	}
	if len(task.Targets) == 0 && s.m.Class == tool.TargetScan {
		typ := ""
		if len(s.m.Consumes) > 0 {
			typ = s.m.Consumes[0]
		}
		task.Targets = []tool.Target{{Ref: "t1", Type: typ, Value: "conformance.invalid"}}
	}
	p, err := s.start()
	if err != nil {
		t.Errorf("Cancel: start: %v", err)
		return
	}
	defer p.kill()
	if err := s.hello(p); err != nil {
		t.Errorf("Cancel: %v", err)
		return
	}
	workdir, err := os.MkdirTemp("", "openctem-conformance-")
	if err != nil {
		t.Errorf("Cancel: %v", err)
		return
	}
	defer func() { _ = os.RemoveAll(workdir) }()
	run, _ := json.Marshal(map[string]any{"v": 1, "type": "run", "task": struct {
		tool.Task
		Workdir string `json:"workdir"`
	}{task, workdir}})
	if err := p.send(string(run)); err != nil {
		t.Errorf("Cancel: write run: %v", err)
		return
	}
	_ = p.send(`{"v":1,"type":"cancel","reason":"conformance"}`)
	const grace = 10 * time.Second
	if _, err := p.next(grace, "result"); err == nil {
		return
	}
	select {
	case <-p.exited:
	case <-time.After(grace):
		t.Errorf("Cancel: neither a result nor an exit within %s of cancel", grace)
	}
}

func loadFixtureTask(dir string, f tool.Fixture) (tool.Task, error) {
	var task tool.Task
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Task))) //nolint:gosec // a fixture path the manifest validated (relative, no ..)
	if err != nil {
		return task, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&task); err != nil {
		return task, fmt.Errorf("%s: %w", f.Task, err)
	}
	return task, nil
}

// runFixtures runs every self-test fixture through the runtime's host.
func runFixtures(t T, m tool.Manifest, dir string, opts ToolSuiteOptions) {
	if len(m.Selftest) == 0 {
		t.Logf("Fixtures: %s declares no selftest fixture (add one: it is how the platform and doctor prove the tool works)", m.Name)
		return
	}
	host := &toolhost.Host{Sensor: "conformance", RuntimeName: conformanceRuntime}
	for _, f := range m.Selftest {
		task, err := loadFixtureTask(dir, f)
		if err != nil {
			t.Errorf("Fixtures/%s: task: %v", f.Name, err)
			continue
		}
		if task.ID == "" {
			task.ID = "selftest-" + f.Name
		}
		ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
		out, err := host.RunManifest(ctx, m, task, toolhost.RunOptions{Trusted: true, Dir: dir, Credentials: opts.Credentials})
		cancel()
		if err != nil {
			t.Errorf("Fixtures/%s: %v", f.Name, err)
			continue
		}
		if out.Err != nil && out.Status == tool.StatusFailed {
			t.Errorf("Fixtures/%s: the task failed: %v (stderr: %s)", f.Name, out.Err, out.Stderr)
			continue
		}
		if out.Stats.Invalid > 0 {
			t.Errorf("Fixtures/%s: %d invalid message(s) or record(s) refused by the runtime (logs: %+v)", f.Name, out.Stats.Invalid, out.Logs)
		}
		got, err := testkit.Normalize(out.Report)
		if err != nil {
			t.Errorf("Fixtures/%s: %v", f.Name, err)
			continue
		}
		expect := filepath.Join(dir, filepath.FromSlash(f.Expect))
		if opts.Update {
			if err := os.WriteFile(expect, got, 0o600); err != nil {
				t.Errorf("Fixtures/%s: %v", f.Name, err)
			}
			continue
		}
		want, err := os.ReadFile(expect) //nolint:gosec // a fixture path the manifest validated
		if err != nil {
			t.Errorf("Fixtures/%s: expect: %v (OPENCTEM_UPDATE_GOLDEN=1 writes it)", f.Name, err)
			continue
		}
		if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
			t.Errorf("Fixtures/%s: the report differs from %s\n--- got\n%s", f.Name, f.Expect, got)
		}
	}
}
