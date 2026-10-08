package toolhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

var placeholderRE = regexp.MustCompile(`\{\{\s*([^{}]*?)\s*\}\}`)

// Files the exec profile writes into the task directory.
const (
	targetsFile     = "targets.txt"
	targetsJSONFile = "targets.json"
	configFile      = "config.json"
	// webScopeFile is the job's web scope (webscope.Scope as JSON; "null"
	// without one): an exec-profile crawler reads it to keep to the scope.
	webScopeFile = "web_scope.json"
	outputFile   = "output"
)

// runExec runs a zero-code tool: the runtime writes the targets and the
// config into the task directory, expands run.argv (closed placeholders,
// no shell, every substituted value checked like a user's extra argument),
// runs the CLI in the sandbox and reads its CTIS or SARIF output through
// the same checks as any record. All targets share the outcome.
func (h *Host) runExec(ctx context.Context, m tool.Manifest, task tool.Task, o RunOptions, argv []string) (*Outcome, error) {
	start := time.Now()
	if task.IsRetest() {
		return h.failedOutcome(m, task, tool.AsError(tool.Invalid("an exec-profile tool cannot retest"))), nil
	}
	p, ierr, err := h.prepare(ctx, m, task, o)
	if err != nil {
		return nil, err
	}
	if ierr != nil {
		return h.failedOutcome(m, task, ierr), nil
	}
	defer func() { _ = os.RemoveAll(p.workdir) }()
	if isMappedFormat(m.Run.Output.Format) {
		// Loaded before the tool starts: a missing, invalid or changed
		// mapping file refuses the task instead of wasting a scan.
		mp, err := tool.LoadMappingFile(o.Dir, m.Run.Output.Mapping, m.Run.Output.MappingDigest)
		if err != nil {
			return h.failedOutcome(m, task, &tool.Error{Class: tool.ToolError, Detail: tool.CapDetail(err.Error())}), nil
		}
		p.mapping = mp
	}
	if err := writeExecFiles(p); err != nil {
		return nil, err
	}
	argv, ierr = expandArgv(argv, p)
	if ierr != nil {
		return h.failedOutcome(m, task, ierr), nil
	}
	_, _, maxBytes, _ := m.Resources.Limits()
	timeout := p.timeout
	stdout := &cappedBuffer{max: int(min(maxBytes, 1<<30))}
	stderr := &cappedBuffer{max: MaxStderr}
	be := h.backend()
	eg, err := h.startEgress(ctx, be, p)
	if err != nil {
		return nil, err
	}
	defer eg.stop()
	t, err := be.Prepare(executor.TaskSpec{
		ID: m.Name, Argv: argv, Env: core.ScannerEnvironFor(envOwner(m), o.Env), SetEnv: o.Env, Dir: p.workdir,
		WritePaths: append([]string{p.workdir}, o.WritePaths...), Limits: o.Limits,
		Network: networkClass(m.Permissions.Network), Stdout: stdout, Stderr: stderr,
		Hooks:       executor.ProcessHooks{Configure: core.ConfigureScannerProcess, Started: core.ApplyScannerPriority, Finished: core.ReapScannerProcess},
		EgressProxy: eg.proxyPath(), EgressDNS: eg.dnsPath(),
	})
	if err != nil {
		return nil, fmt.Errorf("toolhost: %w", err)
	}
	defer func() { _ = t.Cleanup() }()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := t.Start(runCtx); err != nil {
		return nil, fmt.Errorf("toolhost: start %s: %w", m.Name, err)
	}
	res, _ := t.Wait()

	out := &Outcome{Sandbox: be.Status(), ExitCode: -1}
	if res != nil {
		out.ExitCode, out.Sandbox = res.ExitCode, res.Sandbox
	}
	out.Stderr = p.redact(toolrt.CleanString(stderr.String()))
	var runErr *tool.Error
	partial := false
	switch {
	case ctx.Err() != nil:
		runErr = &tool.Error{Class: tool.Canceled, Detail: "canceled"}
	case runCtx.Err() != nil:
		runErr = &tool.Error{Class: tool.Timeout, Retryable: true, Detail: "task timeout"}
	case stdout.Overflowed():
		runErr = &tool.Error{Class: tool.ResourceExhausted, Retryable: true, Detail: "output larger than the limit"}
	default:
		switch outcome := exitOutcome(m.Run.ExitCodes, out.ExitCode); outcome {
		case "ok":
		case "partial":
			partial = true
		default:
			runErr = &tool.Error{Class: tool.ErrorClass(outcome), Retryable: tool.ErrorClass(outcome).Retryable(),
				Detail: fmt.Sprintf("exited with status %d", out.ExitCode)}
		}
	}
	if runErr == nil {
		data := stdout.Bytes()
		if m.Run.Output.From == "file" {
			data, err = readOutputFile(filepath.Join(p.workdir, outputFile), maxBytes)
			if err != nil {
				runErr = &tool.Error{Class: tool.OutputRejected, Detail: "output file: " + err.Error()}
			}
		}
		if runErr == nil {
			if err := ingestOutput(ctx, p, m.Run.Output.Format, data); err != nil {
				if errors.Is(err, tool.ErrOutputLimit) {
					partial = true
				} else {
					runErr = &tool.Error{Class: tool.OutputRejected, Detail: p.redact(tool.CapDetail(err.Error()))}
				}
			}
		}
	}
	for _, tg := range p.task.Targets {
		if runErr == nil {
			_ = p.asm.Target(tg.Ref, tool.StateDone, nil)
		} else {
			_ = p.asm.Target(tg.Ref, tool.StateFailed, runErr)
		}
	}
	out.Err = runErr
	out.Status = p.asm.Status(runErr)
	if runErr == nil && partial {
		out.Status = tool.StatusPartial
	}
	out.Report = p.asm.Report(time.Now().UTC())
	st := p.asm.Checker().Stats()
	out.Stats = Stats{Records: st.Records, Bytes: st.Bytes, Capped: st.Capped, Quarantined: st.Quarantined, Invalid: st.Invalid}
	for _, r := range p.asm.Results() {
		to := TargetOutcome{Ref: r.Target.Ref, Value: r.Target.Value, State: r.State}
		if r.Error != nil {
			to.Class, to.Detail = r.Error.Class, r.Error.Detail
		}
		out.Targets = append(out.Targets, to)
	}
	p.checkContract(out)
	p.addRefused(out)
	if p.rateLine != nil {
		out.Logs = append(out.Logs, *p.rateLine)
	}
	out.Logs = append(out.Logs, p.notes...)
	if eg != nil {
		out.Egress, out.EgressDropped = eg.stop()
		lines := egressLog(out.Egress)
		out.Logs = append(out.Logs, lines...)
		if h.LogSink != nil {
			for _, l := range lines {
				h.LogSink(ctx, m.Name, l)
			}
		}
	}
	out.Duration = time.Since(start)
	h.stamp(out, m, p.task, "exec profile")
	return out, nil
}

func exitOutcome(codes map[string]string, code int) string {
	if v, ok := codes[strconv.Itoa(code)]; ok {
		return v
	}
	if code == 0 {
		return "ok"
	}
	return string(tool.ToolError)
}

func writeExecFiles(p *prepared) error {
	var lines []string
	for _, t := range p.task.Targets {
		lines = append(lines, t.Value)
	}
	txt := strings.Join(lines, "\n")
	if txt != "" {
		txt += "\n"
	}
	tj, err := json.Marshal(p.task.Targets)
	if err != nil {
		return err
	}
	ws, err := json.Marshal(p.task.WebScope)
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{targetsFile: []byte(txt), targetsJSONFile: tj, configFile: p.task.Config, webScopeFile: ws} {
		if err := os.WriteFile(filepath.Join(p.workdir, name), data, 0o600); err != nil {
			return fmt.Errorf("toolhost: %w", err)
		}
	}
	return nil
}

// expandArgv substitutes the placeholders. A substituted value never
// starts with "-", contains no control character and passes the
// dangerous-flag check user extra arguments pass.
func expandArgv(argv []string, p *prepared) ([]string, *tool.Error) {
	var cfg map[string]any
	_ = json.Unmarshal(p.task.Config, &cfg)
	var target *tool.Target
	out := make([]string, len(argv))
	var subErr *tool.Error
	for i, a := range argv {
		out[i] = placeholderRE.ReplaceAllStringFunc(a, func(ph string) string {
			name := strings.TrimSpace(placeholderRE.FindStringSubmatch(ph)[1])
			var v string
			switch {
			case name == "task.targets_file":
				return filepath.Join(p.workdir, targetsFile)
			case name == "task.targets_json":
				return filepath.Join(p.workdir, targetsJSONFile)
			case name == "task.config_file":
				return filepath.Join(p.workdir, configFile)
			case name == "task.web_scope_file":
				return filepath.Join(p.workdir, webScopeFile)
			case name == "task.output":
				return filepath.Join(p.workdir, outputFile)
			case name == "task.workdir":
				return p.workdir
			case name == "http.user_agent":
				v = toolrt.EffectiveUserAgent(p.m)
			case strings.HasPrefix(name, "target."):
				if len(p.task.Targets) != 1 {
					subErr = tool.AsError(tool.Invalid("{{%s}} needs exactly one target per task; this task has %d", name, len(p.task.Targets)))
					return ""
				}
				target = &p.task.Targets[0]
				switch name {
				case "target.value":
					v = target.Value
				case "target.host":
					v = target.Host()
				case "target.port":
					if n := target.Port(); n > 0 {
						v = strconv.Itoa(n)
					}
				case "target.url":
					v = target.URL("")
				}
			case strings.HasPrefix(name, "config."):
				val, ok := cfg[strings.TrimPrefix(name, "config.")]
				if !ok {
					return ""
				}
				switch x := val.(type) {
				case string:
					v = x
				case bool:
					v = strconv.FormatBool(x)
				case float64:
					v = strconv.FormatFloat(x, 'f', -1, 64)
				default:
					subErr = tool.AsError(tool.Invalid("{{%s}} is not a scalar", name))
					return ""
				}
			default:
				subErr = tool.AsError(tool.Invalid("unknown placeholder {{%s}}", name))
				return ""
			}
			if err := checkValue(v); err != nil {
				subErr = tool.AsError(tool.Invalid("{{%s}}: %v", name, err))
				return ""
			}
			return v
		})
	}
	if subErr != nil {
		return nil, subErr
	}
	return out, nil
}

func checkValue(v string) error {
	if strings.HasPrefix(v, "-") {
		return errors.New("a value cannot start with '-' (flag injection)")
	}
	if strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return errors.New("control characters")
	}
	return core.ValidateExtraArgs([]string{v})
}

func readOutputFile(path string, maxBytes int64) ([]byte, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, errors.New("missing or not a plain file")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > maxBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxBytes)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ingestOutput feeds the CLI's output through the record checks.
func ingestOutput(ctx context.Context, p *prepared, format string, data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	switch format {
	case tool.OutputSARIF:
		opts := &core.ParseOptions{}
		if len(p.task.Targets) == 1 {
			opts.AssetValue = p.task.Targets[0].Value
			opts.AssetType = ctis.AssetType(p.task.Targets[0].Type)
		}
		r, err := (&core.SARIFParser{}).Parse(ctx, data, opts)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return ingestCTIS(p, raw)
	case tool.OutputCTIS:
		return ingestCTIS(p, data)
	case tool.OutputJSON, tool.OutputJSONL:
		return ingestMapped(ctx, p, data)
	case tool.OutputJSONLCTIS:
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var rec struct {
				Kind   string          `json:"kind"`
				Target string          `json:"target,omitempty"`
				Data   json.RawMessage `json:"data"`
			}
			d := json.NewDecoder(bytes.NewReader(line))
			d.DisallowUnknownFields()
			if err := d.Decode(&rec); err != nil {
				return fmt.Errorf("jsonl-ctis line: %w", err)
			}
			if err := ingestRecord(p, rec.Kind, rec.Target, rec.Data); err != nil {
				return err
			}
		}
		return nil
	}
	if isNamedFormat(format) {
		return ingestNamed(ctx, p, format, data)
	}
	return fmt.Errorf("unknown output format %q", format)
}

func ingestCTIS(p *prepared, data []byte) error {
	var r struct {
		Version      string            `json:"version"`
		Schema       string            `json:"$schema"`
		Metadata     json.RawMessage   `json:"metadata"`
		Tool         json.RawMessage   `json:"tool"`
		Assets       []json.RawMessage `json:"assets"`
		Findings     []json.RawMessage `json:"findings"`
		Dependencies []json.RawMessage `json:"dependencies"`
		Endpoints    []json.RawMessage `json:"endpoints"`
		Properties   json.RawMessage   `json:"properties"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return fmt.Errorf("CTIS report: %w", err)
	}
	if r.Version != "" && !ctis.IsCompatibleVersion(r.Version) {
		return fmt.Errorf("CTIS version %q is not supported", r.Version)
	}
	info := map[string]json.RawMessage{}
	if len(r.Tool) > 0 {
		info["tool"] = r.Tool
	}
	if len(r.Metadata) > 0 {
		var md map[string]json.RawMessage
		if err := json.Unmarshal(r.Metadata, &md); err == nil {
			delete(md, "timestamp")
			if b, err := json.Marshal(md); err == nil {
				info["metadata"] = b
			}
		}
	}
	if len(r.Properties) > 0 {
		info["properties"] = r.Properties
	}
	if len(info) > 0 {
		b, _ := json.Marshal(info)
		ri, err := p.asm.Checker().InfoJSON(b)
		if err != nil {
			return err
		}
		p.asm.SetInfo(ri)
	}
	for _, a := range r.Assets {
		if err := ingestRecord(p, tool.KindAsset, "", a); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		if err := ingestRecord(p, tool.KindFinding, "", f); err != nil {
			return err
		}
	}
	for _, dep := range r.Dependencies {
		if err := ingestRecord(p, tool.KindDependency, "", dep); err != nil {
			return err
		}
	}
	for _, e := range r.Endpoints {
		if err := ingestRecord(p, tool.KindEndpoint, "", e); err != nil {
			return err
		}
	}
	return nil
}

// ingestRecord checks one record. An undeclared or invalid record is
// skipped (counted); the output limit stops the ingest.
func ingestRecord(p *prepared, kind, ref string, data json.RawMessage) error {
	chk := p.asm.Checker()
	var err error
	switch kind {
	case tool.KindAsset:
		var a ctis.Asset
		if a, err = chk.AssetJSON(data); err == nil {
			p.asm.AddCheckedAsset(a)
		}
	case tool.KindFinding:
		var f ctis.Finding
		if f, err = chk.FindingJSON(data); err == nil {
			err = p.asm.AddCheckedFinding(ref, f)
		}
	case tool.KindDependency:
		var d ctis.Dependency
		if d, err = chk.DependencyJSON(data); err == nil {
			p.asm.AddCheckedDependency(d)
		}
	case tool.KindEndpoint:
		var e ctis.Endpoint
		if e, err = chk.EndpointJSON(data); err == nil {
			p.asm.AddCheckedEndpoint(e)
		}
	default:
		return fmt.Errorf("unknown record kind %q", kind)
	}
	if errors.Is(err, tool.ErrOutputLimit) {
		return err
	}
	return nil
}
