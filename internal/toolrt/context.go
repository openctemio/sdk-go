package toolrt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Sink receives what a tool reports. The adapter's sink writes protocol
// messages; the test kit's feeds an Assembler. Records reach the sink
// already checked by the context's own checker.
type Sink interface {
	Asset(a ctis.Asset) error
	// Finding and Dependency name the target ref ("" for none).
	Finding(ref string, f ctis.Finding) error
	Dependency(ref string, d ctis.Dependency) error
	Info(info *tool.ReportInfo) error
	Target(ref string, state tool.TargetState, err *tool.Error)
	Progress(done, total int, msg string)
	Log(level slog.Level, msg string, attrs map[string]any)
	Artifact(name, mediaType string) (io.WriteCloser, error)
}

// Log bounds per task.
const (
	MaxLogMessages = 1000
	MaxLogBytes    = 1 << 20
	maxLogMsg      = 8 << 10
)

// ContextConfig builds a tool.Context.
type ContextConfig struct {
	Manifest tool.Manifest
	Task     tool.Task
	Sink     Sink
	// Secrets are the credentials delivered for this task (already
	// limited to the declared ones by the runtime).
	Secrets map[string]tool.Secret
	Workdir string
}

// NewContext returns the tool.Context a tool runs with: its emitter checks
// every record before the sink sees it, its logger redacts the task's
// secret values and bounds what it keeps, Secret answers only declared
// credentials, and HTTP reaches only what the network permission allows.
func NewContext(ctx context.Context, cfg ContextConfig) tool.Context {
	c := &runCtx{Context: ctx, cfg: cfg, checker: NewChecker(cfg.Manifest), targets: map[string]bool{}}
	for _, t := range cfg.Task.Targets {
		c.targets[t.Ref] = true
	}
	var secrets []string
	for _, s := range cfg.Secrets {
		if v := s.Reveal(); len(v) >= 4 {
			secrets = append(secrets, v)
		}
	}
	// Longest first, so a secret containing another is masked whole.
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	c.redact = func(s string) string {
		for _, v := range secrets {
			s = strings.ReplaceAll(s, v, tool.Redacted)
		}
		return s
	}
	c.logger = slog.New(&sinkHandler{c: c})
	c.http = NewHTTPClient(cfg.Manifest, cfg.Task)
	return c
}

type runCtx struct {
	context.Context
	cfg     ContextConfig
	checker *Checker
	targets map[string]bool
	redact  func(string) string
	logger  *slog.Logger
	http    *http.Client

	logMu    sync.Mutex
	logCount int
	logBytes int
	logCut   bool
}

func (c *runCtx) Log() *slog.Logger  { return c.logger }
func (c *runCtx) Emit() tool.Emitter { return emitter{c} }
func (c *runCtx) Workdir() string    { return c.cfg.Workdir }
func (c *runCtx) HTTP() *http.Client { return c.http }

func (c *runCtx) Progress(done, total int, msg string) {
	c.cfg.Sink.Progress(max(done, 0), max(total, 0), c.redact(CleanString(truncate(msg, 512))))
}

func (c *runCtx) TargetDone(t tool.Target) { c.target(t, tool.StateDone, nil) }

func (c *runCtx) TargetError(t tool.Target, err error) {
	te := tool.AsError(err)
	if te == nil {
		te = tool.AsError(errors.New("target failed"))
	}
	te.Detail = c.redact(tool.CapDetail(CleanString(te.Detail)))
	te.Err = nil
	c.target(t, tool.StateFailed, te)
}

func (c *runCtx) TargetSkipped(t tool.Target, reason string) {
	c.target(t, tool.StateSkipped, &tool.Error{Class: tool.InvalidInput, Detail: c.redact(tool.CapDetail(CleanString(reason)))})
}

func (c *runCtx) target(t tool.Target, st tool.TargetState, err *tool.Error) {
	if !c.targets[t.Ref] {
		c.logger.Warn("target outcome for a target not in the task ignored", "ref", t.Ref)
		return
	}
	c.cfg.Sink.Target(t.Ref, st, err)
}

func (c *runCtx) Artifact(name, mediaType string) (io.WriteCloser, error) {
	return c.cfg.Sink.Artifact(name, mediaType)
}

func (c *runCtx) Secret(name string) (tool.Secret, error) {
	declared := slices.ContainsFunc(c.cfg.Manifest.Permissions.Credentials, func(r tool.CredentialReq) bool { return r.Name == name })
	s, ok := c.cfg.Secrets[name]
	if !declared || !ok {
		return tool.Secret{}, fmt.Errorf("%w: %q", tool.ErrUndeclaredCredential, name)
	}
	return s, nil
}

type emitter struct{ c *runCtx }

// The emitter checks each record locally, so the tool learns at once, and
// hands it to the sink either way: the runtime's own checks decide, and a
// refused record is counted there (quarantine makes the task partial).

func (e emitter) Asset(a ctis.Asset) error {
	checked, err := e.c.checker.Asset(a)
	if err != nil {
		_ = e.c.cfg.Sink.Asset(a)
		return err
	}
	return e.c.cfg.Sink.Asset(checked)
}

func (e emitter) Finding(t tool.Target, f ctis.Finding) error {
	if t.Ref != "" && !e.c.targets[t.Ref] {
		return fmt.Errorf("%w: target %q is not in the task", tool.ErrInvalidRecord, t.Ref)
	}
	checked, err := e.c.checker.Finding(f)
	if err != nil {
		_ = e.c.cfg.Sink.Finding(t.Ref, f)
		return err
	}
	return e.c.cfg.Sink.Finding(t.Ref, checked)
}

func (e emitter) Dependency(t tool.Target, d ctis.Dependency) error {
	if t.Ref != "" && !e.c.targets[t.Ref] {
		return fmt.Errorf("%w: target %q is not in the task", tool.ErrInvalidRecord, t.Ref)
	}
	checked, err := e.c.checker.Dependency(d)
	if err != nil {
		_ = e.c.cfg.Sink.Dependency(t.Ref, d)
		return err
	}
	return e.c.cfg.Sink.Dependency(t.Ref, checked)
}

// Report emits the report's info, then its assets, findings and
// dependencies. The first output-limit error stops it; other refused
// records are skipped and the first such error is returned.
func (e emitter) Report(r *ctis.Report) error {
	if r == nil {
		return nil
	}
	var first error
	keep := func(err error) error {
		if err == nil {
			return nil
		}
		if errors.Is(err, tool.ErrOutputLimit) {
			return err
		}
		if first == nil {
			first = err
		}
		return nil
	}
	if info := tool.InfoOf(r); info != nil {
		checked, err := e.c.checker.Info(info)
		if err == nil {
			err = e.c.cfg.Sink.Info(checked)
		}
		if err := keep(err); err != nil {
			return err
		}
	}
	for _, a := range r.Assets {
		if err := keep(e.Asset(a)); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		if err := keep(e.Finding(tool.Target{}, f)); err != nil {
			return err
		}
	}
	for _, d := range r.Dependencies {
		if err := keep(e.Dependency(tool.Target{}, d)); err != nil {
			return err
		}
	}
	return first
}

// sinkHandler is the slog handler of a tool's logger: it redacts the
// task's secret values and bounds the count and bytes kept.
type sinkHandler struct {
	c     *runCtx
	attrs []slog.Attr
	group string
}

func (h *sinkHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *sinkHandler) Handle(_ context.Context, r slog.Record) error {
	c := h.c
	msg := c.redact(CleanString(truncate(r.Message, maxLogMsg)))
	attrs := map[string]any{}
	add := func(a slog.Attr) {
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		v := a.Value.Resolve()
		var val any
		switch v.Kind() {
		case slog.KindString:
			val = c.redact(CleanString(truncate(v.String(), maxLogMsg)))
		case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool:
			val = v.Any()
		default:
			val = c.redact(CleanString(truncate(fmt.Sprint(v.Any()), maxLogMsg)))
		}
		if len(attrs) < 32 {
			attrs[CleanString(truncate(key, 128))] = val
		}
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool { add(a); return true })
	size := len(msg) + 64*len(attrs)
	c.logMu.Lock()
	if c.logCount >= MaxLogMessages || c.logBytes+size > MaxLogBytes {
		cut := !c.logCut
		c.logCut = true
		c.logMu.Unlock()
		if cut {
			c.cfg.Sink.Log(slog.LevelWarn, "log limit reached; further messages of this task are dropped", nil)
		}
		return nil
	}
	c.logCount++
	c.logBytes += size
	c.logMu.Unlock()
	c.cfg.Sink.Log(r.Level, msg, attrs)
	return nil
}

func (h *sinkHandler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(slices.Clone(h.attrs), as...)
	return &n
}

func (h *sinkHandler) WithGroup(name string) slog.Handler {
	n := *h
	if n.group != "" {
		name = n.group + "." + name
	}
	n.group = name
	return &n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
