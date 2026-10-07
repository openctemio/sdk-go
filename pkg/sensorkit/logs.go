package sensorkit

// Per-command logs (job logs): every log line of a platform command, from
// its tools (toolhost) and from the sensor's own code (CommandLogger), goes
// to two sinks: the sensor's standard error, and the platform, which keeps
// it with the task for a limited time (protocol v2 feature "logs"). Lines
// are redacted, bounded per command, batched, and handed to the outbox,
// which delivers them before the command's result and keeps them across an
// outage. Logs are best effort: losing them never fails a command.

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Command log bounds (per command, on the sensor's side).
const (
	// MaxCommandLogLines is how many lines of one command are sent.
	MaxCommandLogLines = 2000
	// MaxCommandLogBytes is how many bytes of one command are sent.
	MaxCommandLogBytes = 1 << 20

	logBatchLines    = 200
	logBatchBytes    = 64 << 10
	logFlushInterval = 3 * time.Second
	maxLogMsgBytes   = 8 << 10
	maxLogFields     = 32
	maxLogFieldBytes = 1 << 10
	finalFlushWait   = 10 * time.Second
)

// logSender is what the shipper sends batches with (*client.Client).
type logSender interface {
	QueueCommandLogs(ctx context.Context, commandID string, batch protov2.CommandLogsRequest) error
}

// directLogSender sends a batch now, outside the outbox (*client.Client):
// the last lines of a command about to be handed back.
type directLogSender interface {
	SendCommandLogs(ctx context.Context, commandID string, batch protov2.CommandLogsRequest) (*protov2.CommandLogsResponse, error)
}

// maxSeqMemory bounds the finished commands whose next batch number the
// shipper remembers.
const maxSeqMemory = 4096

// logShipper batches the log lines of running commands.
type logShipper struct {
	send   logSender
	redact func(string) string
	logf   func(format string, args ...any)

	mu   sync.Mutex
	cmds map[string]*commandLog
	// nextSeq is the next batch number of a finished command: lines it
	// gets later (a hand-back, a second run here) continue the sequence,
	// because the platform keeps the first batch of each number.
	nextSeq map[string]int
	kick    chan struct{}
	// sendMu keeps a command's batches in seq order on the wire.
	sendMu sync.Mutex
}

type commandLog struct {
	seq      int
	buf      []protov2.CommandLogLine
	sizes    []int // estimated wire size of each buffered line
	bufBytes int
	lines    int
	bytes    int
	dropped  int
}

func newLogShipper(send logSender, redact func(string) string, logf func(string, ...any)) *logShipper {
	return &logShipper{send: send, redact: redact, logf: logf, cmds: map[string]*commandLog{}, nextSeq: map[string]int{}, kick: make(chan struct{}, 1)}
}

// run flushes full and aging buffers until ctx ends.
func (s *logShipper) run(ctx context.Context) {
	t := time.NewTicker(logFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
		s.flushAll(ctx)
	}
}

// add takes one line of command id. It never blocks on the network.
func (s *logShipper) add(id string, l protov2.CommandLogLine) {
	if id == "" {
		return
	}
	l = s.clean(l)
	size := lineSize(l)
	s.mu.Lock()
	c := s.cmds[id]
	if c == nil {
		c = &commandLog{seq: s.nextSeq[id]}
		delete(s.nextSeq, id)
		s.cmds[id] = c
	}
	if c.lines >= MaxCommandLogLines || c.bytes+size > MaxCommandLogBytes {
		c.dropped++
		s.mu.Unlock()
		return
	}
	c.lines++
	c.bytes += size
	c.buf = append(c.buf, l)
	c.sizes = append(c.sizes, size)
	c.bufBytes += size
	full := len(c.buf) >= logBatchLines || c.bufBytes >= logBatchBytes
	s.mu.Unlock()
	if full {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

// finish sends what is left of command id (with a note of what the bounds
// dropped) and forgets it. Called when the command's executor returned,
// before its result is reported, so the logs are queued ahead of it.
func (s *logShipper) finish(ctx context.Context, id string) {
	s.finishVia(ctx, id, false)
}

// CommandLog takes one of the poller's own lines about command id
// (core.CommandLogSink).
func (s *logShipper) CommandLog(_ context.Context, id, level, msg string, fields map[string]any) {
	s.add(id, protov2.CommandLogLine{TS: time.Now().UTC(), Level: level, Msg: msg, Source: "sensor", Fields: fields})
}

// FinishCommandLog sends what is left of command id: queued through the
// outbox ahead of its result, or directly (core.CommandLogSink).
func (s *logShipper) FinishCommandLog(ctx context.Context, id string, direct bool) {
	s.finishVia(ctx, id, direct)
}

func (s *logShipper) finishVia(ctx context.Context, id string, direct bool) {
	s.mu.Lock()
	c := s.cmds[id]
	if c != nil && c.dropped > 0 {
		note := protov2.CommandLogLine{TS: time.Now().UTC(), Level: "warn",
			Msg: fmt.Sprintf("log limit reached: %d further line(s) of this task were not sent", c.dropped)}
		c.buf = append(c.buf, note)
		c.sizes = append(c.sizes, lineSize(note))
	}
	delete(s.cmds, id)
	s.mu.Unlock()
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalFlushWait)
	defer cancel()
	s.sendBatchesVia(ctx, id, c, direct)
	s.mu.Lock()
	if len(s.nextSeq) >= maxSeqMemory {
		clear(s.nextSeq)
	}
	if _, running := s.cmds[id]; !running {
		s.nextSeq[id] = c.seq
	}
	s.mu.Unlock()
}

func (s *logShipper) flushAll(ctx context.Context) {
	s.mu.Lock()
	ids := make([]string, 0, len(s.cmds))
	for id, c := range s.cmds {
		if len(c.buf) > 0 {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.mu.Lock()
		c := s.cmds[id]
		s.mu.Unlock()
		if c != nil {
			s.sendBatches(ctx, id, c)
		}
	}
}

// sendBatches cuts c's buffer into batches and queues them.
func (s *logShipper) sendBatches(ctx context.Context, id string, c *commandLog) {
	s.sendBatchesVia(ctx, id, c, false)
}

// sendBatchesVia sends c's buffer: queued, or directly when direct and the
// sender can (else queued).
func (s *logShipper) sendBatchesVia(ctx context.Context, id string, c *commandLog, direct bool) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	for {
		s.mu.Lock()
		if len(c.buf) == 0 {
			s.mu.Unlock()
			return
		}
		// A batch stays well under the platform's line and body limits.
		n, bytes := 0, 0
		for n < len(c.buf) && n < protov2.MaxCommandLogLines && (n == 0 || bytes+c.sizes[n] <= maxBatchBodyBytes) {
			bytes += c.sizes[n]
			n++
		}
		batch := protov2.CommandLogsRequest{Seq: c.seq, Lines: append([]protov2.CommandLogLine(nil), c.buf[:n]...)}
		c.seq++
		c.buf, c.sizes = c.buf[n:], c.sizes[n:]
		c.bufBytes -= bytes
		if len(c.buf) == 0 {
			c.buf, c.sizes, c.bufBytes = nil, nil, 0
		}
		s.mu.Unlock()
		var err error
		if d, ok := s.send.(directLogSender); ok && direct {
			_, err = d.SendCommandLogs(ctx, id, batch)
		} else {
			err = s.send.QueueCommandLogs(ctx, id, batch)
		}
		if err != nil && s.logf != nil {
			s.logf("command %s: log batch %d not sent: %v", id, batch.Seq, err)
		}
	}
}

// maxBatchBodyBytes bounds the estimated size of one batch (half the
// platform's body limit, for JSON escaping).
const maxBatchBodyBytes = protov2.MaxCommandLogBodyBytes / 2

// lineSize estimates a line's size on the wire.
func lineSize(l protov2.CommandLogLine) int {
	size := len(l.Msg) + len(l.Source) + 64
	for k, v := range l.Fields {
		size += len(k) + len(fmt.Sprint(v)) + 8
	}
	return size
}

// secretKeyRE matches a field name that names a secret.
var secretKeyRE = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|authorization|cookie)`)

var (
	// credentialValueRE is a credential written into a log line: a header
	// ("Authorization: Bearer x", "Cookie: a=b") or a key=value / key: value
	// pair whose key names a secret. The value is replaced, the key kept.
	credentialValueRE = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|client[_-]?secret|pass(?:word|wd)?|session(?:id)?)("?\s*[:=]\s*)("?)(?:(?:bearer|basic|token)\s+)?[^\s"&,;]+`)
	// cookieHeaderRE is a cookie header: every cookie in it is a session.
	cookieHeaderRE = regexp.MustCompile(`(?i)\b((?:set-)?cookie\s*:\s*)[^\r\n"]+`)
	// urlUserinfoRE is the user info of a URL ("https://user:pass@host").
	urlUserinfoRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)
)

// redactLogText masks credentials written into a line's text: header and
// key=value secrets and the user info of URLs. A tool's own secrets are
// masked by the tool host, the sensor's key by the kit; this catches what
// a tool prints about its targets.
func redactLogText(v string) string {
	if v == "" {
		return v
	}
	v = urlUserinfoRE.ReplaceAllString(v, "${1}"+tool.Redacted+"@")
	v = cookieHeaderRE.ReplaceAllString(v, "${1}"+tool.Redacted)
	return credentialValueRE.ReplaceAllString(v, "${1}${2}${3}"+tool.Redacted)
}

// clean redacts, strips control and bidirectional-override characters
// and bounds one line.
func (s *logShipper) clean(l protov2.CommandLogLine) protov2.CommandLogLine {
	switch l.Level {
	case "debug", "info", "warn", "error":
	default:
		l.Level = "info"
	}
	if l.TS.IsZero() {
		l.TS = time.Now().UTC()
	}
	l.Msg = s.text(l.Msg, maxLogMsgBytes)
	l.Source = s.text(l.Source, 64)
	if len(l.Fields) > 0 {
		out := make(map[string]any, min(len(l.Fields), maxLogFields))
		for k, v := range l.Fields {
			if len(out) >= maxLogFields {
				break
			}
			k = s.text(k, 128)
			switch x := v.(type) {
			case bool, int, int64, float64:
				out[k] = x
			default:
				str := s.text(fmt.Sprint(x), maxLogFieldBytes)
				if secretKeyRE.MatchString(k) {
					str = tool.Redacted
				}
				out[k] = str
			}
		}
		l.Fields = out
	}
	return l
}

func (s *logShipper) text(v string, maxBytes int) string {
	v = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			return -1
		}
		return r
	}, v)
	if s.redact != nil {
		v = s.redact(v)
	}
	v = redactLogText(v)
	if len(v) > maxBytes {
		v = v[:maxBytes]
	}
	return v
}

// toolLogSink is the toolhost sink: a tool's lines go to the command the
// task runs for.
func (s *logShipper) toolLogSink(ctx context.Context, name string, l toolhost.LogLine) {
	s.add(core.CommandIDFromContext(ctx), protov2.CommandLogLine{TS: time.Now().UTC(), Level: l.Level, Msg: l.Msg,
		Source: name, Fields: l.Fields})
}

// commandLogHandler is the slog handler of CommandLogger: the sensor's
// standard error and the command's platform log.
type commandLogHandler struct {
	local slog.Handler
	ship  *logShipper
	id    string
	attrs []slog.Attr
	group string
}

func (h *commandLogHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelInfo || h.local.Enabled(ctx, l)
}

func (h *commandLogHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.local.Enabled(ctx, r.Level) {
		_ = h.local.Handle(ctx, r)
	}
	if h.ship == nil || r.Level < slog.LevelInfo {
		return nil
	}
	fields := map[string]any{}
	add := func(a slog.Attr) {
		k := a.Key
		if h.group != "" {
			k = h.group + "." + k
		}
		v := a.Value.Resolve()
		switch v.Kind() {
		case slog.KindBool, slog.KindInt64, slog.KindFloat64:
			fields[k] = v.Any()
		default:
			fields[k] = v.String()
		}
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool { add(a); return true })
	lv := "info"
	switch {
	case r.Level >= slog.LevelError:
		lv = "error"
	case r.Level >= slog.LevelWarn:
		lv = "warn"
	}
	h.ship.add(h.id, protov2.CommandLogLine{TS: r.Time.UTC(), Level: lv, Msg: r.Message, Fields: fields})
	return nil
}

func (h *commandLogHandler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.local = h.local.WithAttrs(as)
	n.attrs = append(append([]slog.Attr(nil), h.attrs...), as...)
	return &n
}

func (h *commandLogHandler) WithGroup(name string) slog.Handler {
	n := *h
	n.local = h.local.WithGroup(name)
	if n.group != "" {
		name = n.group + "." + name
	}
	n.group = name
	return &n
}

// ToolLogSink is the log sink for a tool host the sensor builds itself
// (toolhost.Host.LogSink): a tool's lines go to the platform with the
// command the task runs for (core.CommandIDFromContext), redacted and
// bounded like the kit's own tools. It may be taken before Run; until the
// kit runs with a platform client, and outside a command, lines are not
// sent. Lines never block the tool: past the per-command bounds they are
// dropped and counted.
func (k *Kit) ToolLogSink() func(ctx context.Context, tool string, l toolhost.LogLine) {
	return func(ctx context.Context, name string, l toolhost.LogLine) {
		if ship := k.logs.Load(); ship != nil {
			ship.toolLogSink(ctx, name, l)
		}
	}
}

// CommandLogger is the logger of the platform command ctx runs for (an
// executor added with HandleCommand gets it from its context): lines at
// info and above go to the sensor's standard error and to the command's
// log on the platform, redacted (the sensor's key, field names that name a
// secret, tool.Secret values) and bounded per command. Outside a command,
// or before Run, it logs locally only.
func (k *Kit) CommandLogger(ctx context.Context) *slog.Logger {
	return slog.New(&commandLogHandler{local: k.localLogHandler(), ship: k.logs.Load(), id: core.CommandIDFromContext(ctx)})
}

// redactKey masks the sensor's key in v.
func (k *Kit) redactKey(v string) string {
	if key := strings.TrimSpace(k.s.apiKey); len(key) >= 8 {
		v = strings.ReplaceAll(v, key, tool.Redacted)
	}
	return v
}

// localLogHandler writes to the sensor's standard error at info and above,
// with the same redaction as the platform sink: the sensor's key, and the
// value of any field whose name names a secret.
func (k *Kit) localLogHandler() slog.Handler {
	return slog.NewTextHandler(k.errw, &slog.HandlerOptions{Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey || a.Key == slog.LevelKey {
				return a
			}
			if a.Key != slog.MessageKey && secretKeyRE.MatchString(a.Key) {
				return slog.String(a.Key, tool.Redacted)
			}
			if a.Value.Kind() == slog.KindString {
				return slog.String(a.Key, k.redactKey(a.Value.String()))
			}
			return a
		}})
}

// startLogShipper creates the shipper (when the kit has a platform
// client) and wires it into the tool host; the poller is its other source
// and sends a command's last lines before its result.
func (k *Kit) startLogShipper(ctx context.Context) {
	if k.client == nil {
		return
	}
	ship := newLogShipper(k.client, k.redactKey, func(f string, a ...any) {
		if k.s.verbose {
			_, _ = fmt.Fprintf(k.errw, "Warning: "+f+"\n", a...)
		}
	})
	k.logs.Store(ship)
	go ship.run(ctx)
	h := k.toolHost()
	h.LogSink = ship.toolLogSink
	if h.Logger == nil {
		h.Logger = slog.New(k.localLogHandler())
	}
}

var (
	_ logSender           = (*client.Client)(nil)
	_ directLogSender     = (*client.Client)(nil)
	_ core.CommandLogSink = (*logShipper)(nil)
)

// commandExecFunc is a function as a core.CommandExecutor.
type commandExecFunc func(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error)

func (f commandExecFunc) Execute(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
	return f(ctx, cmd)
}
