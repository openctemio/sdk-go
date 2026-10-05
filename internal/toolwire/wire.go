// Package toolwire holds the messages of adapter protocol v1: newline-
// delimited JSON between the runtime and a tool process, over the tool's
// stdin and stdout, one task per process (docs/rfcs/sensor-sdk-v2.md,
// D.4.2). Both sides (pkg/tool/adapter, pkg/sensorkit/toolhost) use these
// types; the protocol's JSON Schema is in pkg/tool/schema.
package toolwire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// Version is the protocol version.
const Version = 1

// MaxLine bounds one message.
const MaxLine = 1 << 20

// Message types, runtime to adapter.
const (
	TypeHello    = "hello"
	TypeDescribe = "describe"
	TypeValidate = "validate"
	TypeRun      = "run"
	TypeCancel   = "cancel"
)

// Message types, adapter to runtime (besides hello).
const (
	TypeManifest     = "manifest"
	TypeValidation   = "validation"
	TypeLog          = "log"
	TypeProgress     = "progress"
	TypeRecord       = "record"
	TypeReportInfo   = "report_info"
	TypeTargetStatus = "target_status"
	TypeArtifact     = "artifact"
	TypeHeartbeat    = "heartbeat"
	TypeResult       = "result"
)

// Features the runtime offers in its hello.
var Features = []string{"artifacts", "progress", "credentials", "target_status", "report_info"}

// Envelope is the part every message has.
type Envelope struct {
	V    int    `json:"v"`
	Type string `json:"type"`
}

// RuntimeInfo names the runtime.
type RuntimeInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	OS      string `json:"os,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

// Limits are the runtime's limits, announced in its hello.
type Limits struct {
	MaxLine          int   `json:"max_line"`
	MaxRecords       int   `json:"max_records"`
	MaxOutputBytes   int64 `json:"max_output_bytes"`
	MaxArtifactBytes int64 `json:"max_artifact_bytes"`
}

// Hello is the runtime's first message.
type Hello struct {
	Envelope
	Protocol []int       `json:"protocol"`
	Runtime  RuntimeInfo `json:"runtime"`
	Limits   Limits      `json:"limits"`
	Features []string    `json:"features,omitempty"`
}

// SDKInfo names the adapter's SDK.
type SDKInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// HelloReply is the adapter's first message: the version it chose.
type HelloReply struct {
	Envelope
	Protocol int      `json:"protocol"`
	SDK      SDKInfo  `json:"sdk"`
	Features []string `json:"features,omitempty"`
}

// Credential is a credential delivered with a run: only those the manifest
// declares and the operator stored.
type Credential struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RunTask is the task as the adapter receives it.
type RunTask struct {
	tool.Task
	// Workdir is the task's private directory.
	Workdir     string       `json:"workdir"`
	Credentials []Credential `json:"credentials,omitempty"`
}

// Run starts the task.
type Run struct {
	Envelope
	Task RunTask `json:"task"`
}

// Validate asks the adapter to check a task.
type Validate struct {
	Envelope
	Task tool.Task `json:"task"`
}

// Cancel asks the adapter to stop.
type Cancel struct {
	Envelope
	Reason string `json:"reason,omitempty"`
}

// ManifestMsg answers describe.
type ManifestMsg struct {
	Envelope
	Manifest json.RawMessage `json:"manifest"`
}

// ValidationError is one problem of a task.
type ValidationError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Validation answers validate.
type Validation struct {
	Envelope
	OK     bool              `json:"ok"`
	Errors []ValidationError `json:"errors,omitempty"`
}

// Log is a log line.
type Log struct {
	Envelope
	Level  string         `json:"level"`
	Msg    string         `json:"msg"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Progress reports progress.
type Progress struct {
	Envelope
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Msg   string `json:"msg,omitempty"`
}

// Record is one CTIS record.
type Record struct {
	Envelope
	// Kind is asset, finding or dependency.
	Kind string `json:"kind"`
	// Target is the ref of the target the record belongs to ("" none).
	Target string          `json:"target,omitempty"`
	Data   json.RawMessage `json:"data"`
}

// ReportInfoMsg carries a report's tool, metadata and properties.
type ReportInfoMsg struct {
	Envelope
	Info json.RawMessage `json:"info"`
}

// Error is a categorized error on the wire.
type Error struct {
	Class        tool.ErrorClass `json:"class"`
	Retryable    bool            `json:"retryable,omitempty"`
	RetryAfterMs int64           `json:"retry_after_ms,omitempty"`
	Detail       string          `json:"detail,omitempty"`
}

// FromError converts a tool error for the wire (detail capped).
func FromError(e *tool.Error) *Error {
	if e == nil {
		return nil
	}
	return &Error{Class: e.Class, Retryable: e.Retryable, RetryAfterMs: e.RetryAfter.Milliseconds(), Detail: tool.CapDetail(e.Detail)}
}

// ToError converts a wire error. A class a tool may not claim becomes
// tool_error.
func (e *Error) ToError() *tool.Error {
	if e == nil {
		return nil
	}
	out := &tool.Error{Class: e.Class, Retryable: e.Retryable, RetryAfter: time.Duration(e.RetryAfterMs) * time.Millisecond, Detail: tool.CapDetail(e.Detail)}
	if !out.Class.Valid() {
		out.Class, out.Retryable = tool.ToolError, false
	}
	if out.Retryable && !out.Class.Retryable() {
		// A tool may only turn retrying off.
		out.Retryable = false
	}
	if out.RetryAfter < 0 || out.RetryAfter > 24*time.Hour {
		out.RetryAfter = 0
	}
	return out
}

// TargetStatus reports one target's outcome.
type TargetStatus struct {
	Envelope
	Target string           `json:"target"`
	Status tool.TargetState `json:"status"`
	Error  *Error           `json:"error,omitempty"`
}

// Artifact announces an artifact file in the task's directory.
type Artifact struct {
	Envelope
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
	// Path is relative to the task's directory.
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Stats are the adapter's own counters (informational).
type Stats struct {
	Records int `json:"records,omitempty"`
}

// Result is the adapter's last message.
type Result struct {
	Envelope
	Status tool.Status `json:"status"`
	Error  *Error      `json:"error,omitempty"`
	Stats  Stats       `json:"stats,omitzero"`
}

// Writer writes messages, one per line, safely from several goroutines.
type Writer struct {
	mu sync.Mutex
	w  *bufio.Writer
}

// NewWriter writes to w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: bufio.NewWriterSize(w, 64<<10)} }

// ErrLineTooLong is the error of a message larger than MaxLine.
var ErrLineTooLong = errors.New("message larger than the protocol's line limit")

// Write encodes msg (which must embed an Envelope with V and Type set) and
// flushes it.
func (w *Writer) Write(msg any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(msg); err != nil {
		return err
	}
	if buf.Len() > MaxLine {
		return fmt.Errorf("%w (%d bytes)", ErrLineTooLong, buf.Len())
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.w.Write(buf.Bytes()); err != nil {
		return err
	}
	return w.w.Flush()
}

// Env is an Envelope of type t.
func Env(t string) Envelope { return Envelope{V: Version, Type: t} }

// Reader reads messages, refusing lines longer than MaxLine.
type Reader struct {
	r *bufio.Reader
}

// NewReader reads from r.
func NewReader(r io.Reader) *Reader { return &Reader{r: bufio.NewReaderSize(r, 64<<10)} }

// Next returns the next non-empty line (without its line ending). A line
// longer than MaxLine is ErrLineTooLong (the stream cannot be trusted
// after it).
func (r *Reader) Next() ([]byte, error) {
	for {
		var line []byte
		for {
			chunk, err := r.r.ReadSlice('\n')
			if len(line)+len(chunk) > MaxLine+1 {
				return nil, ErrLineTooLong
			}
			line = append(line, chunk...)
			if err == nil {
				break
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if errors.Is(err, io.EOF) && len(line) > 0 {
				break
			}
			return nil, err
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		return line, nil
	}
}

// Peek decodes the envelope of a line.
func Peek(line []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(line, &e); err != nil {
		return e, err
	}
	if e.Type == "" {
		return e, errors.New("message without a type")
	}
	return e, nil
}

// Decode decodes a line into msg. Members msg does not know are ignored
// (a newer peer may add some); records' data is decoded strictly where it
// is checked.
func Decode(line []byte, msg any) error {
	d := json.NewDecoder(bytes.NewReader(line))
	if err := d.Decode(msg); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data after the message")
	}
	return nil
}
