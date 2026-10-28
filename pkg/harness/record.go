package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"sync"
	"time"
)

// RecordSchema names the run record format.
const RecordSchema = "openctem.ai.run/v1"

// Event types of the run record.
const (
	EventStart         = "start"
	EventModelRequest  = "model_request"
	EventModelResponse = "model_response"
	EventToolDecision  = "tool_decision"
	EventToolResult    = "tool_result"
	EventOutputInvalid = "output_invalid"
	EventFinal         = "final"
	EventStop          = "stop"
)

// Event is one line of the run record. The record is what the platform's
// "why" view shows and what a replay or an eval reads back: model responses
// and tool outputs in full (bounded), requests by digest (a replay that
// produces a different request digest has drifted).
type Event struct {
	Schema   string     `json:"schema,omitempty"`
	Seq      int        `json:"seq"`
	Type     string     `json:"type"`
	At       time.Time  `json:"at"`
	Step     int        `json:"step,omitempty"`
	Digest   string     `json:"digest,omitempty"`
	Response *Response  `json:"response,omitempty"`
	Call     *ToolCall  `json:"call,omitempty"`
	Decision string     `json:"decision,omitempty"`
	Output   string     `json:"output,omitempty"`
	Ref      string     `json:"ref,omitempty"`
	Code     string     `json:"code,omitempty"`
	Meta     *StartMeta `json:"meta,omitempty"`
}

// StartMeta is the first event's description of the run.
type StartMeta struct {
	JobID          string   `json:"job_id"`
	Kind           string   `json:"kind"`
	Playbook       string   `json:"playbook"`
	PlaybookDigest string   `json:"playbook_digest"`
	Provider       string   `json:"provider"`
	Model          string   `json:"model"`
	Tools          []string `json:"tools"`
	Withheld       []string `json:"withheld,omitempty"`
	FenceNonce     string   `json:"fence_nonce"`
	Budgets        Budgets  `json:"budgets"`
}

// Recorder receives the run record, append only.
type Recorder interface {
	Record(e Event) error
}

// JSONLRecorder writes the record as JSON lines and keeps a running SHA-256
// over exactly the bytes written, so the digest in the result binds the
// uploaded record.
type JSONLRecorder struct {
	mu  sync.Mutex
	w   io.Writer
	h   hash.Hash
	seq int
}

// NewJSONLRecorder writes to w (w may be io.Discard when only the digest is
// needed).
func NewJSONLRecorder(w io.Writer) *JSONLRecorder {
	return &JSONLRecorder{w: w, h: sha256.New()}
}

// Record implements Recorder. It assigns the sequence number.
func (r *JSONLRecorder) Record(e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	e.Seq = r.seq
	if e.Seq == 1 {
		e.Schema = RecordSchema
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	r.h.Write(b)
	_, err = r.w.Write(b)
	return err
}

// Digest is "sha256:<hex>" of the bytes written so far.
func (r *JSONLRecorder) Digest() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return "sha256:" + hex.EncodeToString(r.h.Sum(nil))
}

func digestJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}
