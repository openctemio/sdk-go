package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/internal/toolwire"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// MaxArtifactBytes bounds one artifact on the tool side (the runtime
// enforces its own limit too).
const MaxArtifactBytes = 64 << 20

var artifactNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// sink writes what the tool reports as protocol messages.
type sink struct {
	w       *toolwire.Writer
	workdir string

	mu        sync.Mutex
	records   int
	rejected  bool
	lastProg  time.Time
	artifacts map[string]bool
}

func newSink(w *toolwire.Writer, workdir string) *sink {
	return &sink{w: w, workdir: workdir, artifacts: map[string]bool{}}
}

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records
}

func (s *sink) refused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejected
}

func (s *sink) record(kind, ref string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: %v", tool.ErrInvalidRecord, err)
	}
	if err := s.w.Write(toolwire.Record{Envelope: toolwire.Env(toolwire.TypeRecord), Kind: kind, Target: ref, Data: b}); err != nil {
		if errors.Is(err, toolwire.ErrLineTooLong) {
			s.mu.Lock()
			s.rejected = true
			s.mu.Unlock()
			return fmt.Errorf("%w: %v (put large data in an artifact)", tool.ErrInvalidRecord, err)
		}
		return err
	}
	s.mu.Lock()
	s.records++
	s.mu.Unlock()
	return nil
}

func (s *sink) Asset(a ctis.Asset) error { return s.record(tool.KindAsset, "", a) }

func (s *sink) Finding(ref string, f ctis.Finding) error { return s.record(tool.KindFinding, ref, f) }

func (s *sink) Dependency(ref string, d ctis.Dependency) error {
	return s.record(tool.KindDependency, ref, d)
}

func (s *sink) Info(info *tool.ReportInfo) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return s.w.Write(toolwire.ReportInfoMsg{Envelope: toolwire.Env(toolwire.TypeReportInfo), Info: b})
}

func (s *sink) Target(ref string, st tool.TargetState, err *tool.Error) {
	_ = s.w.Write(toolwire.TargetStatus{Envelope: toolwire.Env(toolwire.TypeTargetStatus), Target: ref, Status: st, Error: toolwire.FromError(err)})
}

// Progress is throttled to one message a second (the last one of a run
// may be dropped; the result follows anyway).
func (s *sink) Progress(done, total int, msg string) {
	s.mu.Lock()
	if time.Since(s.lastProg) < time.Second {
		s.mu.Unlock()
		return
	}
	s.lastProg = time.Now()
	s.mu.Unlock()
	_ = s.w.Write(toolwire.Progress{Envelope: toolwire.Env(toolwire.TypeProgress), Done: done, Total: total, Msg: msg})
}

func (s *sink) Log(level slog.Level, msg string, attrs map[string]any) {
	lv := "info"
	switch {
	case level >= slog.LevelError:
		lv = "error"
	case level >= slog.LevelWarn:
		lv = "warn"
	case level < slog.LevelInfo:
		lv = "debug"
	}
	_ = s.w.Write(toolwire.Log{Envelope: toolwire.Env(toolwire.TypeLog), Level: lv, Msg: msg, Fields: attrs})
}

func (s *sink) Verdict(ref string, v tool.Verdict, detail string) {
	_ = s.w.Write(toolwire.VerdictMsg{Envelope: toolwire.Env(toolwire.TypeVerdict), Item: ref, Verdict: v, Detail: detail})
}

// Artifact creates <workdir>/artifacts/<name>; closing it announces the
// file with its size and digest.
func (s *sink) Artifact(name, mediaType string) (io.WriteCloser, error) {
	if !artifactNameRE.MatchString(name) {
		return nil, errors.New("artifact name must be a plain file name ([A-Za-z0-9._-], at most 128)")
	}
	if s.workdir == "" {
		return nil, errors.New("no task directory for artifacts")
	}
	s.mu.Lock()
	if s.artifacts[name] {
		s.mu.Unlock()
		return nil, fmt.Errorf("artifact %q already exists", name)
	}
	s.artifacts[name] = true
	s.mu.Unlock()
	dir := filepath.Join(s.workdir, "artifacts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	rel := filepath.Join("artifacts", name)
	f, err := os.OpenFile(filepath.Join(s.workdir, rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return &artifactWriter{s: s, f: f, h: sha256.New(), name: name, mediaType: mediaType, rel: rel}, nil
}

type artifactWriter struct {
	s         *sink
	f         *os.File
	h         hash.Hash
	n         int64
	name      string
	mediaType string
	rel       string
	closed    bool
}

func (a *artifactWriter) Write(p []byte) (int, error) {
	if a.n+int64(len(p)) > MaxArtifactBytes {
		return 0, fmt.Errorf("artifact larger than %d bytes", MaxArtifactBytes)
	}
	n, err := a.f.Write(p)
	a.n += int64(n)
	a.h.Write(p[:n])
	return n, err
}

func (a *artifactWriter) Close() error {
	if a.closed {
		return nil
	}
	a.closed = true
	if err := a.f.Close(); err != nil {
		return err
	}
	return a.s.w.Write(toolwire.Artifact{Envelope: toolwire.Env(toolwire.TypeArtifact), Name: a.name,
		MediaType: a.mediaType, Path: filepath.ToSlash(a.rel), SHA256: hex.EncodeToString(a.h.Sum(nil)), Size: a.n})
}
