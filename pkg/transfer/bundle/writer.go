package bundle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Writer defaults.
const (
	// DefaultTargetRecords is the average records per chunk: a chunk ends
	// after a record whose id hashes to 0 modulo this (content-defined).
	DefaultTargetRecords = 2000
	// DefaultMaxUncompressed is the hard cap of a chunk's JSON bytes
	// (about 4-8 MiB compressed for typical feed records).
	DefaultMaxUncompressed = 48 << 20
)

// WriterOptions configure a Writer.
type WriterOptions struct {
	Feed         string
	Sequence     uint64
	Kind         string // KindSnapshot or KindDelta
	BaseSequence uint64 // a delta's base
	// TargetRecords is the average records per chunk (content-defined
	// boundary); MaxRecords (default 4x TargetRecords) and MaxUncompressed
	// are hard caps. A chunk holds at least TargetRecords/4 records unless
	// a cap or the stream's end cuts it.
	TargetRecords   int
	MaxRecords      int
	MaxUncompressed int64
}

// Writer writes one bundle's chunks and its signed manifest into a
// directory. Chunk files are content-addressed: a chunk identical to one
// already in the directory (an earlier release) is not written twice.
type Writer struct {
	dir     string
	opt     WriterOptions
	streams []Stream
	cur     *chunkWriter
	lastID  string
	open    bool
	done    bool
}

// NewWriter returns a Writer into dir (created 0755: bundles are public).
func NewWriter(dir string, opt WriterOptions) (*Writer, error) {
	switch {
	case !feedRE.MatchString(opt.Feed):
		return nil, fmt.Errorf("bundle: feed %q", opt.Feed)
	case opt.Sequence == 0:
		return nil, errors.New("bundle: sequence 0")
	case opt.Kind == KindSnapshot && opt.BaseSequence != 0,
		opt.Kind == KindDelta && (opt.BaseSequence == 0 || opt.BaseSequence >= opt.Sequence),
		opt.Kind != KindSnapshot && opt.Kind != KindDelta:
		return nil, fmt.Errorf("bundle: kind %q with base %d", opt.Kind, opt.BaseSequence)
	}
	if opt.TargetRecords <= 0 {
		opt.TargetRecords = DefaultTargetRecords
	}
	if opt.MaxRecords <= 0 {
		opt.MaxRecords = 4 * opt.TargetRecords
	}
	if opt.MaxUncompressed <= 0 {
		opt.MaxUncompressed = DefaultMaxUncompressed
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // published bundle directory
		return nil, err
	}
	return &Writer{dir: dir, opt: opt}, nil
}

// Stream starts the next record stream; the previous one is finished.
func (w *Writer) Stream(name string) error {
	if w.done {
		return errors.New("bundle: writer finished")
	}
	if !streamRE.MatchString(name) {
		return fmt.Errorf("bundle: stream name %q", name)
	}
	for _, s := range w.streams {
		if s.Name == name {
			return fmt.Errorf("bundle: stream %q twice", name)
		}
	}
	if err := w.cut(); err != nil {
		return err
	}
	w.streams = append(w.streams, Stream{Name: name})
	w.lastID = ""
	w.open = true
	return nil
}

// Add appends a record (one JSON value, no newline) with its id. Ids must
// strictly ascend within a stream.
func (w *Writer) Add(id string, record []byte) error {
	switch {
	case !w.open:
		return errors.New("bundle: Add before Stream")
	case id == "":
		return errors.New("bundle: empty record id")
	case w.lastID != "" && id <= w.lastID:
		return fmt.Errorf("bundle: record id %q not after %q", id, w.lastID)
	case len(record) == 0 || bytes.ContainsAny(record, "\r\n"):
		return fmt.Errorf("bundle: record %q must be one non-empty JSON line", id)
	}
	if w.cur == nil {
		c, err := newChunkWriter(w.dir)
		if err != nil {
			return err
		}
		w.cur = c
		w.cur.first = id
	}
	if err := w.cur.add(record); err != nil {
		return err
	}
	w.cur.last = id
	w.lastID = id
	if w.boundary(id) {
		return w.cut()
	}
	return nil
}

func (w *Writer) boundary(id string) bool {
	c := w.cur
	if c.records >= w.opt.MaxRecords || c.uncompressed >= w.opt.MaxUncompressed {
		return true
	}
	if c.records < max(1, w.opt.TargetRecords/4) {
		return false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return h.Sum32()%uint32(w.opt.TargetRecords) == 0 //nolint:gosec // TargetRecords > 0
}

func (w *Writer) cut() error {
	if w.cur == nil {
		return nil
	}
	ref, err := w.cur.finish()
	w.cur = nil
	if err != nil {
		return err
	}
	s := &w.streams[len(w.streams)-1]
	s.Chunks = append(s.Chunks, ref)
	s.Records += ref.Records
	return nil
}

// Finish writes the signed manifest (ManifestFile(kind)) and returns it
// with the reference a Pointer needs.
func (w *Writer) Finish(meta json.RawMessage, createdAt, expiresAt time.Time, signer Signer) (*Manifest, FileRef, error) {
	if err := w.cut(); err != nil {
		return nil, FileRef{}, err
	}
	w.done = true
	streams := w.streams
	if streams == nil {
		streams = []Stream{}
	}
	m := &Manifest{
		Schema: Schema, Feed: w.opt.Feed, Sequence: w.opt.Sequence, Kind: w.opt.Kind, BaseSequence: w.opt.BaseSequence,
		CreatedAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(), Streams: streams, Meta: meta,
	}
	if err := m.Validate(w.opt.Feed, createdAt, Limits{}); err != nil {
		return nil, FileRef{}, err
	}
	ref, err := writeSigned(w.dir, ManifestFile(w.opt.Kind), ManifestPayloadType(w.opt.Feed), m, signer)
	return m, ref, err
}

// WritePointer writes the signed pointer (PointerFile) into dir.
func WritePointer(dir string, p Pointer, signer Signer) error {
	p.Schema = PointerSchema
	p.CreatedAt, p.ExpiresAt = p.CreatedAt.UTC(), p.ExpiresAt.UTC()
	if err := p.Validate(p.Feed, p.CreatedAt, Limits{}); err != nil {
		return err
	}
	_, err := writeSigned(dir, PointerFile, PointerPayloadType(p.Feed), p, signer)
	return err
}

func writeSigned(dir, name, payloadType string, v any, signer Signer) (FileRef, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return FileRef{}, err
	}
	env, err := signer.Sign(payloadType, payload)
	if err != nil {
		return FileRef{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, name), env, 0o644); err != nil { //nolint:gosec // published file
		return FileRef{}, err
	}
	sum := sha256.Sum256(env)
	return FileRef{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(env))}, nil
}

// chunkWriter writes one gzip JSON Lines chunk to a temporary file.
type chunkWriter struct {
	dir          string
	f            *os.File
	h            hash.Hash
	cw           *countWriter
	gz           *gzip.Writer
	records      int
	uncompressed int64
	first, last  string
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func newChunkWriter(dir string) (*chunkWriter, error) {
	f, err := os.CreateTemp(dir, ".chunk-*")
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h)}
	// No name or mtime in the header: equal records give equal bytes.
	gz, _ := gzip.NewWriterLevel(cw, gzip.BestCompression)
	return &chunkWriter{dir: dir, f: f, h: h, cw: cw, gz: gz}, nil
}

func (c *chunkWriter) add(record []byte) error {
	if _, err := c.gz.Write(record); err != nil {
		return err
	}
	if _, err := c.gz.Write([]byte{'\n'}); err != nil {
		return err
	}
	c.records++
	c.uncompressed += int64(len(record)) + 1
	return nil
}

func (c *chunkWriter) finish() (ChunkRef, error) {
	tmp := c.f.Name()
	err := c.gz.Close()
	if err == nil {
		err = c.f.Sync()
	}
	if cerr := c.f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return ChunkRef{}, err
	}
	ref := ChunkRef{SHA256: hex.EncodeToString(c.h.Sum(nil)), Size: c.cw.n, Uncompressed: c.uncompressed,
		Records: c.records, FirstID: c.first, LastID: c.last}
	final := filepath.Join(c.dir, ChunkFile(ref.SHA256))
	if st, err := os.Stat(final); err == nil && st.Size() == ref.Size {
		_ = os.Remove(tmp) // same content already published
		return ref, nil
	}
	if err := os.Chmod(tmp, 0o644); err != nil { //nolint:gosec // published file
		return ChunkRef{}, err
	}
	return ref, os.Rename(tmp, final)
}
