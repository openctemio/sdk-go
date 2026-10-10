package bundle

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer"
)

// Errors of a consumer run.
var (
	// ErrRollback: the origin serves an older sequence than the one applied
	// (a stale mirror or a replay). Nothing is applied.
	ErrRollback = errors.New("bundle: sequence older than the applied one (rollback refused)")
	// ErrPinMismatch: a manifest does not match the digest its pointer pins.
	ErrPinMismatch = errors.New("bundle: manifest does not match the pointer")
	// ErrChunk: a chunk's content does not match its manifest entry.
	ErrChunk = errors.New("bundle: chunk does not match the manifest")
)

// Applier applies a verified bundle. Every method runs after the bytes it
// receives were verified against the signed manifest.
type Applier interface {
	// ApplyChunk applies one chunk's records, in one transaction. It must
	// return any error of c.Records and then not commit. A database applier
	// should also persist next in that transaction (exactly-once); the
	// consumer then saves next through the Checkpoint as well.
	//
	// Upserts are keyed by record id and must not replace a record stored
	// by a newer sequence than c.Manifest.Sequence: a chunk may be applied
	// twice after a crash.
	ApplyChunk(ctx context.Context, c *Chunk, next State) error
	// Complete finishes the bundle after its last chunk (for a snapshot:
	// remove what the snapshot no longer holds). It may be called again
	// after a crash and must be idempotent.
	Complete(ctx context.Context, m *Manifest, next State) error
}

// Chunk is one verified chunk handed to an Applier.
type Chunk struct {
	Manifest *Manifest
	Located
	path   string
	limits Limits
}

// Records calls fn for each record line in order, streaming (bounded
// memory). It refuses a chunk whose decompressed size or record count
// differs from its manifest entry, or a line longer than MaxRecordBytes.
// The line is only valid during the call.
func (c *Chunk) Records(fn func(line []byte) error) error {
	f, err := os.Open(c.path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrChunk, c.Ref.SHA256[:12], err)
	}
	defer gz.Close()
	lr := &io.LimitedReader{R: gz, N: c.Ref.Uncompressed + 1}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 0, min(64<<10, c.limits.MaxRecordBytes+1)), c.limits.MaxRecordBytes+1)
	n := 0
	for sc.Scan() {
		if lr.N <= 0 {
			// More bytes than declared: refuse before the (possibly cut)
			// line reaches the applier.
			return fmt.Errorf("%w: %s decompresses to more than the declared %d bytes", ErrChunk, c.Ref.SHA256[:12], c.Ref.Uncompressed)
		}
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return fmt.Errorf("%w: %s: empty line %d", ErrChunk, c.Ref.SHA256[:12], n+1)
		}
		n++
		if n > c.Ref.Records {
			return fmt.Errorf("%w: %s holds more than %d records", ErrChunk, c.Ref.SHA256[:12], c.Ref.Records)
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrChunk, c.Ref.SHA256[:12], err)
	}
	if used := c.Ref.Uncompressed + 1 - lr.N; used != c.Ref.Uncompressed {
		return fmt.Errorf("%w: %s decompresses to %d bytes, declared %d", ErrChunk, c.Ref.SHA256[:12], used, c.Ref.Uncompressed)
	}
	if n != c.Ref.Records {
		return fmt.Errorf("%w: %s holds %d records, declared %d", ErrChunk, c.Ref.SHA256[:12], n, c.Ref.Records)
	}
	return nil
}

// Config configures a Consumer.
type Config struct {
	Feed    string
	Fetcher *transfer.Fetcher
	// Trust builds the verifier from the release's key set (KeySetFile),
	// checking it against the pinned root. Nil: Verifier is used and no key
	// set is fetched.
	Trust    func(ctx context.Context, keySet []byte) (Verifier, error)
	Verifier Verifier

	Checkpoint Checkpoint
	Applier    Applier
	Limits     Limits
	// KeepCache keeps chunks of earlier bundles in the fetcher's cache
	// (default: only the applied bundle's chunks are kept, for reuse by the
	// next release).
	KeepCache bool
	Logger    *slog.Logger
	Now       func() time.Time
}

// Result says what a run did.
type Result struct {
	UpToDate      bool
	Sequence      uint64
	Kind          string
	Resumed       bool
	ChunksApplied int
	Records       int
}

// ConsumerStats are a consumer's counters.
type ConsumerStats struct {
	Runs, Completed, Resumes, ChunksApplied, ChunksFailed, Records, Refused uint64
}

// Consumer fetches, verifies and applies a feed's bundles.
type Consumer struct {
	cfg                                                                     Config
	runs, completed, resumes, chunksApplied, chunksFailed, records, refused atomic.Uint64
}

// NewConsumer returns a Consumer.
func NewConsumer(cfg Config) (*Consumer, error) {
	switch {
	case !feedRE.MatchString(cfg.Feed):
		return nil, fmt.Errorf("bundle: feed %q", cfg.Feed)
	case cfg.Fetcher == nil || cfg.Checkpoint == nil || cfg.Applier == nil:
		return nil, errors.New("bundle: Fetcher, Checkpoint and Applier are required")
	case cfg.Trust == nil && cfg.Verifier == nil:
		return nil, errors.New("bundle: Trust or Verifier is required")
	}
	cfg.Limits = cfg.Limits.withDefaults()
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Consumer{cfg: cfg}, nil
}

// Stats returns the counters.
func (c *Consumer) Stats() ConsumerStats {
	return ConsumerStats{Runs: c.runs.Load(), Completed: c.completed.Load(), Resumes: c.resumes.Load(),
		ChunksApplied: c.chunksApplied.Load(), ChunksFailed: c.chunksFailed.Load(), Records: c.records.Load(), Refused: c.refused.Load()}
}

// Run applies the newest bundle if it is newer than the applied one,
// resuming a bundle a previous run left half-applied. Signatures, pins and
// caps are checked before any chunk is fetched; each chunk's hash before it
// is parsed. One Run at a time per feed (the caller holds a lock).
func (c *Consumer) Run(ctx context.Context) (Result, error) {
	c.runs.Add(1)
	res, err := c.run(ctx)
	if err != nil && (errors.Is(err, ErrSignature) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrExpired) ||
		errors.Is(err, ErrPinMismatch) || errors.Is(err, ErrRollback) || errors.Is(err, ErrChunk) || errors.Is(err, transfer.ErrHashMismatch)) {
		c.refused.Add(1)
	}
	return res, err
}

func (c *Consumer) run(ctx context.Context) (Result, error) {
	cfg, log, now := c.cfg, c.cfg.Logger.With("feed", c.cfg.Feed), c.cfg.Now()
	st, err := cfg.Checkpoint.Load(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("bundle: load checkpoint: %w", err)
	}
	st.Feed = cfg.Feed
	v := cfg.Verifier
	if cfg.Trust != nil {
		ks, err := cfg.Fetcher.Small(ctx, KeySetFile, cfg.Limits.MaxKeySetBytes)
		if err != nil {
			return Result{}, err
		}
		if v, err = cfg.Trust(ctx, ks); err != nil {
			return Result{}, fmt.Errorf("%w: key set: %w", ErrSignature, err)
		}
	}

	var p Pointer
	if err := c.signed(ctx, v, PointerFile, nil, PointerPayloadType(cfg.Feed), cfg.Limits.MaxPointerBytes, &p); err != nil {
		return Result{}, err
	}
	if err := p.Validate(cfg.Feed, now, cfg.Limits); err != nil {
		return Result{}, err
	}
	switch {
	case p.Sequence < st.Applied:
		return Result{}, fmt.Errorf("%w: served %d, applied %d", ErrRollback, p.Sequence, st.Applied)
	case p.Sequence == st.Applied:
		return Result{UpToDate: true, Sequence: st.Applied}, nil
	}

	// A half-applied bundle of this sequence is resumed in its own kind; a
	// delta is used only on top of exactly its base.
	ref, kind := p.Snapshot, KindSnapshot
	switch {
	case st.InProgress == p.Sequence && st.Kind == KindDelta && p.Delta != nil && p.Delta.SHA256 == st.Manifest:
		ref, kind = *p.Delta, KindDelta
	case st.InProgress == p.Sequence && st.Kind == KindSnapshot:
	case p.Delta != nil && st.Applied != 0 && p.BaseSequence == st.Applied:
		ref, kind = *p.Delta, KindDelta
	}

	var m Manifest
	if err := c.signed(ctx, v, ref.Name, &ref, ManifestPayloadType(cfg.Feed), cfg.Limits.MaxManifestBytes, &m); err != nil {
		return Result{}, err
	}
	if err := m.Validate(cfg.Feed, now, cfg.Limits); err != nil {
		return Result{}, err
	}
	if m.Sequence != p.Sequence || m.Kind != kind || (kind == KindDelta && m.BaseSequence != p.BaseSequence) {
		return Result{}, fmt.Errorf("%w: manifest %s/%d does not match pointer %s/%d", ErrPinMismatch, m.Kind, m.Sequence, kind, p.Sequence)
	}

	res := Result{Sequence: m.Sequence, Kind: kind}
	chunks := m.Chunks()
	start := 0
	if st.InProgress == m.Sequence && st.Kind == kind && st.Manifest == ref.SHA256 && st.NextChunk <= len(chunks) {
		start = st.NextChunk
		res.Resumed = true
		c.resumes.Add(1)
		log.Info("bundle: resuming", "sequence", m.Sequence, "kind", kind, "next_chunk", start, "chunks", len(chunks))
	} else {
		if st.InProgress != 0 {
			log.Warn("bundle: abandoning a partial bundle", "partial_sequence", st.InProgress, "sequence", m.Sequence)
		}
		st = State{Feed: cfg.Feed, Applied: st.Applied, InProgress: m.Sequence, Kind: kind, Manifest: ref.SHA256, UpdatedAt: now}
		if err := cfg.Checkpoint.Save(ctx, st); err != nil {
			return res, fmt.Errorf("bundle: save checkpoint: %w", err)
		}
	}

	for _, lc := range chunks[start:] {
		path, err := cfg.Fetcher.Blob(ctx, ChunkFile(lc.Ref.SHA256), lc.Ref.SHA256, lc.Ref.Size)
		if err != nil {
			c.chunksFailed.Add(1)
			return res, fmt.Errorf("bundle: chunk %d/%d: %w", lc.Index+1, len(chunks), err)
		}
		next := st
		next.NextChunk = lc.Index + 1
		next.UpdatedAt = c.cfg.Now()
		ch := &Chunk{Manifest: &m, Located: lc, path: path, limits: cfg.Limits}
		if err := cfg.Applier.ApplyChunk(ctx, ch, next); err != nil {
			c.chunksFailed.Add(1)
			return res, fmt.Errorf("bundle: apply chunk %d/%d (%s): %w", lc.Index+1, len(chunks), lc.Stream, err)
		}
		if err := cfg.Checkpoint.Save(ctx, next); err != nil {
			return res, fmt.Errorf("bundle: save checkpoint: %w", err)
		}
		st = next
		res.ChunksApplied++
		res.Records += lc.Ref.Records
		c.chunksApplied.Add(1)
		c.records.Add(uint64(lc.Ref.Records)) //nolint:gosec // validated positive
		log.Debug("bundle: chunk applied", "sequence", m.Sequence, "chunk", lc.Index+1, "of", len(chunks), "stream", lc.Stream, "records", lc.Ref.Records)
	}

	done := State{Feed: cfg.Feed, Applied: m.Sequence, UpdatedAt: c.cfg.Now()}
	if err := cfg.Applier.Complete(ctx, &m, done); err != nil {
		return res, fmt.Errorf("bundle: complete sequence %d: %w", m.Sequence, err)
	}
	if err := cfg.Checkpoint.Save(ctx, done); err != nil {
		return res, fmt.Errorf("bundle: save checkpoint: %w", err)
	}
	c.completed.Add(1)
	log.Info("bundle: applied", "sequence", m.Sequence, "kind", kind, "chunks", res.ChunksApplied, "records", res.Records, "resumed", res.Resumed)
	if !cfg.KeepCache {
		keep := map[string]bool{}
		for _, lc := range chunks {
			keep[lc.Ref.SHA256] = true
		}
		if _, err := cfg.Fetcher.PruneBlobs(keep); err != nil {
			log.Warn("bundle: prune cache", "err", err)
		}
	}
	return res, nil
}

// signed fetches name, checks the pin (when given) and the signature, and
// decodes the payload strictly into v.
func (c *Consumer) signed(ctx context.Context, verifier Verifier, name string, pin *FileRef, payloadType string, maxBytes int64, v any) error {
	raw, err := c.cfg.Fetcher.Small(ctx, name, maxBytes)
	if err != nil {
		return err
	}
	if pin != nil {
		sum := sha256.Sum256(raw)
		if int64(len(raw)) != pin.Size || hex.EncodeToString(sum[:]) != pin.SHA256 {
			return fmt.Errorf("%w: %s", ErrPinMismatch, name)
		}
	}
	payload, err := verifier.Verify(raw, payloadType)
	if err != nil {
		if errors.Is(err, ErrSignature) {
			return fmt.Errorf("%s: %w", name, err)
		}
		return fmt.Errorf("%w: %s: %w", ErrSignature, name, err)
	}
	if err := decodeStrict(payload, v); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalid, name, err)
	}
	return nil
}
