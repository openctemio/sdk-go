// Package bundle is the chunked, signed feed bundle (format v2) of api
// docs/rfcs/RFC-070-chunked-feed-transfer.md: the producer's Writer, the
// signed Pointer and Manifest, and the Consumer that fetches, verifies and
// applies a bundle chunk by chunk with a durable checkpoint.
//
// A release is a flat set of files (flat so it fits release-asset hosting):
//
//	keyset.dsse.json                  the feed's key set (verified by the caller's Trust)
//	latest.v2.dsse.json               signed Pointer: sequence, manifest names and digests
//	snapshot.v2.manifest.dsse.json    signed Manifest of the full record set
//	delta.v2.manifest.dsse.json       signed Manifest of the changes since BaseSequence
//	sha256-<hex>.jsonl.gz             chunks: gzip JSON Lines, named by their digest
//
// The pointer pins each manifest's sha256; each manifest lists, per record
// stream, its chunks with sha256, size, uncompressed size, record count and
// the first and last record id. So one signature covers every byte, and a
// mirror can serve the files but cannot change them.
//
// Chunk boundaries are content-defined from record ids (records are written
// in ascending id order), so a change to one record changes one chunk and
// the others keep their digest across releases: consumers fetch them once
// (transfer's blob cache) and object-store mirrors store them once.
//
// Stability: Experimental (docs/STABILITY.md).
package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Schemas, kinds and file names.
const (
	Schema        = "openctem.bundle/v2"
	PointerSchema = "openctem.bundle.pointer/v2"

	KindSnapshot = "snapshot"
	KindDelta    = "delta"

	PointerFile = "latest.v2.dsse.json"
	KeySetFile  = "keyset.dsse.json"
)

// ManifestFile is the manifest file of a kind.
func ManifestFile(kind string) string { return kind + ".v2.manifest.dsse.json" }

// ChunkFile is the file name of a chunk.
func ChunkFile(sha256Hex string) string { return "sha256-" + sha256Hex + ".jsonl.gz" }

// PointerPayloadType and ManifestPayloadType are the DSSE payload types of
// a feed's pointer and manifests: a signature of one feed never verifies as
// another feed's, nor a pointer as a manifest.
func PointerPayloadType(feed string) string {
	return "application/vnd.openctem." + feed + ".pointer.v2+json"
}

// ManifestPayloadType is the DSSE payload type of a feed manifest.
func ManifestPayloadType(feed string) string {
	return "application/vnd.openctem." + feed + ".manifest.v2+json"
}

// Limits bound what a consumer accepts (decompression bombs, oversized
// manifests). Zero values take the defaults.
type Limits struct {
	MaxPointerBytes      int64         // default 64 KiB
	MaxKeySetBytes       int64         // default 64 KiB
	MaxManifestBytes     int64         // default 8 MiB
	MaxChunks            int           // per manifest, default 8192
	MaxChunkBytes        int64         // compressed, default 32 MiB
	MaxChunkUncompressed int64         // default 256 MiB
	MaxChunkRecords      int           // default 1 000 000
	MaxRecordBytes       int           // one JSON line, default 4 MiB
	MaxTotalBytes        int64         // compressed sum of a manifest, default 8 GiB
	MaxValidity          time.Duration // expires_at - created_at, default 8 days
	ClockSkew            time.Duration // tolerated future created_at, default 10 min
}

func (l Limits) withDefaults() Limits {
	set := func(v *int64, d int64) {
		if *v <= 0 {
			*v = d
		}
	}
	set(&l.MaxPointerBytes, 64<<10)
	set(&l.MaxKeySetBytes, 64<<10)
	set(&l.MaxManifestBytes, 8<<20)
	set(&l.MaxChunkBytes, 32<<20)
	set(&l.MaxChunkUncompressed, 256<<20)
	set(&l.MaxTotalBytes, 8<<30)
	if l.MaxChunks <= 0 {
		l.MaxChunks = 8192
	}
	if l.MaxChunkRecords <= 0 {
		l.MaxChunkRecords = 1_000_000
	}
	if l.MaxRecordBytes <= 0 {
		l.MaxRecordBytes = 4 << 20
	}
	if l.MaxValidity <= 0 {
		l.MaxValidity = 8 * 24 * time.Hour
	}
	if l.ClockSkew <= 0 {
		l.ClockSkew = 10 * time.Minute
	}
	return l
}

// ChunkRef describes one chunk.
type ChunkRef struct {
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Uncompressed int64  `json:"uncompressed"`
	Records      int    `json:"records"`
	FirstID      string `json:"first_id"`
	LastID       string `json:"last_id"`
}

// Stream is one record stream (for example "programs"), applied in
// manifest order, its chunks in order.
type Stream struct {
	Name    string     `json:"name"`
	Records int        `json:"records"`
	Chunks  []ChunkRef `json:"chunks"`
}

// Manifest is the signed description of a snapshot or a delta.
type Manifest struct {
	Schema       string    `json:"schema"`
	Feed         string    `json:"feed"`
	Sequence     uint64    `json:"sequence"`
	Kind         string    `json:"kind"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Streams      []Stream  `json:"streams"`
	// Meta is the feed's own signed metadata (sources, licenses, stats,
	// collector build). The SDK does not interpret it.
	Meta json.RawMessage `json:"meta,omitempty"`
}

// FileRef pins a manifest file.
type FileRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Pointer is the signed pointer to a release's newest bundle.
type Pointer struct {
	Schema       string    `json:"schema"`
	Feed         string    `json:"feed"`
	Sequence     uint64    `json:"sequence"`
	Snapshot     FileRef   `json:"snapshot"`
	Delta        *FileRef  `json:"delta,omitempty"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Chunks returns the manifest's chunks in apply order with their stream.
func (m *Manifest) Chunks() []Located {
	var out []Located
	for _, s := range m.Streams {
		for _, c := range s.Chunks {
			out = append(out, Located{Stream: s.Name, Index: len(out), Ref: c})
		}
	}
	return out
}

// Located is a chunk with its stream and its position in apply order.
type Located struct {
	Stream string
	Index  int
	Ref    ChunkRef
}

var (
	feedRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	streamRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	hexRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrInvalid marks a structurally invalid pointer or manifest.
var ErrInvalid = errors.New("bundle: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func checkTimes(created, expires, now time.Time, l Limits) error {
	switch {
	case created.IsZero() || expires.IsZero() || !expires.After(created):
		return invalid("created_at/expires_at")
	case expires.Sub(created) > l.MaxValidity:
		return invalid("validity %s exceeds %s", expires.Sub(created), l.MaxValidity)
	case created.After(now.Add(l.ClockSkew)):
		return invalid("created_at is in the future")
	case !now.Before(expires):
		return fmt.Errorf("%w: expired at %s", ErrExpired, expires.Format(time.RFC3339))
	}
	return nil
}

// ErrExpired: the pointer or manifest is past its expiry.
var ErrExpired = errors.New("bundle: expired")

// Validate checks the pointer's structure and freshness.
func (p *Pointer) Validate(feed string, now time.Time, l Limits) error {
	l = l.withDefaults()
	switch {
	case p.Schema != PointerSchema:
		return invalid("pointer schema %q", p.Schema)
	case p.Feed != feed:
		return invalid("pointer feed %q, want %q", p.Feed, feed)
	case p.Sequence == 0:
		return invalid("pointer sequence 0")
	case p.Snapshot.Name != ManifestFile(KindSnapshot) || !hexRE.MatchString(p.Snapshot.SHA256) || p.Snapshot.Size <= 0:
		return invalid("pointer snapshot reference")
	}
	if p.Delta != nil {
		if p.Delta.Name != ManifestFile(KindDelta) || !hexRE.MatchString(p.Delta.SHA256) || p.Delta.Size <= 0 ||
			p.BaseSequence == 0 || p.BaseSequence >= p.Sequence {
			return invalid("pointer delta reference")
		}
	}
	return checkTimes(p.CreatedAt, p.ExpiresAt, now, l)
}

// Validate checks the manifest's structure, caps and freshness.
func (m *Manifest) Validate(feed string, now time.Time, l Limits) error {
	l = l.withDefaults()
	switch {
	case m.Schema != Schema:
		return invalid("manifest schema %q", m.Schema)
	case m.Feed != feed:
		return invalid("manifest feed %q, want %q", m.Feed, feed)
	case m.Sequence == 0:
		return invalid("manifest sequence 0")
	case m.Kind == KindSnapshot && m.BaseSequence != 0:
		return invalid("snapshot with a base sequence")
	case m.Kind == KindDelta && (m.BaseSequence == 0 || m.BaseSequence >= m.Sequence):
		return invalid("delta base sequence %d", m.BaseSequence)
	case m.Kind != KindSnapshot && m.Kind != KindDelta:
		return invalid("manifest kind %q", m.Kind)
	}
	if err := checkTimes(m.CreatedAt, m.ExpiresAt, now, l); err != nil {
		return err
	}
	seen := map[string]bool{}
	chunks := 0
	var total int64
	for _, s := range m.Streams {
		if !streamRE.MatchString(s.Name) || seen[s.Name] {
			return invalid("stream name %q", s.Name)
		}
		seen[s.Name] = true
		recs := 0
		for _, c := range s.Chunks {
			chunks++
			switch {
			case !hexRE.MatchString(c.SHA256):
				return invalid("chunk digest %q", c.SHA256)
			case c.Size <= 0 || c.Size > l.MaxChunkBytes:
				return invalid("chunk %s size %d (max %d)", c.SHA256[:12], c.Size, l.MaxChunkBytes)
			case c.Uncompressed <= 0 || c.Uncompressed > l.MaxChunkUncompressed:
				return invalid("chunk %s uncompressed size %d (max %d)", c.SHA256[:12], c.Uncompressed, l.MaxChunkUncompressed)
			case c.Records <= 0 || c.Records > l.MaxChunkRecords:
				return invalid("chunk %s records %d", c.SHA256[:12], c.Records)
			case c.FirstID == "" || c.LastID == "" || c.FirstID > c.LastID:
				return invalid("chunk %s id range", c.SHA256[:12])
			}
			recs += c.Records
			total += c.Size
		}
		if recs != s.Records {
			return invalid("stream %s declares %d records, chunks hold %d", s.Name, s.Records, recs)
		}
	}
	if chunks > l.MaxChunks {
		return invalid("%d chunks (max %d)", chunks, l.MaxChunks)
	}
	if total > l.MaxTotalBytes {
		return invalid("%d bytes (max %d)", total, l.MaxTotalBytes)
	}
	return nil
}
