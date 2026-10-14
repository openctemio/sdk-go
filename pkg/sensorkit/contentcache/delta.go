package contentcache

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// Delta installs (research/139 §3.2): the platform serves a pack's file
// index and single files by sha256; the cache copies the files it already
// holds in other packs, fetches only the missing ones and rebuilds the
// canonical archive, whose digest and size must equal the signed ones. The
// integrity is that of a full download.

// IndexEntry is one file of a pack's index.
type IndexEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// IndexFetcher is a Fetcher that also serves a pack's file index and its
// files one by one.
type IndexFetcher interface {
	Fetcher
	Index(ctx context.Context, digest string) ([]IndexEntry, error)
	FetchFile(ctx context.Context, digest, sha256Hex string) (io.ReadCloser, error)
}

// indexFile is the cache's record of a held pack's files (path, sha256).
const indexFile = ".openctem-index.json"

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// epoch is the modification time of every canonical entry (the platform's
// contentpack.canonicalTar).
var epoch = time.Unix(0, 0).UTC() //nolint:gochecknoglobals // constant

// canonicalTar is the platform's canonical archive of files sorted by path:
// regular files, mode 0644, mtime 0, PAX format.
func canonicalTar(files []file) ([]byte, error) {
	sorted := append([]file(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].path < sorted[j].path })
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range sorted {
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: f.path, Mode: 0o644, Size: int64(len(f.data)), ModTime: epoch, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeIndex records a stored pack's files.
func writeIndex(dir string, files []file) error {
	idx := make([]IndexEntry, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		idx = append(idx, IndexEntry{Path: f.path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(f.data))})
	}
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, indexFile), b, 0o400)
}

// localFiles maps the sha256 of every file of every held pack to its path.
func (c *Cache) localFiles() map[string]string {
	out := map[string]string{}
	for _, d := range c.Held() {
		dir := c.dir(d)
		b, err := os.ReadFile(filepath.Join(dir, indexFile)) //nolint:gosec // the cache's own file
		if err != nil {
			continue
		}
		var idx []IndexEntry
		if json.Unmarshal(b, &idx) != nil {
			continue
		}
		for _, e := range idx {
			if _, ok := out[e.SHA256]; !ok && sha256HexRE.MatchString(e.SHA256) {
				if p, err := cleanPath(e.Path, c.opts.Limits); err == nil {
					out[e.SHA256] = filepath.Join(dir, filepath.FromSlash(p))
				}
			}
		}
	}
	return out
}

var errNoDelta = errors.New("no delta")

// installDelta builds the pack from held files and fetched ones. It returns
// errNoDelta when nothing is held to reuse (a full download is cheaper).
func (c *Cache) installDelta(ctx context.Context, f IndexFetcher, digest string, size int64) ([]file, error) {
	local := c.localFiles()
	if len(local) == 0 {
		return nil, errNoDelta
	}
	idx, err := f.Index(ctx, digest)
	if err != nil {
		return nil, err
	}
	lim := c.opts.Limits
	if len(idx) == 0 || len(idx) > lim.MaxFiles {
		return nil, fmt.Errorf("%w: index of %d entries", ErrVerify, len(idx))
	}
	var total int64
	files := make([]file, 0, len(idx))
	var reused, fetched int64
	for _, e := range idx {
		p, err := cleanPath(e.Path, lim)
		if err != nil || !sha256HexRE.MatchString(e.SHA256) || e.Size < 0 || e.Size > lim.MaxFileSize {
			return nil, fmt.Errorf("%w: index entry %q", ErrVerify, e.Path)
		}
		if total += e.Size; total > lim.MaxTotal {
			return nil, fmt.Errorf("%w: the files add up to more than %d bytes", ErrTooLarge, lim.MaxTotal)
		}
		var data []byte
		if lp, ok := local[e.SHA256]; ok {
			if b, err := os.ReadFile(lp); err == nil && sha256Hex(b) == e.SHA256 { //nolint:gosec // a held pack's file
				data = b
				reused += int64(len(b))
			}
		}
		if data == nil {
			rc, err := f.FetchFile(ctx, digest, e.SHA256)
			if err != nil {
				return nil, fmt.Errorf("fetch %s: %w", e.Path, err)
			}
			data, err = io.ReadAll(io.LimitReader(rc, e.Size+1))
			_ = rc.Close()
			if err != nil {
				return nil, fmt.Errorf("fetch %s: %w", e.Path, err)
			}
			if int64(len(data)) != e.Size || sha256Hex(data) != e.SHA256 {
				return nil, fmt.Errorf("%w: %s does not match the index", ErrVerify, e.Path)
			}
			fetched += int64(len(data))
		}
		files = append(files, file{p, data})
	}
	canonical, err := canonicalTar(files)
	if err != nil {
		return nil, err
	}
	if int64(len(canonical)) != size || "sha256:"+sha256Hex(canonical) != digest {
		return nil, fmt.Errorf("%w: %s rebuilt from its index does not match its digest", ErrVerify, digest)
	}
	c.stats.add(func(s *Stats) {
		s.BytesDownloaded += fetched
		s.BytesSaved += reused
		s.DeltaInstalls++
	})
	return files, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
