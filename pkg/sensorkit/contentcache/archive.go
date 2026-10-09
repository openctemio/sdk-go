package contentcache

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits bound one pack archive. They mirror the platform's ingest limits
// for platform packs (the larger of the two).
type Limits struct {
	MaxUpload   int64
	MaxTotal    int64
	MaxFiles    int
	MaxFileSize int64
	MaxDepth    int
	MaxPath     int
}

// DefaultLimits are the platform pack limits.
var DefaultLimits = Limits{ //nolint:gochecknoglobals // read-only defaults
	MaxUpload:   400 << 20,
	MaxTotal:    384 << 20,
	MaxFiles:    60000,
	MaxFileSize: 32 << 20,
	MaxDepth:    16,
	MaxPath:     255,
}

type file struct {
	path string
	data []byte
}

// readArchive reads a canonical pack archive under the same rules the
// platform applies at ingest: regular files and directories only (PAX
// global headers skipped), clean relative printable paths, no case-folded
// duplicates, no file that is also a directory, every limit checked before
// the bytes it concerns are read.
func readArchive(data []byte, lim Limits) ([]file, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var (
		files []file
		total int64
		seen  = map[string]bool{}
	)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("not a tar archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name, err := cleanPath(hdr.Name, lim)
		if err != nil {
			return nil, err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("%s: only regular files and directories are allowed", name)
		}
		if hdr.Size < 0 || hdr.Size > lim.MaxFileSize {
			return nil, fmt.Errorf("%s: larger than %d bytes", name, lim.MaxFileSize)
		}
		if total += hdr.Size; total > lim.MaxTotal {
			return nil, fmt.Errorf("the files add up to more than %d bytes", lim.MaxTotal)
		}
		if len(files) >= lim.MaxFiles {
			return nil, fmt.Errorf("more than %d files", lim.MaxFiles)
		}
		folded := strings.ToLower(name)
		if seen[folded] {
			return nil, fmt.Errorf("%s: duplicate", name)
		}
		seen[folded] = true
		b := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, b); err != nil {
			return nil, fmt.Errorf("%s: truncated", name)
		}
		files = append(files, file{name, b})
	}
	if len(files) == 0 {
		return nil, errors.New("the archive holds no files")
	}
	for folded := range seen {
		for dir := path.Dir(folded); dir != "."; dir = path.Dir(dir) {
			if seen[dir] {
				return nil, fmt.Errorf("%s is both a file and a directory", dir)
			}
		}
	}
	return files, nil
}

func cleanPath(name string, lim Limits) (string, error) {
	p := strings.TrimSuffix(strings.TrimPrefix(name, "./"), "/")
	switch {
	case p == "" || p == ".":
		return "", errors.New("an entry has an empty path")
	case !utf8.ValidString(p):
		return "", errors.New("an entry path is not UTF-8")
	case len(p) > lim.MaxPath:
		return "", fmt.Errorf("a path is longer than %d bytes", lim.MaxPath)
	case strings.HasPrefix(p, "/"), strings.Contains(p, `\`):
		return "", fmt.Errorf("%q: not a relative path", p)
	case strings.IndexFunc(p, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) >= 0:
		return "", fmt.Errorf("%q: control character in path", p)
	}
	for _, el := range strings.Split(p, "/") {
		if el == ".." {
			return "", fmt.Errorf("%s: '..' in path", p)
		}
	}
	if path.Clean(p) != p {
		return "", fmt.Errorf("%s: path is not in clean form", p)
	}
	if strings.Count(p, "/") >= lim.MaxDepth {
		return "", fmt.Errorf("%s: deeper than %d directories", p, lim.MaxDepth)
	}
	// .statement.json is the cache's own file.
	if p == ".statement.json" {
		return "", errors.New("the archive may not hold .statement.json")
	}
	return p, nil
}
