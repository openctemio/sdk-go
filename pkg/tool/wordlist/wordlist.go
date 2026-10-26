// Package wordlist composes the one wordlist file a tool task reads.
//
// A job names wordlists as content (pack files, and lists the platform
// generated for the job inline). The runtime concatenates them into a single
// file in the task's own directory: it normalises every line for the list's
// purpose, drops duplicates (the first occurrence keeps its rank) and stops
// at the job's line cap. The tool is handed that one path and never chooses
// a file, so a list can neither name a path outside the task nor grow past
// what the job allowed.
//
// The same normalisers are used by the platform when it builds generated
// lists and by the build that curates the public lists.
//
// Stability: Experimental (docs/STABILITY.md).
package wordlist

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Purposes of a wordlist.
const (
	DNSLabels = "dns-labels"
	WebPaths  = "web-paths"
	WebFiles  = "web-files"
	APIRoutes = "api-routes"
	Params    = "params"
	Extension = "extensions"
	VHosts    = "vhosts"
)

// Purposes lists the known purposes.
var Purposes = []string{DNSLabels, WebPaths, WebFiles, APIRoutes, Params, Extension, VHosts}

// Known reports whether p is a known purpose.
func Known(p string) bool {
	for _, k := range Purposes {
		if k == p {
			return true
		}
	}
	return false
}

// Limits of a line and of a composed list.
const (
	// MaxLineBytes is the longest raw line read; a longer one is dropped.
	MaxLineBytes = 4096
	// MaxPathBytes is the longest path-like entry kept.
	MaxPathBytes = 255
	// MaxPathSegments is the most segments a path-like entry may have.
	MaxPathSegments = 16
	// MaxDNSLabels is the most labels a dotted dns-labels entry may have.
	MaxDNSLabels = 3
	// DefaultMaxLines caps a composed list when the caller gives no cap.
	DefaultMaxLines = 2_000_000
)

var (
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	paramRE    = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)
	extRE      = regexp.MustCompile(`^\.?[A-Za-z0-9_-]{1,16}$`)
)

// Normalize returns the entry a raw line stands for under purpose, or false
// when the line is dropped (empty, a comment, or invalid for the purpose).
// An unknown or empty purpose keeps any printable entry up to MaxPathBytes.
func Normalize(purpose, line string) (string, bool) {
	line = strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if line == "" || strings.HasPrefix(line, "#") || len(line) > MaxLineBytes {
		return "", false
	}
	for _, r := range line {
		if r < 0x20 || r == 0x7f || r > 0x7e && r < 0xa0 || r == 0xfffd {
			return "", false
		}
	}
	switch purpose {
	case DNSLabels, VHosts:
		line = strings.ToLower(line)
		maxLabels := MaxDNSLabels
		if purpose == VHosts {
			maxLabels = 6
		}
		labels := strings.Split(line, ".")
		if len(labels) > maxLabels {
			return "", false
		}
		for _, l := range labels {
			if !dnsLabelRE.MatchString(l) {
				return "", false
			}
		}
		return line, true
	case Params:
		if !paramRE.MatchString(line) {
			return "", false
		}
		return line, true
	case Extension:
		if !extRE.MatchString(line) {
			return "", false
		}
		return line, true
	default:
		// WebPaths, WebFiles, APIRoutes and an unknown purpose: a relative
		// path the tool joins to a target. No scheme, host, "..", spaces
		// inside, or more than MaxPathSegments segments.
		line = strings.TrimLeft(line, "/")
		if line == "" || len(line) > MaxPathBytes || strings.Contains(line, "://") || strings.ContainsAny(line, " \t") {
			return "", false
		}
		segs := strings.Split(strings.TrimRight(line, "/"), "/")
		if len(segs) > MaxPathSegments {
			return "", false
		}
		for _, s := range segs {
			if s == ".." {
				return "", false
			}
		}
		return line, true
	}
}

// Options configure Compose.
type Options struct {
	// Purpose selects the normaliser ("" or unknown: generic).
	Purpose string
	// MaxLines caps the composed list (0: DefaultMaxLines). Entries past
	// the cap are not written and Result.Truncated is set.
	MaxLines int
	// MaxBytes caps the composed list's size (0: no cap beyond MaxLines).
	MaxBytes int64
}

// Result describes a composed list.
type Result struct {
	// Lines and Bytes are what was written.
	Lines int
	Bytes int64
	// SHA256 is the lower-case hex SHA-256 of the written bytes.
	SHA256 string
	// Duplicates and Invalid count the input lines dropped as repeated and
	// as invalid for the purpose.
	Duplicates, Invalid int
	// Truncated is true when a cap stopped the list before its sources
	// ended.
	Truncated bool
}

// ErrEmpty marks a composition with no entry left.
var ErrEmpty = errors.New("wordlist: no usable entry")

// Compose concatenates the sources in order into w, one normalised entry per
// line, without repeats. Earlier sources rank first: put the lists generated
// for the target before the general ones. It returns ErrEmpty (and writes
// nothing) when no entry survives.
func Compose(w io.Writer, o Options, sources ...io.Reader) (Result, error) {
	maxLines := o.MaxLines
	if maxLines <= 0 {
		maxLines = DefaultMaxLines
	}
	var res Result
	seen := map[string]struct{}{}
	h := sha256.New()
	bw := bufio.NewWriter(io.MultiWriter(w, h))
	for _, src := range sources {
		if src == nil {
			continue
		}
		br := bufio.NewReaderSize(src, MaxLineBytes+2)
		for {
			raw, tooLong, err := readLine(br)
			if len(raw) > 0 || tooLong {
				e, ok := "", false
				if !tooLong {
					e, ok = Normalize(o.Purpose, string(raw))
				}
				switch _, dup := seen[e]; {
				case !ok:
					res.Invalid++
				case dup:
					res.Duplicates++
				case res.Lines >= maxLines || (o.MaxBytes > 0 && res.Bytes+int64(len(e))+1 > o.MaxBytes):
					res.Truncated = true
				default:
					seen[e] = struct{}{}
					if _, werr := bw.WriteString(e + "\n"); werr != nil {
						return res, werr
					}
					res.Lines++
					res.Bytes += int64(len(e)) + 1
				}
			}
			if res.Truncated {
				break
			}
			if err != nil {
				if err != io.EOF {
					return res, fmt.Errorf("wordlist: read: %w", err)
				}
				break
			}
		}
		if res.Truncated {
			break
		}
	}
	if err := bw.Flush(); err != nil {
		return res, err
	}
	if res.Lines == 0 {
		return res, ErrEmpty
	}
	res.SHA256 = hex.EncodeToString(h.Sum(nil))
	return res, nil
}

// readLine reads one line without its newline. A line longer than
// MaxLineBytes is consumed to its end and reported as tooLong.
func readLine(br *bufio.Reader) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, rerr := br.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > MaxLineBytes+1 {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if rerr == bufio.ErrBufferFull {
			continue
		}
		return bytes.TrimRight(buf, "\r\n"), tooLong, rerr
	}
}

// CleanFilePath reports whether f is a relative, slash-separated path that
// stays inside a pack: no empty, "." or ".." segment, no backslash, no
// control character.
func CleanFilePath(f string) bool {
	if f == "" || len(f) > 512 || strings.HasPrefix(f, "/") || strings.ContainsAny(f, "\\\x00") {
		return false
	}
	for _, seg := range strings.Split(f, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	for _, r := range f {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
