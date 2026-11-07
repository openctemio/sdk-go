package importcli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/text/encoding/unicode"
)

// MaxFiles bounds how many files one command reads after its patterns are
// expanded. They are sent MaxInputs at a time.
const MaxFiles = 500

// expandInputs expands the file patterns of the command line. cmd.exe and
// PowerShell hand "C:\scans\*.nessus" to the program as it is, so the CLI
// expands it itself: an argument that names no existing file and holds a
// pattern character (* ? [) is a pattern, matched with filepath.Glob (on
// Windows the backslash is the separator there, never an escape). An existing
// file is taken literally, even when its name holds such a character. A
// pattern that matches nothing is an error, as is a match that is a
// directory. The same file named twice is read once.
func expandInputs(args []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "-" {
			out = append(out, p) // read once: the caller refuses a second "-"
			return
		}
		key := filepath.Clean(p)
		if filepath.Separator == '\\' {
			key = strings.ToLower(key) // NTFS names compare case-blind
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	for _, a := range args {
		if a == "-" || !strings.ContainsAny(a, "*?[") {
			add(a)
			continue
		}
		if _, err := os.Stat(a); err == nil {
			add(a)
			continue
		}
		matches, err := filepath.Glob(a)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", clean(a, 200), err)
		}
		var files []string
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && !st.IsDir() {
				files = append(files, m)
			}
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s: no file matches", clean(a, 200))
		}
		sort.Strings(files)
		for _, f := range files {
			add(f)
		}
		if len(out) > MaxFiles {
			break
		}
	}
	if len(out) > MaxFiles {
		return nil, fmt.Errorf("%d files or more; at most %d per command", len(out), MaxFiles)
	}
	return out, nil
}

// decodeText turns an export written by a Windows tool into the UTF-8 the
// importers read, as a stream:
//   - a UTF-8 byte order mark is dropped;
//   - UTF-16 (little or big endian) with a byte order mark, which Windows
//     PowerShell 5.1 writes for "Out-File" and ">", is decoded to UTF-8;
//   - XML in UTF-16 without a mark is recognized by its first character
//     ("<" as two bytes, the XML 1.0 appendix F rule) and decoded too.
//
// When UTF-16 was decoded and the text starts with an XML declaration, its
// encoding="UTF-16" pseudo-attribute is rewritten to UTF-8, since that is
// what the reader now gets. Line ends are left as they are: every format
// reads CRLF.
func decodeText(r io.Reader) (io.Reader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, err := br.Peek(4)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return nil, err
	}
	var enc unicode.Endianness
	switch {
	case bytes.HasPrefix(head, []byte{0xEF, 0xBB, 0xBF}):
		_, _ = br.Discard(3)
		return br, nil
	case bytes.HasPrefix(head, []byte{0xFF, 0xFE}):
		_, _ = br.Discard(2)
		enc = unicode.LittleEndian
	case bytes.HasPrefix(head, []byte{0xFE, 0xFF}):
		_, _ = br.Discard(2)
		enc = unicode.BigEndian
	case bytes.Equal(head, []byte{'<', 0, '?', 0}):
		enc = unicode.LittleEndian
	case bytes.Equal(head, []byte{0, '<', 0, '?'}):
		enc = unicode.BigEndian
	default:
		return br, nil
	}
	dec := unicode.UTF16(enc, unicode.IgnoreBOM).NewDecoder().Reader(br)
	return fixXMLDeclaration(bufio.NewReaderSize(dec, 64<<10))
}

// fixXMLDeclaration rewrites the encoding of a leading XML declaration
// (<?xml ... encoding="UTF-16" ?>) to UTF-8. Anything else passes unchanged.
func fixXMLDeclaration(br *bufio.Reader) (io.Reader, error) {
	head, err := br.Peek(256)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return nil, err
	}
	if !bytes.HasPrefix(head, []byte("<?xml")) {
		return br, nil
	}
	end := bytes.Index(head, []byte("?>"))
	if end < 0 {
		return br, nil
	}
	decl := head[:end]
	lower := bytes.ToLower(decl)
	i := bytes.Index(lower, []byte("encoding"))
	if i < 0 {
		return br, nil
	}
	j := i + len("encoding")
	for j < len(decl) && (decl[j] == ' ' || decl[j] == '=' || decl[j] == '\t') {
		j++
	}
	if j >= len(decl) || (decl[j] != '"' && decl[j] != '\'') {
		return br, nil
	}
	q := decl[j]
	k := bytes.IndexByte(decl[j+1:], q)
	if k < 0 {
		return br, nil
	}
	label := strings.ToLower(string(decl[j+1 : j+1+k]))
	if label != "utf-16" && label != "utf-16le" && label != "utf-16be" {
		return br, nil
	}
	fixed := make([]byte, 0, end+8)
	fixed = append(fixed, decl[:j+1]...)
	fixed = append(fixed, "UTF-8"...)
	fixed = append(fixed, decl[j+1+k:]...)
	_, _ = br.Discard(end)
	return io.MultiReader(bytes.NewReader(fixed), br), nil
}
