package toolhost

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/openctemio/contract/secretref"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// scrubber removes a task's delivered secret values from everything the
// task sends out: log lines, records, verdicts and their evidence, report
// info, artifacts, stderr and the outcome. A value is removed with the
// forms a tool or a library commonly turns it into: base64 (standard and
// URL alphabets, padded or not, also inside a longer encoded string such
// as an HTTP Basic authorization of "user:value"), URL encoding (query and
// path, upper- or lower-case hex), JSON escaping, and each colon-separated
// part of a pair. A form shorter than secretref.MinSecretLen is not
// removed on its own (it would match unrelated text).
type scrubber struct {
	// forms are the strings removed, longest first.
	forms []string
}

var pctHex = regexp.MustCompile(`%[0-9A-F]{2}`)

// newScrubber returns the scrubber of values (nil when there is nothing to
// remove).
func newScrubber(values []string) *scrubber {
	seen := map[string]bool{}
	var forms []string
	add := func(f string) {
		if len(f) >= secretref.MinSecretLen && !seen[f] {
			seen[f] = true
			forms = append(forms, f)
		}
	}
	addAll := func(v string) {
		add(v)
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			add(enc.EncodeToString([]byte(v)))
		}
		for _, f := range embeddedBase64(v) {
			add(f)
		}
		for _, f := range []string{url.QueryEscape(v), url.PathEscape(v)} {
			add(f)
			add(pctHex.ReplaceAllStringFunc(f, strings.ToLower))
		}
		for _, f := range jsonEscaped(v) {
			add(f)
		}
	}
	for _, v := range values {
		if len(v) < secretref.MinSecretLen {
			continue
		}
		addAll(v)
		if strings.Contains(v, ":") {
			for _, part := range strings.Split(v, ":") {
				if part != v {
					addAll(part)
				}
			}
		}
	}
	if len(forms) == 0 {
		return nil
	}
	slices.SortFunc(forms, func(a, b string) int { return len(b) - len(a) })
	return &scrubber{forms: forms}
}

// embeddedBase64 are the base64 characters that encode v whatever bytes
// come before it in a longer encoded string (the three alignments), in
// both alphabets: only the characters that depend on v's bytes alone.
func embeddedBase64(v string) []string {
	var out []string
	n := len(v)
	for k := 0; k < 3; k++ {
		buf := make([]byte, k+n)
		copy(buf[k:], v)
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			e := enc.EncodeToString(buf)
			start := (8*k + 5) / 6   // first character made only of v's bits
			end := (8*(k+n)-6)/6 + 1 // one past the last such character
			if start < end && end <= len(e) {
				out = append(out, e[start:end])
			}
		}
	}
	return out
}

// jsonEscaped are v as it appears inside a JSON string: with and without
// HTML escaping, and with an escaped solidus.
func jsonEscaped(v string) []string {
	var out []string
	for _, html := range []bool{true, false} {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(html)
		if enc.Encode(v) != nil {
			continue
		}
		s := strings.TrimSuffix(b.String(), "\n")
		s = strings.TrimSuffix(strings.TrimPrefix(s, `"`), `"`)
		out = append(out, s, strings.ReplaceAll(s, "/", `\/`))
	}
	return out
}

// String removes the values from s.
func (sc *scrubber) String(s string) string {
	if sc == nil {
		return s
	}
	for _, f := range sc.forms {
		s = strings.ReplaceAll(s, f, tool.Redacted)
	}
	return s
}

// Bytes removes the values from b (b itself is not changed).
func (sc *scrubber) Bytes(b []byte) []byte {
	if sc == nil {
		return b
	}
	for _, f := range sc.forms {
		if bytes.Contains(b, []byte(f)) {
			b = bytes.ReplaceAll(b, []byte(f), []byte(tool.Redacted))
		}
	}
	return b
}

// trimPartial drops from the end of s any fragment that is a prefix of one
// of the forms: output cut mid-value would otherwise leave the start of a
// secret.
func (sc *scrubber) trimPartial(s string) string {
	if sc == nil {
		return s
	}
	for k := min(len(s), len(sc.forms[0])-1); k > 0; k-- {
		tail := s[len(s)-k:]
		for _, f := range sc.forms {
			if strings.HasPrefix(f, tail) {
				return s[:len(s)-k]
			}
		}
	}
	return s
}

// JSONLine removes the values from one JSON message: from its raw bytes
// and, because JSON can spell a character as \uXXXX, from every decoded
// string (keys too). A line that decodes with no change is returned as
// scrubbed bytes; a changed one is re-encoded.
func (sc *scrubber) JSONLine(line []byte) []byte {
	if sc == nil {
		return line
	}
	line = sc.Bytes(line)
	var v any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return line
	}
	nv, changed := sc.walk(v)
	if !changed {
		return line
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(nv) != nil {
		return []byte(`{}`)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func (sc *scrubber) walk(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		if r := sc.String(x); r != x {
			return r, true
		}
	case []any:
		ch := false
		for i := range x {
			n, c := sc.walk(x[i])
			x[i], ch = n, ch || c
		}
		return x, ch
	case map[string]any:
		ch := false
		out := make(map[string]any, len(x))
		for k, e := range x {
			n, c := sc.walk(e)
			nk := sc.String(k)
			ch = ch || c || nk != k
			out[nk] = n
		}
		if ch {
			return out, true
		}
	}
	return v, false
}

// wipe drops the forms (the values are gone with the task).
func (sc *scrubber) wipe() {
	if sc != nil {
		sc.forms = nil
	}
}
