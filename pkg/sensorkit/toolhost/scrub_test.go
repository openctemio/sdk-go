package toolhost

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// scrubForms are the encodings a tool or library turns value v into.
func scrubForms(v string) map[string]string {
	jsonHTML, _ := json.Marshal(v)
	return map[string]string{
		"raw":              v,
		"base64 std":       base64.StdEncoding.EncodeToString([]byte(v)),
		"base64 std raw":   base64.RawStdEncoding.EncodeToString([]byte(v)),
		"base64 url":       base64.URLEncoding.EncodeToString([]byte(v)),
		"base64 url raw":   base64.RawURLEncoding.EncodeToString([]byte(v)),
		"query escape":     url.QueryEscape(v),
		"path escape":      url.PathEscape(v),
		"lower-case hex":   strings.ToLower(url.QueryEscape(v)),
		"json escaped":     strings.Trim(string(jsonHTML), `"`),
		"json solidus":     strings.ReplaceAll(strings.Trim(string(jsonHTML), `"`), "/", `\/`),
		"basic user:value": "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+v)),
		"basic u:value":    "Basic " + base64.StdEncoding.EncodeToString([]byte("u:"+v)),
		"basic ab:value":   base64.RawURLEncoding.EncodeToString([]byte("ab:" + v)),
	}
}

// SECURITY: every delivered value is scrubbed with its encodings from a
// record's JSON, a verdict's evidence and an artifact's bytes, and the
// scrubbed JSON stays valid.
func TestScrubberCoversEncodings(t *testing.T) {
	// Characters that encodings change: / + = ? & < > " \ and a colon.
	values := []string{"s3cr3t/v+al=ue?&<x>\"q\\z", "tok-0123456789abcdef", "token-0123456789:org-0042-abcd"}
	sc := newScrubber(values)
	for _, v := range values {
		for name, form := range scrubForms(v) {
			rec, _ := json.Marshal(map[string]any{"type": "record", "kind": "finding", "data": map[string]string{"title": "x " + form + " y"}})
			ev, _ := json.Marshal(map[string]any{"type": "verdict", "item": "i1", "verdict": "confirmed",
				"evidence": []map[string]string{{"kind": "http.request", "label": form, "body": "Authorization: " + form}}})
			for what, line := range map[string][]byte{"record": rec, "evidence": ev, "artifact": []byte("line: " + form + "\n")} {
				out := sc.Bytes(line)
				if strings.Contains(string(out), form) {
					t.Fatalf("%s of %q kept in the %s: %s", name, v, what, out)
				}
				if what != "artifact" && !json.Valid(out) {
					t.Fatalf("%s of %q: the scrubbed %s is not JSON: %s", name, v, what, out)
				}
			}
		}
	}
	// Each part of a pair, alone and encoded.
	for _, part := range []string{"token-0123456789", "org-0042-abcd"} {
		if got := sc.String("p=" + part + " b=" + base64.StdEncoding.EncodeToString([]byte(part))); strings.Contains(got, part) ||
			strings.Contains(got, base64.StdEncoding.EncodeToString([]byte(part))) {
			t.Fatalf("pair part kept: %s", got)
		}
	}
}

// Values and forms shorter than secretref.MinSecretLen are not scrubbed on
// their own (they would match unrelated text).
func TestScrubberMinLength(t *testing.T) {
	if newScrubber([]string{"short"}) != nil {
		t.Fatal("a 5-character value is scrubbed")
	}
	sc := newScrubber([]string{"ab:longer-part-123"})
	if got := sc.String("ab and longer-part-123"); got != "ab and [REDACTED]" {
		t.Fatalf("got %q", got)
	}
	var nilScrub *scrubber
	if nilScrub.String("x") != "x" || string(nilScrub.Bytes([]byte("x"))) != "x" {
		t.Fatal("a nil scrubber changed its input")
	}
}

// SECURITY: a value spelled with \uXXXX escapes in a JSON message is removed
// from the decoded strings, and the line stays valid JSON.
func TestScrubberJSONLineRemovesUnicodeEscapedValues(t *testing.T) {
	v := "tok-0123456789abcdef"
	var esc strings.Builder
	for _, r := range v {
		esc.WriteString(`\u` + strings.Repeat("0", 4-len(hexOf(r))) + hexOf(r))
	}
	line := []byte(`{"type":"record","kind":"finding","n":12345678901234567890,"data":{"title":"` + esc.String() + `","` + esc.String() + `":1}}`)
	sc := newScrubber([]string{v})
	if strings.Contains(string(sc.Bytes(line)), v) {
		t.Fatal("test setup: Bytes already removes the escaped form")
	}
	out := sc.JSONLine(line)
	if !json.Valid(out) {
		t.Fatalf("not JSON: %s", out)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), v) || strings.Contains(fmt.Sprint(back), v) {
		t.Fatalf("value kept after decoding: %s", out)
	}
	if !strings.Contains(string(out), "12345678901234567890") {
		t.Fatalf("number changed: %s", out)
	}
	// A clean line is returned as it came.
	clean := []byte(`{"type":"log","msg":"ok"}`)
	if got := sc.JSONLine(clean); string(got) != string(clean) {
		t.Fatalf("clean line changed: %s", got)
	}
}

func hexOf(r rune) string { return fmt.Sprintf("%x", r) }

// SECURITY: output cut inside a value leaves no prefix of it.
func TestScrubberTrimPartialDropsCutPrefix(t *testing.T) {
	v := "tok-0123456789abcdef"
	sc := newScrubber([]string{v})
	for cut := 1; cut < len(v); cut++ {
		cb := &cappedBuffer{max: 10 + cut}
		_, _ = cb.Write([]byte("0123456789" + v + " more"))
		raw, was := cb.Raw()
		if !was {
			t.Fatal("not cut")
		}
		got := sc.trimPartial(sc.String(raw))
		if strings.HasSuffix(got, v[:1]) {
			t.Fatalf("cut %d: tail %q", cut, got)
		}
	}
}
