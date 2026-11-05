package toolhost

import (
	"encoding/base64"
	"encoding/json"
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
