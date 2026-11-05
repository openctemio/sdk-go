package webdiff

import (
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
	"html"
	"math/bits"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Sig is what the differ keeps of one response: its signature. Nothing of
// the body leaves it but a length, a hash and counts.
type Sig struct {
	// Status is the HTTP status as received.
	Status int
	// Location is the redirect target as a pattern: the probed name
	// replaced by {r}, the host lower-cased and dropped when it is the
	// origin's ("" without a Location).
	Location string
	// Family is the content-type family: html, json, xml, js, text, binary
	// or none (no Content-Type).
	Family string
	// ContentType is the media type (no parameters), at most 128 bytes.
	ContentType string
	// Length, Words and Lines are measured over the normalised body.
	Length, Words, Lines int
	// Title is the page title, normalised, at most 256 bytes.
	Title string
	// Headers is a hash of the response's header names, volatile ones
	// (Date, Set-Cookie, request ids, ...) excluded.
	Headers uint64
	// SimHash is a 64-bit simhash over word 3-shingles of the normalised
	// body.
	SimHash uint64
	// Size is the number of decoded body bytes read (at most MaxBody).
	Size int
	// Hash is the first 64 bits of the SHA-256 of the normalised body, 16
	// lower-case hex characters.
	Hash string
	// Truncated is set when the body was longer than what was read.
	Truncated bool
}

// volatileHeaders are header names whose presence changes from one answer
// to the next; they are left out of Sig.Headers.
var volatileHeaders = map[string]bool{
	"date": true, "age": true, "etag": true, "expires": true, "last-modified": true, "set-cookie": true,
	"x-request-id": true, "x-amzn-requestid": true, "x-amz-cf-id": true, "x-amz-request-id": true, "cf-ray": true,
	"x-cache": true, "x-cache-hits": true, "x-served-by": true, "x-timer": true, "x-runtime": true,
	"x-correlation-id": true, "traceparent": true, "server-timing": true, "content-length": true,
	"transfer-encoding": true, "connection": true, "keep-alive": true, "retry-after": true, "x-trace-id": true,
	"x-azure-ref": true, "x-iinfo": true, "via": true, "vary": true, "cache-control": true,
}

// Patterns of dynamic content (E19), applied after the probed name is
// removed. Order matters: the longer structures first.
var (
	uuidRE   = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	nonceRE  = regexp.MustCompile(`(?i)\bnonce\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	hiddenRE = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?hidden\b[^>]*>`)
	hexRE    = regexp.MustCompile(`[0-9a-fA-F]{16,}`)
	b64RE    = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)
	digitsRE = regexp.MustCompile(`[0-9]+`)
	titleRE  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// Normalize removes what changes from one answer to the next from a body:
// every form of token (raw, URL-encoded, HTML-escaped, case-insensitive),
// then UUIDs, nonce attributes, hidden input fields, hex runs of 16 or more,
// base64 runs of 24 or more and digit runs. Two answers of the same page
// normalise to the same text.
func Normalize(body string, tokens ...string) string {
	for _, t := range tokens {
		body = removeToken(body, t)
	}
	body = uuidRE.ReplaceAllString(body, "")
	body = nonceRE.ReplaceAllString(body, "nonce")
	body = hiddenRE.ReplaceAllString(body, "<input hidden>")
	body = hexRE.ReplaceAllString(body, "")
	body = b64RE.ReplaceAllString(body, "")
	return digitsRE.ReplaceAllString(body, "0")
}

// removeToken removes every form of t from s: raw, path- and query-escaped
// and HTML-escaped, ignoring case. Tokens shorter than 3 bytes are left (a
// one-letter name would erase the page).
func removeToken(s, t string) string {
	if len(t) < 3 || s == "" {
		return s
	}
	forms := []string{t, url.PathEscape(t), url.QueryEscape(t), html.EscapeString(t)}
	seen := map[string]bool{}
	for _, f := range forms {
		lf := strings.ToLower(f)
		if seen[lf] || lf == "" {
			continue
		}
		seen[lf] = true
		s = replaceFold(s, f, "")
	}
	return s
}

// replaceFold replaces every case-insensitive (ASCII) occurrence of old in s.
func replaceFold(s, old, repl string) string {
	if old == "" {
		return s
	}
	ls, lo := strings.ToLower(s), strings.ToLower(old)
	if len(ls) != len(s) { // non-ASCII case folding changed lengths: exact only
		return strings.ReplaceAll(s, old, repl)
	}
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(ls[i:], lo)
		if j < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		b.WriteString(s[i : i+j])
		b.WriteString(repl)
		i += j + len(lo)
	}
}

// SimHash is a 64-bit simhash over the word 3-shingles of s (single words
// when s has fewer than three). Similar texts have hashes a few bits apart.
func SimHash(s string) uint64 {
	words := strings.Fields(s)
	if len(words) == 0 {
		return 0
	}
	var v [64]int
	add := func(sh string) {
		h := fnv.New64a()
		_, _ = h.Write([]byte(sh))
		x := h.Sum64()
		for i := 0; i < 64; i++ {
			if x&(1<<uint(i)) != 0 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	if len(words) < 3 {
		for _, w := range words {
			add(w)
		}
	} else {
		for i := 0; i+3 <= len(words); i++ {
			add(words[i] + " " + words[i+1] + " " + words[i+2])
		}
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

// Distance is the Hamming distance of two simhashes.
func Distance(a, b uint64) int { return bits.OnesCount64(a ^ b) }

// Family is the content-type family of a Content-Type value.
func Family(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	switch {
	case mt == "":
		return "none"
	case mt == "text/html" || mt == "application/xhtml+xml":
		return "html"
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		return "json"
	case strings.Contains(mt, "javascript") || strings.Contains(mt, "ecmascript"):
		return "js"
	case mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml"):
		return "xml"
	case strings.HasPrefix(mt, "text/"):
		return "text"
	}
	return "binary"
}

// mediaType is the Content-Type without parameters, lower case, bounded.
func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	return clip(mt, 128)
}

// LocationPattern is the pattern of a redirect target: resolved against the
// request URL, the host dropped when it is the request's (lower-cased
// otherwise), the fragment dropped, and every form of each token replaced by
// {r}.
func LocationPattern(reqURL *url.URL, location string, tokens ...string) string {
	if location == "" {
		return ""
	}
	u, err := reqURL.Parse(strings.TrimSpace(location))
	if err != nil {
		return "invalid"
	}
	u.Fragment, u.RawFragment = "", ""
	var s string
	if strings.EqualFold(u.Host, reqURL.Host) && (u.Scheme == reqURL.Scheme || u.Scheme == "") {
		s = u.EscapedPath()
		if u.RawQuery != "" {
			s += "?" + u.RawQuery
		}
	} else {
		u.Host = strings.ToLower(u.Host)
		u.User = nil
		s = u.String()
	}
	for _, t := range tokens {
		if len(t) < 3 {
			continue
		}
		for _, f := range []string{t, url.PathEscape(t), url.QueryEscape(t), strings.ReplaceAll(url.QueryEscape(t), "+", "%20")} {
			s = replaceFold(s, f, "{r}")
		}
	}
	return clip(s, 512)
}

// headerHash hashes the sorted header names of h, volatile ones excluded.
func headerHash(h http.Header) uint64 {
	names := make([]string, 0, len(h))
	for k := range h {
		lk := strings.ToLower(k)
		if volatileHeaders[lk] || strings.HasPrefix(lk, "x-ratelimit") {
			continue
		}
		names = append(names, lk)
	}
	sort.Strings(names)
	f := fnv.New64a()
	for _, n := range names {
		_, _ = f.Write([]byte(n))
		_, _ = f.Write([]byte{0})
	}
	return f.Sum64()
}

// title is the normalised page title of a body, at most 256 bytes.
func title(body string, tokens ...string) string {
	m := titleRE.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := html.UnescapeString(m[1])
	t = strings.Join(strings.Fields(t), " ")
	return clip(Normalize(t, tokens...), 256)
}

// makeSig builds the signature of a response whose decoded body (at most
// MaxBody bytes) is body.
func makeSig(resp *http.Response, reqURL *url.URL, body []byte, truncated bool, tokens []string) Sig {
	raw := string(body)
	norm := Normalize(raw, tokens...)
	sum := sha256.Sum256([]byte(norm))
	s := Sig{
		Status:      resp.StatusCode,
		Location:    LocationPattern(reqURL, resp.Header.Get("Location"), tokens...),
		Family:      Family(resp.Header.Get("Content-Type")),
		ContentType: mediaType(resp.Header.Get("Content-Type")),
		Length:      len(norm),
		Words:       len(strings.Fields(norm)),
		Lines:       strings.Count(norm, "\n") + 1,
		Headers:     headerHash(resp.Header),
		SimHash:     SimHash(norm),
		Size:        len(body),
		Hash:        hex.EncodeToString(sum[:8]),
		Truncated:   truncated,
	}
	if s.Family == "html" {
		s.Title = title(raw, tokens...)
	}
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
