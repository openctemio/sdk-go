package tool

// Evidence of a finding or a retest verdict (CTIS 1.6 evidence_items):
// what the tool sent and saw, captured as it was. Builders cap what they
// keep, hash what was captured and mark sensitive values (session cookies,
// authorization headers, credential parameters) in the item's sensitive
// spans; they never mask them, so the platform can mask for display and
// reveal to an authorized user. A tool never logs evidence.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// HTTPExchange is an http_exchange evidence item of one request and the
// response it got (resp nil: none arrived). reqBody and respBody are the
// bodies as sent and received (a body already read from resp). match are
// the spans that matched, with byte offsets into the bodies.
//
// A body over the CTIS cap keeps a window around the first response-body
// match (the head without one); matches outside the window are dropped.
// content_sha256 covers the full captured exchange. ok is false without a
// request or a response.
func HTTPExchange(req *http.Request, reqBody []byte, resp *http.Response, respBody []byte, match ...ctis.EvidenceMatch) (ctis.EvidenceItem, bool) {
	if req == nil && resp == nil {
		return ctis.EvidenceItem{}, false
	}
	match = slices.Clone(match)
	fullReq, fullResp := rawRequest(req, reqBody), rawResponse(resp, respBody)
	sum := sha256.Sum256([]byte(fullReq + "\x00" + fullResp))

	respWindow, respOff := window(respBody, firstBodyMatch(match, ctis.MatchLocationResponse))
	reqWindow, reqOff := window(reqBody, firstBodyMatch(match, ctis.MatchLocationRequest))
	item, ok := ctis.HTTPExchangeFromRaw(rawRequest(req, reqWindow), rawResponse(resp, respWindow), "")
	if !ok {
		return ctis.EvidenceItem{}, false
	}
	if item.HTTP.Request != nil && len(reqWindow) < len(reqBody) {
		item.HTTP.Request.BodyTruncated, item.HTTP.Request.BodySize = true, int64(len(reqBody))
	}
	if item.HTTP.Response != nil && len(respWindow) < len(respBody) {
		item.HTTP.Response.BodyTruncated, item.HTTP.Response.BodySize = true, int64(len(respBody))
	}
	item.Match = shiftMatches(match, item, reqOff, len(reqWindow), respOff, len(respWindow))
	item.ContentSHA256 = "sha256:" + hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	item.CapturedAt = &now
	ctis.FitEvidenceItem(&item)
	ctis.MarkSensitive(&item)
	return item, true
}

// Evidence is an evidence item of a kind this CTIS version does not know,
// its fields in data (at most ctis.MaxEvidenceDataBytes as JSON). Known
// kinds have their own fields: build them with HTTPExchange or the ctis
// builders.
func Evidence(kind, label string, data map[string]any) (ctis.EvidenceItem, error) {
	if ctis.IsKnownEvidenceKind(kind) {
		return ctis.EvidenceItem{}, fmt.Errorf("evidence kind %q has typed fields; use its builder", kind)
	}
	b, err := json.Marshal(data)
	if err != nil {
		return ctis.EvidenceItem{}, fmt.Errorf("evidence data: %w", err)
	}
	if len(b) > ctis.MaxEvidenceDataBytes {
		return ctis.EvidenceItem{}, fmt.Errorf("evidence data: %d bytes, at most %d", len(b), ctis.MaxEvidenceDataBytes)
	}
	if len([]rune(label)) > ctis.MaxEvidenceLabelLen {
		return ctis.EvidenceItem{}, errors.New("evidence label too long")
	}
	sum := sha256.Sum256(b)
	now := time.Now().UTC()
	it := ctis.EvidenceItem{Kind: kind, Version: 1, Label: label, CapturedAt: &now, Data: data,
		ContentSHA256: "sha256:" + hex.EncodeToString(sum[:])}
	if err := checkItemKind(it); err != nil {
		return ctis.EvidenceItem{}, err
	}
	return it, nil
}

func checkItemKind(it ctis.EvidenceItem) error {
	if len(it.Kind) == 0 || len(it.Kind) > 64 {
		return fmt.Errorf("evidence kind %q is invalid", it.Kind)
	}
	for i, c := range it.Kind {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '_' || c == '.' || c == '-'))
		if !ok {
			return fmt.Errorf("evidence kind %q is invalid", it.Kind)
		}
	}
	return nil
}

// rawRequest is the request as HTTP/1.x text ("" without one).
func rawRequest(req *http.Request, body []byte) string {
	if req == nil || req.URL == nil {
		return ""
	}
	var b bytes.Buffer
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	fmt.Fprintf(&b, "%s %s HTTP/%d.%d\r\n", method, req.URL.String(), max(req.ProtoMajor, 1), req.ProtoMinor)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	writeHeaders(&b, req.Header)
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// rawResponse is the response as HTTP/1.x text ("" without one).
func rawResponse(resp *http.Response, body []byte) string {
	if resp == nil {
		return ""
	}
	var b bytes.Buffer
	reason := http.StatusText(resp.StatusCode)
	if len(resp.Status) > 4 {
		reason = resp.Status[4:]
	}
	fmt.Fprintf(&b, "HTTP/%d.%d %d %s\r\n", max(resp.ProtoMajor, 1), resp.ProtoMinor, resp.StatusCode, reason)
	writeHeaders(&b, resp.Header)
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

func writeHeaders(b *bytes.Buffer, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(b, "%s: %s\r\n", k, v)
		}
	}
}

// firstBodyMatch is the start of the first body match at loc (-1: none).
func firstBodyMatch(match []ctis.EvidenceMatch, loc string) int {
	first := -1
	for _, m := range match {
		if m.Location == loc && m.Part == ctis.MatchPartBody && m.Start != nil && (first < 0 || *m.Start < first) {
			first = *m.Start
		}
	}
	return first
}

// window is the part of body kept under the CTIS cap: a window around at
// (a quarter before it), or the head; and its offset in body.
func window(body []byte, at int) ([]byte, int) {
	limit := ctis.MaxEvidenceBodyBytes
	if len(body) <= limit {
		return body, 0
	}
	off := 0
	if at > 0 {
		off = min(max(0, at-limit/4), len(body)-limit)
	}
	return body[off : off+limit], off
}

// shiftMatches moves body matches into their window, drops those outside
// it and those on a body the item holds in base64 (offsets would not hold).
func shiftMatches(match []ctis.EvidenceMatch, it ctis.EvidenceItem, reqOff, reqLen, respOff, respLen int) []ctis.EvidenceMatch {
	out := make([]ctis.EvidenceMatch, 0, len(match))
	for _, m := range match {
		if m.Part == ctis.MatchPartBody && m.Start != nil {
			off, n, enc := reqOff, reqLen, ""
			if m.Location == ctis.MatchLocationResponse {
				off, n = respOff, respLen
				if it.HTTP.Response != nil {
					enc = it.HTTP.Response.BodyEncoding
				}
			} else if it.HTTP.Request != nil {
				enc = it.HTTP.Request.BodyEncoding
			}
			s := *m.Start - off
			if enc == ctis.BodyEncodingBase64 || s < 0 || s > n {
				continue
			}
			m.Start = &s
			if m.End != nil {
				e := *m.End - off
				if e > n || e < s {
					continue
				}
				m.End = &e
			}
		}
		out = append(out, m)
		if len(out) == ctis.MaxEvidenceMatches {
			break
		}
	}
	return out
}
