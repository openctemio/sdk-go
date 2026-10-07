package testkit_test

import (
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func intp(n int) *int { return &n }

// exchange is a request with credentials and the 200 that answered it.
func exchange(t *testing.T, body []byte, match ...ctis.EvidenceMatch) ctis.EvidenceItem {
	t.Helper()
	u, _ := url.Parse("https://app.example.com/download?file=../../etc/passwd&token=s3cr3t-token")
	req := &http.Request{Method: "GET", URL: u, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{
		"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"}, "Cookie": {"session=abc123secret"}, "Accept": {"*/*"}}}
	resp := &http.Response{StatusCode: 200, Status: "200 OK", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"text/plain"}, "Set-Cookie": {"sid=zzz-session; HttpOnly"}}}
	it, ok := tool.HTTPExchange(req, nil, resp, body, match...)
	if !ok {
		t.Fatal("no exchange")
	}
	return it
}

// isMarked reports whether a span marks the whole value at ptr or a range
// covering needle.
func isMarked(it ctis.EvidenceItem, ptr string) bool {
	for _, s := range it.Sensitive {
		if s.Pointer == ptr {
			return true
		}
	}
	return false
}

func headerIndex(hs []ctis.EvidenceHeader, name string) int {
	for i, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return i
		}
	}
	return -1
}

// SECURITY: the builder keeps the exchange raw (the platform masks), marks
// every credential, hashes what was captured and validates as CTIS.
func TestHTTPExchangeMarksCredentials(t *testing.T) {
	body := []byte("root:x:0:0:root:/root:/bin/bash\n")
	it := exchange(t, body, ctis.EvidenceMatch{Location: ctis.MatchLocationResponse, Part: ctis.MatchPartBody, Start: intp(0), End: intp(10), Matcher: "passwd"})
	if it.Kind != ctis.EvidenceKindHTTPExchange || it.HTTP.Response == nil || it.HTTP.Response.Status != 200 {
		t.Fatalf("item %+v", it)
	}
	if !strings.HasPrefix(it.ContentSHA256, "sha256:") || it.CapturedAt == nil {
		t.Fatalf("hash %q captured %v", it.ContentSHA256, it.CapturedAt)
	}
	for _, h := range []struct{ name, ptr string }{
		{"Authorization", "/http/request/headers/%d/value"}, {"Cookie", "/http/request/headers/%d/value"},
	} {
		i := headerIndex(it.HTTP.Request.Headers, h.name)
		if i < 0 {
			t.Fatalf("%s not kept", h.name)
		}
		ptr := strings.Replace(h.ptr, "%d", itoa(i), 1)
		if !isMarked(it, ptr) {
			t.Errorf("%s value not marked (%s): %+v", h.name, ptr, it.Sensitive)
		}
	}
	if i := headerIndex(it.HTTP.Response.Headers, "Set-Cookie"); i < 0 || !isMarked(it, "/http/response/headers/"+itoa(i)+"/value") {
		t.Errorf("Set-Cookie not marked: %+v", it.Sensitive)
	}
	// Marked, never masked: the platform needs the value to reveal it.
	if i := headerIndex(it.HTTP.Request.Headers, "Cookie"); it.HTTP.Request.Headers[i].Value != "session=abc123secret" {
		t.Fatalf("the builder masked a value: %q", it.HTTP.Request.Headers[i].Value)
	}
	if !strings.Contains(it.HTTP.Request.URL, "token=") || !isMarkedPrefix(it, "/http/request/url") {
		t.Errorf("the token query value is not marked: %s %+v", it.HTTP.Request.URL, it.Sensitive)
	}
	if len(it.Match) != 1 || it.HTTP.Response.Body[*it.Match[0].Start:*it.Match[0].End] != "root:x:0:0" {
		t.Fatalf("match %+v", it.Match)
	}
	rep := ctis.NewReport()
	rep.Assets = []ctis.Asset{{ID: "a", Type: ctis.AssetTypeDomain, Value: "app.example.com"}}
	rep.Findings = []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "lfi", Severity: ctis.SeverityHigh, AssetRef: "a", EvidenceItems: []ctis.EvidenceItem{it}}}
	if err := rep.Validate(); err != nil {
		t.Fatalf("the item is not valid CTIS: %v", err)
	}
}

func isMarkedPrefix(it ctis.EvidenceItem, ptr string) bool {
	for _, s := range it.Sensitive {
		if strings.HasPrefix(s.Pointer, ptr) {
			return true
		}
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }

// A body over the cap keeps a window around the first match, with the
// match offsets moved into it, and records the full size; a match outside
// the window is dropped.
func TestHTTPExchangeWindowsALargeBody(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 200<<10)
	at := 150 << 10
	copy(body[at:], "MATCHED-HERE")
	deep := ctis.EvidenceMatch{Location: ctis.MatchLocationResponse, Part: ctis.MatchPartBody, Start: intp(at), End: intp(at + 12)}
	it := exchange(t, body, deep)
	r := it.HTTP.Response
	if !r.BodyTruncated || r.BodySize != int64(len(body)) || len(r.Body) > ctis.MaxEvidenceBodyBytes {
		t.Fatalf("truncated %v size %d kept %d", r.BodyTruncated, r.BodySize, len(r.Body))
	}
	if len(it.Match) != 1 || r.Body[*it.Match[0].Start:*it.Match[0].End] != "MATCHED-HERE" {
		t.Fatalf("match %+v", it.Match)
	}
	// The first match is at the head: the head is kept, the deep match
	// falls outside the window.
	it = exchange(t, body, deep, ctis.EvidenceMatch{Location: ctis.MatchLocationResponse, Part: ctis.MatchPartBody, Start: intp(10), End: intp(20)})
	if len(it.Match) != 1 || *it.Match[0].Start != 10 {
		t.Fatalf("match %+v", it.Match)
	}
}

func TestEvidenceOfAnUnknownKind(t *testing.T) {
	it, err := tool.Evidence("dns_answer", "A records", map[string]any{"answers": []string{"192.0.2.1"}})
	if err != nil || it.Data == nil || !strings.HasPrefix(it.ContentSHA256, "sha256:") {
		t.Fatalf("item %+v err %v", it, err)
	}
	if _, err := tool.Evidence(ctis.EvidenceKindHTTPExchange, "", map[string]any{}); err == nil {
		t.Fatal("a known kind must use its builder")
	}
	if _, err := tool.Evidence("Bad Kind", "", nil); err == nil {
		t.Fatal("an invalid kind was accepted")
	}
	if _, err := tool.Evidence("big", "", map[string]any{"x": strings.Repeat("a", ctis.MaxEvidenceDataBytes)}); err == nil {
		t.Fatal("data over the cap was accepted")
	}
}

// webCheck is a networked retest tool: it reports Fixed on every item, with
// the evidence the item's rule id asks for.
func webCheck(t *testing.T) tool.Tool {
	m := checkManifest
	m.Name = "web-check"
	m.Permissions = tool.Permissions{Network: tool.NetTargets}
	return tool.WithRetest(tool.New(m, func(tool.Context, tool.Task, tool.NoConfig) error { return nil }),
		func(ctx tool.RetestContext, task tool.Task) error {
			answered := exchange(t, []byte("ok"))
			noResponse := answered
			noResponse.HTTP = &ctis.EvidenceHTTP{Request: answered.HTTP.Request}
			for _, it := range task.Retest {
				r := tool.VerdictReport{Verdict: tool.Fixed, TemplateDigest: "sha256:abc"}
				switch it.RuleID {
				case "with-exchange":
					r.Evidence = []ctis.EvidenceItem{answered}
				case "no-response":
					r.Evidence = []ctis.EvidenceItem{noResponse}
				case "too-much":
					r.Evidence = []ctis.EvidenceItem{answered, answered, answered, answered, answered, answered}
				case "unmarked":
					raw := answered
					raw.Sensitive = nil
					r.Evidence = []ctis.EvidenceItem{raw}
				}
				ctx.Report(it, r)
			}
			for _, tg := range task.Targets {
				ctx.TargetDone(tg)
			}
			return nil
		})
}

// SECURITY: a networked tool's Fixed on a finding stands only with the
// attempt's answered HTTP exchange; evidence the runtime cannot accept
// makes the verdict Unverifiable; unmarked credentials are marked.
func TestFixedNeedsTheAttemptsExchange(t *testing.T) {
	items := []tool.RetestItem{}
	for _, r := range []string{"with-exchange", "no-evidence", "no-response", "too-much", "unmarked"} {
		items = append(items, tool.RetestItem{Ref: r, Target: "t1", Kind: tool.RetestFinding, RuleID: r})
	}
	res := testkit.Run(t, webCheck(t), tool.Task{Targets: []tool.Target{{Ref: "t1", Type: "domain", Value: "app.example.com"}}, Retest: items})
	got := map[string]tool.RetestVerdict{}
	for _, v := range res.Verdicts {
		got[v.Ref] = v
	}
	want := map[string]tool.Verdict{"with-exchange": tool.Fixed, "no-evidence": tool.Unverifiable, "no-response": tool.Unverifiable,
		"too-much": tool.Unverifiable, "unmarked": tool.Fixed}
	for ref, v := range want {
		if got[ref].Verdict != v {
			t.Errorf("%s: %s (%s), want %s", ref, got[ref].Verdict, got[ref].Detail, v)
		}
	}
	if got["with-exchange"].TemplateDigest != "sha256:abc" || len(got["with-exchange"].Evidence) != 1 {
		t.Errorf("evidence or digest lost: %+v", got["with-exchange"])
	}
	if !strings.Contains(got["too-much"].Detail, "at most 5") {
		t.Errorf("detail %q", got["too-much"].Detail)
	}
	u := got["unmarked"].Evidence[0]
	if i := headerIndex(u.HTTP.Request.Headers, "Authorization"); !isMarked(u, "/http/request/headers/"+itoa(i)+"/value") {
		t.Errorf("the runtime did not mark the Authorization value: %+v", u.Sensitive)
	}
}
