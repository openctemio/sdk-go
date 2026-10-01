package conformance

// The live conformance suite runs the RFC-026 v2 results contract against a
// real OpenCTEM API:
//
//	OPENCTEM_CONFORMANCE_URL=https://api.example   # API base URL
//	OPENCTEM_CONFORMANCE_KEY=rda_...               # a tenant sensor's key
//	OPENCTEM_CONFORMANCE_TOOL=semgrep              # a tool the sensor declares (default semgrep)
//	go test ./pkg/conformance -run Live -v
//
// It writes test reports (one repository asset per run, named
// conformance.invalid/<run id>) into the sensor's tenant. Use a test tenant.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/ctis"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

type live struct {
	url, key, tool, run string
	hc                  *http.Client
}

func liveTarget(t *testing.T) *live {
	t.Helper()
	url, key := os.Getenv("OPENCTEM_CONFORMANCE_URL"), os.Getenv("OPENCTEM_CONFORMANCE_KEY")
	if url == "" || key == "" {
		t.Skip("set OPENCTEM_CONFORMANCE_URL and OPENCTEM_CONFORMANCE_KEY to run the live suite")
	}
	tool := os.Getenv("OPENCTEM_CONFORMANCE_TOOL")
	if tool == "" {
		tool = "semgrep"
	}
	return &live{url: strings.TrimRight(url, "/"), key: key, tool: tool, run: uuid.NewString()[:8], hc: &http.Client{Timeout: 30 * time.Second}}
}

func (l *live) report(findings int, tag string) *ctis.Report {
	r := &ctis.Report{
		Version:  "1.0",
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC().Truncate(time.Second), SourceType: "scanner"},
		Tool:     &ctis.Tool{Name: l.tool, Version: "conformance"},
		Assets: []ctis.Asset{{
			ID: "repo", Type: ctis.AssetTypeRepository, Value: "conformance.invalid/" + l.run, Name: "conformance " + l.run,
		}},
	}
	for i := range findings {
		r.Findings = append(r.Findings, ctis.Finding{
			ID: fmt.Sprintf("%s-%d", tag, i), Type: ctis.FindingTypeVulnerability, Title: "conformance finding " + tag,
			Severity: ctis.SeverityLow, AssetRef: "repo", RuleID: "conformance." + tag,
			Fingerprint: fmt.Sprintf("conformance-%s-%s-%d", l.run, tag, i),
		})
	}
	return r
}

type liveResp struct {
	status int
	header http.Header
	body   []byte
}

func (r liveResp) problem() *protov2.Problem { return protov2.ParseProblem(r.body) }

func (l *live) do(t *testing.T, method, path string, body []byte, hdr map[string]string) liveResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, l.url+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+l.key)
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := l.hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return liveResp{status: resp.StatusCode, header: resp.Header, body: b}
}

func ctisHeaders(body []byte) map[string]string {
	return map[string]string{"Content-Type": protov2.MediaTypeCTIS, "Content-Digest": protov2.ContentDigest(body)}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantProblem(t *testing.T, r liveResp, status int, name protov2.ProblemType) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status %d, want %d: %s", r.status, status, r.body)
	}
	if !protov2.IsProblemContentType(r.header.Get("Content-Type")) {
		t.Fatalf("Content-Type %q, want problem+json", r.header.Get("Content-Type"))
	}
	if p := r.problem(); p == nil || p.Name() != name {
		t.Fatalf("problem %s, want %s", r.body, name)
	}
	if r.header.Get(protov2.HeaderProtocol) != "2" {
		t.Errorf("no %s: 2 on a v2 problem", protov2.HeaderProtocol)
	}
}

func (l *live) waitFinal(t *testing.T, id string) protov2.Status {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		r := l.do(t, http.MethodGet, protov2.StatusPath(id), nil, nil)
		if r.status != http.StatusOK {
			t.Fatalf("status resource: %d %s", r.status, r.body)
		}
		var st protov2.Status
		if err := json.Unmarshal(r.body, &st); err != nil {
			t.Fatal(err)
		}
		if st.State.IsFinal() {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("report %s still %s", id, st.State)
		}
		time.Sleep(time.Second)
	}
}

func TestLive_Hello(t *testing.T) {
	l := liveTarget(t)
	r := l.do(t, http.MethodGet, protov2.PathPrefix+protov2.HelloPath, nil, nil)
	if r.status != http.StatusOK {
		t.Fatalf("hello: %d %s", r.status, r.body)
	}
	var h protov2.Hello
	if err := json.Unmarshal(r.body, &h); err != nil || !h.SupportsResults() || !h.SupportsEncoding("zstd") {
		t.Fatalf("hello = %s (%v)", r.body, err)
	}
	if h.Limits.MaxContentBytes <= 0 || h.Limits.MaxFindingsPerSegment <= 0 {
		t.Fatalf("limits = %+v", h.Limits)
	}
}

func TestLive_WholeReportReplayAndConflict(t *testing.T) {
	l := liveTarget(t)
	id := uuid.Must(uuid.NewV7()).String()
	rep := l.report(3, "whole")
	rep.Metadata.ID = id
	body := mustJSON(t, rep)

	r := l.do(t, http.MethodPut, protov2.ReportPath("", id), body, ctisHeaders(body))
	if r.status != http.StatusAccepted {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}
	if r.header.Get("Location") != protov2.StatusPath(id) || r.header.Get(protov2.HeaderProtocol) != "2" {
		t.Errorf("Location %q, protocol %q", r.header.Get("Location"), r.header.Get(protov2.HeaderProtocol))
	}

	// Identical replay: 200, nothing new.
	r = l.do(t, http.MethodPut, protov2.ReportPath("", id), body, ctisHeaders(body))
	if r.status != http.StatusOK {
		t.Fatalf("replay: %d %s", r.status, r.body)
	}

	// Different content under the same id: 409 report-conflict.
	other := l.report(4, "whole")
	other.Metadata.ID = id
	ob := mustJSON(t, other)
	wantProblem(t, l.do(t, http.MethodPut, protov2.ReportPath("", id), ob, ctisHeaders(ob)), http.StatusConflict, protov2.ProblemReportConflict)

	st := l.waitFinal(t, id)
	if st.State != protov2.StateCompleted || st.Accepted.Findings != 3 {
		t.Fatalf("status = %+v", st)
	}
}

func TestLive_HeaderGates(t *testing.T) {
	l := liveTarget(t)
	rep := l.report(1, "gates")
	body := mustJSON(t, rep)
	id := func() string { return uuid.Must(uuid.NewV7()).String() }

	// application/json is refused: no sniffing.
	r := l.do(t, http.MethodPut, protov2.ReportPath("", id()), body, map[string]string{"Content-Type": "application/json", "Content-Digest": protov2.ContentDigest(body)})
	wantProblem(t, r, http.StatusUnsupportedMediaType, protov2.ProblemUnsupportedMediaType)
	if r.header.Get("Accept") != protov2.MediaTypeCTIS {
		t.Errorf("415 Accept = %q", r.header.Get("Accept"))
	}

	// Digest missing, then wrong.
	wantProblem(t, l.do(t, http.MethodPut, protov2.ReportPath("", id()), body, map[string]string{"Content-Type": protov2.MediaTypeCTIS}),
		http.StatusBadRequest, protov2.ProblemDigestRequired)
	wantProblem(t, l.do(t, http.MethodPut, protov2.ReportPath("", id()), body, map[string]string{"Content-Type": protov2.MediaTypeCTIS, "Content-Digest": protov2.ContentDigest([]byte("x"))}),
		http.StatusBadRequest, protov2.ProblemDigestMismatch)

	// Upper-case report id.
	wantProblem(t, l.do(t, http.MethodPut, protov2.ReportPath("", strings.ToUpper(id())), body, ctisHeaders(body)),
		http.StatusBadRequest, protov2.ProblemInvalidID)

	// Duplicate member names and unknown fields are not I-JSON / CTIS.
	dup := []byte(strings.Replace(string(body), `"version":"1.0"`, `"version":"1.0","version":"1.0"`, 1))
	if r := l.do(t, http.MethodPut, protov2.ReportPath("", id()), dup, ctisHeaders(dup)); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate key: %d %s", r.status, r.body)
	}
	unk := []byte(strings.Replace(string(body), `"version":"1.0"`, `"version":"1.0","not_ctis":1`, 1))
	if r := l.do(t, http.MethodPut, protov2.ReportPath("", id()), unk, ctisHeaders(unk)); r.status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown field: %d %s", r.status, r.body)
	}

	// Bad key: 401 problem.
	saved := l.key
	l.key = "rda_not_a_key"
	wantProblem(t, l.do(t, http.MethodPut, protov2.ReportPath("", id()), body, ctisHeaders(body)), http.StatusUnauthorized, protov2.ProblemUnauthenticated)
	l.key = saved
}

func TestLive_GzipAccepted(t *testing.T) {
	l := liveTarget(t)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(mustJSON(t, l.report(2, "gzip")))
	_ = zw.Close()
	body := buf.Bytes()
	h := ctisHeaders(body)
	h["Content-Encoding"] = "gzip"
	id := uuid.Must(uuid.NewV7()).String()
	if r := l.do(t, http.MethodPut, protov2.ReportPath("", id), body, h); r.status != http.StatusAccepted {
		t.Fatalf("gzip PUT: %d %s", r.status, r.body)
	}
	if st := l.waitFinal(t, id); st.Accepted.Findings != 2 {
		t.Fatalf("status = %+v", st)
	}
}

func TestLive_SegmentsOutOfOrderAndCommit(t *testing.T) {
	l := liveTarget(t)
	id := uuid.Must(uuid.NewV7()).String()
	full := l.report(6, "seg")
	full.Metadata.ID = id
	var digests []string
	var bodies [][]byte
	for s := range 3 {
		seg := *full
		seg.Findings = full.Findings[s*2 : s*2+2]
		b := mustJSON(t, &seg)
		bodies = append(bodies, b)
		digests = append(digests, protov2.ContentDigest(b))
	}
	for _, s := range []int{2, 0, 1} {
		if r := l.do(t, http.MethodPut, protov2.SegmentPath("", id, s), bodies[s], ctisHeaders(bodies[s])); r.status != http.StatusAccepted {
			t.Fatalf("segment %d: %d %s", s, r.status, r.body)
		}
	}
	// A commit naming the wrong digests is refused.
	bad := mustJSON(t, protov2.CommitRequest{SegmentCount: 3, SegmentDigests: []string{digests[1], digests[0], digests[2]}})
	wantProblem(t, l.do(t, http.MethodPost, protov2.CommitPath("", id), bad, map[string]string{"Content-Type": "application/json"}),
		http.StatusConflict, protov2.ProblemSegmentSetMismatch)

	ok := mustJSON(t, protov2.CommitRequest{SegmentCount: 3, SegmentDigests: digests})
	if r := l.do(t, http.MethodPost, protov2.CommitPath("", id), ok, map[string]string{"Content-Type": "application/json"}); r.status != http.StatusAccepted {
		t.Fatalf("commit: %d %s", r.status, r.body)
	}
	st := l.waitFinal(t, id)
	if st.State != protov2.StateCompleted || st.Accepted.Findings != 6 {
		t.Fatalf("status = %+v", st)
	}
}

func TestLive_FindingWithoutAssetIsRejectedNotFiledOnAFakeAsset(t *testing.T) {
	l := liveTarget(t)
	rep := l.report(1, "orphan")
	rep.Assets = append(rep.Assets, ctis.Asset{ID: "second", Type: ctis.AssetTypeRepository, Value: "conformance.invalid/" + l.run + "-2"})
	rep.Findings = append(rep.Findings, ctis.Finding{
		ID: "orphan", Type: ctis.FindingTypeVulnerability, Title: "no asset", Severity: ctis.SeverityLow,
		Fingerprint: "conformance-" + l.run + "-orphan",
	})
	id := uuid.Must(uuid.NewV7()).String()
	rep.Metadata.ID = id
	body := mustJSON(t, rep)
	if r := l.do(t, http.MethodPut, protov2.ReportPath("", id), body, ctisHeaders(body)); r.status != http.StatusAccepted {
		t.Fatalf("PUT: %d %s", r.status, r.body)
	}
	st := l.waitFinal(t, id)
	if st.Accepted.Findings != 1 || st.Rejected.Findings != 1 {
		t.Fatalf("status = %+v", st)
	}
}

// TestLive_SDK runs the SDK client itself against the API: discovery, a
// segmented push, and an identical replay that the server answers as a
// no-op.
func TestLive_SDK(t *testing.T) {
	l := liveTarget(t)
	c := client.New(&client.Config{BaseURL: l.url, APIKey: l.key, Protocol: client.ProtocolAuto})
	defer c.Close()
	ctx := context.Background()
	if p, err := c.ResultsProtocol(ctx); err != nil || p != client.ProtocolV2 {
		t.Fatalf("protocol = %s, %v", p, err)
	}
	var prog client.V2Progress
	opts := &client.V2PushOptions{MaxFindingsPerSegment: 4, OnProgress: func(p client.V2Progress) error { prog = p; return nil }}
	rep := l.report(10, "sdk")
	st, err := c.PushResultsV2(ctx, rep, opts)
	if err != nil {
		t.Fatal(err)
	}
	if prog.Segments < 3 {
		t.Fatalf("segments = %d", prog.Segments)
	}
	final := l.waitFinal(t, st.ReportID)
	if final.State != protov2.StateCompleted || final.Accepted.Findings != 10 {
		t.Fatalf("status = %+v", final)
	}
	// Replay the same report id from scratch (lost acknowledgements).
	again, err := c.PushResultsV2(ctx, rep, &client.V2PushOptions{ReportID: st.ReportID, MaxFindingsPerSegment: 4})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if again.ReportID != st.ReportID {
		t.Fatalf("replay changed the report id: %s", again.ReportID)
	}
}
