// Package conformance is the sensor protocol conformance suite (RFC-026
// WP-S3, RFC-023 D23), starting with results ingest.
//
// It has two halves:
//
//   - FakePlatform, a control plane that implements the v2 results contract
//     (RFC-026 §3) strictly and the v1 routes a sensor uses, records every
//     request and can be told to fail in each §3.8 class. The SDK's own
//     tests run against it: they check the SDK sends the right headers and
//     digest, retries only what it should, splits on 413, never resends a
//     partially accepted report and reuses report_id on retry.
//   - The live suite (live_test.go), which runs the same contract against a
//     real API: OPENCTEM_CONFORMANCE_URL and OPENCTEM_CONFORMANCE_KEY (a
//     sensor key) select it; see the package README in the test file.
package conformance

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// Request is one request the fake received.
type Request struct {
	Method, Path string
	Header       http.Header
	Body         []byte // as sent (compressed when Content-Encoding is set)
	Status       int    // what the fake answered
}

// Fault makes the fake answer a request with an error instead of handling
// it. Return nil to handle it normally.
type Fault func(r *http.Request, seq int) *FaultAnswer

// FaultAnswer is an injected answer.
type FaultAnswer struct {
	Status     int
	Problem    protov2.ProblemType // "" for a plain (non-problem) answer
	RetryAfter string
	// Drop closes the connection without answering (a network error, the
	// sender cannot tell whether the request was processed). With Process
	// the request is handled first: "the response was lost".
	Drop    bool
	Process bool
}

// StoredReport is a report the fake accepted.
type StoredReport struct {
	ReportID  string
	CommandID string
	Segments  map[int]segment
	Committed bool
	Status    protov2.Status
}

type segment struct {
	digest string
	report *ctis.Report
}

// FakePlatform is an in-process control plane. Safe for concurrent use.
type FakePlatform struct {
	Server *httptest.Server
	// APIKey is the sensor key it accepts.
	APIKey string
	// V2 serves the v2 routes and advertises them; false behaves like a
	// platform from before RFC-026 (404 on /api/v2).
	V2 bool
	// Limits are published on hello.
	Limits protov2.Limits
	// Tools are the sensor's declared tools (empty: any).
	Tools []string
	// Control serves the api RFC-029 control plane on v2 (heartbeat,
	// commands, suppressions, fingerprints, keys) and lists it on hello.
	// False (with V2) is a platform from api v0.8: v2 results only.
	Control bool
	// Paused answers heartbeats as for a disabled sensor (v2: 200 + pause).
	Paused bool

	mu        sync.Mutex
	fault     Fault
	seq       int
	requests  []Request
	reports   map[string]*StoredReport
	v1Reports []*ctis.Report
	commands  map[string]string // id -> "pending" | "acknowledged" | "running" | "completed" | "failed"
	cmdErrors map[string]string
	cmdResult map[string]json.RawMessage
	cmdQueue  []string // pending commands in poll order
	outbox    []json.RawMessage
	keys      int
}

// NewFakePlatform starts a fake platform. Close it with Close.
func NewFakePlatform(v2 bool) *FakePlatform {
	f := &FakePlatform{
		APIKey:    "rda_conformance",
		V2:        v2,
		Limits:    protov2.DefaultLimits(),
		reports:   map[string]*StoredReport{},
		commands:  map[string]string{},
		cmdErrors: map[string]string{},
		cmdResult: map[string]json.RawMessage{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// URL is the base URL.
func (f *FakePlatform) URL() string { return f.Server.URL }

// Close stops the server.
func (f *FakePlatform) Close() { f.Server.Close() }

// SetFault installs a fault injector (nil removes it).
func (f *FakePlatform) SetFault(fl Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = fl
}

// SetV2 switches the v2 routes on or off.
func (f *FakePlatform) SetV2(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.V2 = on
}

// OpenCommand registers a running command assigned to the sensor.
func (f *FakePlatform) OpenCommand(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands[id] = "running"
}

// SetControl switches the RFC-029 control plane on v2 on or off.
func (f *FakePlatform) SetControl(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Control = on
}

// SetPaused answers heartbeats as for a disabled sensor.
func (f *FakePlatform) SetPaused(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Paused = on
}

// QueueCommand adds a pending command a poll offers.
func (f *FakePlatform) QueueCommand(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands[id] = "pending"
	f.cmdQueue = append(f.cmdQueue, id)
}

// CommandResult returns the result a completed command stored.
func (f *FakePlatform) CommandResult(id string) json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cmdResult[id]
}

// CommandState returns a command's state and its error message.
func (f *FakePlatform) CommandState(id string) (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.commands[id], f.cmdErrors[id]
}

// Requests returns the recorded requests.
func (f *FakePlatform) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// RequestsTo returns the recorded requests whose path has prefix.
func (f *FakePlatform) RequestsTo(method, prefix string) []Request {
	var out []Request
	for _, r := range f.Requests() {
		if (method == "" || r.Method == method) && strings.HasPrefix(r.Path, prefix) {
			out = append(out, r)
		}
	}
	return out
}

// Reports returns the accepted v2 reports by id.
func (f *FakePlatform) Reports() map[string]*StoredReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]*StoredReport, len(f.reports))
	for k, v := range f.reports {
		cp := *v
		out[k] = &cp
	}
	return out
}

// V1Reports returns the reports received on the v1 ingest route.
func (f *FakePlatform) V1Reports() []*ctis.Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*ctis.Report(nil), f.v1Reports...)
}

// HeartbeatOutbox returns the outbox objects heartbeats carried.
func (f *FakePlatform) HeartbeatOutbox() []json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]json.RawMessage(nil), f.outbox...)
}

// AcceptedFindings counts the findings of committed v2 reports plus v1
// reports.
func (f *FakePlatform) AcceptedFindings() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reports {
		if r.Committed {
			for _, s := range r.Segments {
				n += len(s.report.Findings)
			}
		}
	}
	for _, r := range f.v1Reports {
		n += len(r.Findings)
	}
	return n
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (f *FakePlatform) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	r.Body = io.NopCloser(bytes.NewReader(body))
	f.mu.Lock()
	f.seq++
	seq, fault := f.seq, f.fault
	f.mu.Unlock()
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		f.mu.Lock()
		f.requests = append(f.requests, Request{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body, Status: rec.status})
		f.mu.Unlock()
	}()

	if fault != nil {
		if a := fault(r, seq); a != nil {
			if a.Drop {
				if a.Process {
					f.route(httptest.NewRecorder(), r, body)
				}
				rec.status = 0
				if hj, ok := w.(http.Hijacker); ok {
					if conn, _, err := hj.Hijack(); err == nil {
						if tc, ok := conn.(*net.TCPConn); ok {
							_ = tc.SetLinger(0)
						}
						_ = conn.Close()
						return
					}
				}
				return
			}
			if a.RetryAfter != "" {
				w.Header().Set("Retry-After", a.RetryAfter)
			}
			if a.Problem != "" {
				f.problem(rec, a.Status, a.Problem)
				return
			}
			http.Error(rec, http.StatusText(a.Status), a.Status)
			return
		}
	}
	f.route(rec, r, body)
}

func (f *FakePlatform) authed(r *http.Request) bool {
	f.mu.Lock()
	key := f.APIKey
	f.mu.Unlock()
	return r.Header.Get("Authorization") == "Bearer "+key
}

// SetAPIKey replaces the accepted sensor key (a key rotation).
func (f *FakePlatform) SetAPIKey(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.APIKey = key
}

func (f *FakePlatform) route(w http.ResponseWriter, r *http.Request, body []byte) {
	p := r.URL.Path
	f.mu.Lock()
	v2 := f.V2
	f.mu.Unlock()
	switch {
	case strings.HasPrefix(p, legacyv1.PathPrefix+"/"):
		if !f.authed(r) {
			http.Error(w, `{"code":"UNAUTHORIZED","message":"Invalid API key"}`, http.StatusUnauthorized)
			return
		}
		f.v1(w, r, body)
	case strings.HasPrefix(p, protov2.PathPrefix+"/"):
		if !v2 {
			http.NotFound(w, r)
			return
		}
		if !f.authed(r) {
			f.problem(w, http.StatusUnauthorized, protov2.ProblemUnauthenticated)
			return
		}
		f.v2(w, r, body)
	default:
		http.NotFound(w, r)
	}
}

func (f *FakePlatform) v1(w http.ResponseWriter, r *http.Request, body []byte) {
	p := strings.TrimPrefix(r.URL.Path, legacyv1.PathPrefix)
	switch {
	case p == "/heartbeat":
		var hb struct {
			Outbox json.RawMessage `json:"outbox"`
		}
		_ = json.Unmarshal(body, &hb)
		f.mu.Lock()
		if len(hb.Outbox) > 0 {
			f.outbox = append(f.outbox, hb.Outbox)
		}
		v2 := f.V2
		f.mu.Unlock()
		if v2 && protov2HasFeature(r.Header.Values(legacyv1.HeaderSensorFeatures), protov2.FeatureResultsV2) {
			w.Header().Set(protov2.HeaderProtocolAdvert, "2")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{legacyv1.FieldSensorID: "s1", "status": "ok", "tenant_id": "t1"})
	case p == "/ingest":
		raw, err := decodeBody(r.Header.Get("Content-Encoding"), body)
		var rep ctis.Report
		if err == nil {
			err = json.Unmarshal(raw, &rep)
		}
		if err != nil {
			http.Error(w, `{"message":"bad report"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.v1Reports = append(f.v1Reports, &rep)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"findings_created": len(rep.Findings), "assets_created": len(rep.Assets)})
	case strings.HasPrefix(p, "/commands/"):
		parts := strings.Split(strings.TrimPrefix(p, "/commands/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		id, action := parts[0], parts[1]
		f.mu.Lock()
		defer f.mu.Unlock()
		state, ok := f.commands[id]
		if !ok {
			http.Error(w, `{"message":"command not found"}`, http.StatusNotFound)
			return
		}
		switch action {
		case "complete", "fail":
			if state != "running" {
				http.Error(w, `{"message":"command must be running to complete"}`, http.StatusConflict)
				return
			}
			if action == "complete" {
				f.commands[id] = "completed"
			} else {
				var b struct {
					ErrorMessage string `json:"error_message"`
				}
				_ = json.Unmarshal(body, &b)
				f.commands[id] = "failed"
				f.cmdErrors[id] = b.ErrorMessage
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}
}

func protov2HasFeature(values []string, feature string) bool {
	for _, v := range values {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), feature) {
				return true
			}
		}
	}
	return false
}

func (f *FakePlatform) problem(w http.ResponseWriter, status int, t protov2.ProblemType) {
	f.problemState(w, status, t, "")
}

// sensorProblems are the RFC-029 types (ProblemTypeBaseSensor).
var sensorProblems = map[protov2.ProblemType]bool{
	protov2.ProblemInvalidTransition: true, protov2.ProblemCommandClaimed: true,
	protov2.ProblemTransitionConflict: true, protov2.ProblemRenewalRefused: true, protov2.ProblemTooManyItems: true,
}

func (f *FakePlatform) problemState(w http.ResponseWriter, status int, t protov2.ProblemType, state string) {
	w.Header().Set("Content-Type", protov2.MediaTypeProblem)
	w.Header().Set(protov2.HeaderProtocol, "2")
	if t == protov2.ProblemUnsupportedMediaType {
		w.Header().Set("Accept", protov2.MediaTypeCTIS)
	}
	base := protov2.ProblemTypeBase
	if sensorProblems[t] {
		base = protov2.ProblemTypeBaseSensor
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(protov2.Problem{
		Type: base + string(t), Title: string(t), Status: status, Detail: "fake: " + string(t),
		State: state, Retryable: status == 429 || status >= 500,
	})
}

func (f *FakePlatform) v2(w http.ResponseWriter, r *http.Request, body []byte) {
	rest := strings.TrimPrefix(r.URL.Path, protov2.PathPrefix)
	if rest == protov2.HelloPath && r.Method == http.MethodGet {
		features := []string{protov2.FeatureResults}
		f.mu.Lock()
		if f.Control {
			features = append(features, protov2.FeatureHeartbeat, protov2.FeatureCommands,
				protov2.FeatureSuppressions, protov2.FeatureFingerprints, protov2.FeatureKeys)
		}
		f.mu.Unlock()
		h := protov2.Hello{
			Protocol: 2, Features: features, MediaTypes: []string{protov2.MediaTypeCTIS},
			Encodings: []string{"gzip", "zstd"}, Digests: []string{"sha-256"}, Limits: f.Limits,
		}
		w.Header().Set("Content-Type", protov2.MediaTypeJSON)
		_ = json.NewEncoder(w).Encode(h)
		return
	}
	f.mu.Lock()
	control := f.Control
	f.mu.Unlock()
	if control && f.control(w, r, rest, body) {
		return
	}
	commandID := ""
	if strings.HasPrefix(rest, protov2.CommandsPath+"/") {
		parts := strings.SplitN(strings.TrimPrefix(rest, protov2.CommandsPath+"/"), "/", 2)
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		commandID, rest = parts[0], "/"+parts[1]
		f.mu.Lock()
		state := f.commands[commandID]
		f.mu.Unlock()
		if state != "running" {
			f.problem(w, http.StatusNotFound, protov2.ProblemCommandNotFound)
			return
		}
	}
	if !strings.HasPrefix(rest, protov2.ResultsPath+"/") {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(rest, protov2.ResultsPath+"/"), "/")
	reportID := parts[0]
	if _, err := uuid.Parse(reportID); err != nil || strings.ToLower(reportID) != reportID {
		f.problem(w, http.StatusBadRequest, protov2.ProblemInvalidID)
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		f.mu.Lock()
		rep := f.reports[reportID]
		var st protov2.Status
		if rep != nil {
			st = rep.Status
		}
		f.mu.Unlock()
		if rep == nil {
			f.problem(w, http.StatusNotFound, protov2.ProblemReportNotFound)
			return
		}
		writeJSON(w, http.StatusOK, st)
	case len(parts) == 1 && r.Method == http.MethodPut:
		f.putSegment(w, r, body, commandID, reportID, 0, true)
	case len(parts) == 3 && parts[1] == "segments" && r.Method == http.MethodPut:
		seq, err := strconv.Atoi(parts[2])
		if err != nil || seq < 0 || seq >= f.Limits.MaxSegmentsPerReport {
			f.problem(w, http.StatusBadRequest, protov2.ProblemInvalidID)
			return
		}
		f.putSegment(w, r, body, commandID, reportID, seq, false)
	case len(parts) == 2 && parts[1] == "commit" && r.Method == http.MethodPost:
		f.commit(w, body, commandID, reportID)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", protov2.MediaTypeJSON)
	w.Header().Set(protov2.HeaderProtocol, "2")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(enc string, body []byte) ([]byte, error) {
	switch strings.ToLower(enc) {
	case "", "identity":
		return body, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(io.LimitReader(zr, 64<<20))
	case "zstd":
		d, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return nil, err
		}
		defer d.Close()
		return d.DecodeAll(body, nil)
	default:
		return nil, fmt.Errorf("unsupported encoding %q", enc)
	}
}

// putSegment validates a v2 content request the way RFC-026 §3.3 orders it.
func (f *FakePlatform) putSegment(w http.ResponseWriter, r *http.Request, body []byte, commandID, reportID string, seq int, whole bool) {
	ct := r.Header.Get("Content-Type")
	if !strings.EqualFold(strings.TrimSpace(strings.Split(ct, ";")[0]), protov2.MediaTypeCTIS) {
		f.problem(w, http.StatusUnsupportedMediaType, protov2.ProblemUnsupportedMediaType)
		return
	}
	if r.ContentLength < 0 {
		http.Error(w, "length required", http.StatusLengthRequired)
		return
	}
	if int64(len(body)) > f.Limits.MaxContentBytes {
		f.problem(w, http.StatusRequestEntityTooLarge, protov2.ProblemContentTooLarge)
		return
	}
	digest := r.Header.Get(protov2.HeaderContentDigest)
	if digest == "" {
		f.problem(w, http.StatusBadRequest, protov2.ProblemDigestRequired)
		return
	}
	if digest != protov2.ContentDigest(body) {
		f.problem(w, http.StatusBadRequest, protov2.ProblemDigestMismatch)
		return
	}
	raw, err := decodeBody(r.Header.Get("Content-Encoding"), body)
	if err != nil {
		f.problem(w, http.StatusBadRequest, "invalid-encoding")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rep ctis.Report
	if err := dec.Decode(&rep); err != nil {
		f.problem(w, http.StatusUnprocessableEntity, protov2.ProblemSchemaInvalid)
		return
	}
	if !protov2CTISMajor(rep.Version) || rep.Tool == nil || rep.Tool.Name == "" ||
		(rep.Metadata.ID != "" && rep.Metadata.ID != reportID) {
		f.problem(w, http.StatusUnprocessableEntity, protov2.ProblemSchemaInvalid)
		return
	}
	if len(f.Tools) > 0 && !contains(f.Tools, rep.Tool.Name) {
		f.problem(w, http.StatusUnprocessableEntity, protov2.ProblemToolNotPermitted)
		return
	}
	if len(rep.Findings) > f.Limits.MaxFindingsPerSegment || len(rep.Assets) > f.Limits.MaxAssetsPerSegment {
		f.problem(w, http.StatusRequestEntityTooLarge, protov2.ProblemReportTooLarge)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().UTC()
	st := f.reports[reportID]
	if st == nil {
		st = &StoredReport{ReportID: reportID, CommandID: commandID, Segments: map[int]segment{},
			Status: protov2.Status{ReportID: reportID, CommandID: commandID, State: protov2.StateReceiving, ReceivedAt: now, Errors: []protov2.ItemError{}}}
		f.reports[reportID] = st
	}
	if st.CommandID != commandID {
		f.problemLocked(w, http.StatusConflict, protov2.ProblemBindingMismatch)
		return
	}
	if old, ok := st.Segments[seq]; ok {
		if old.digest == digest {
			st.Status.UpdatedAt = now
			writeJSON(w, http.StatusOK, st.Status)
			return
		}
		f.problemLocked(w, http.StatusConflict, protov2.ProblemReportConflict)
		return
	}
	if st.Committed {
		f.problemLocked(w, http.StatusConflict, protov2.ProblemReportCommitted)
		return
	}
	st.Segments[seq] = segment{digest: digest, report: &rep}
	st.Status.Segments.Received = len(st.Segments)
	st.Status.UpdatedAt = now
	if whole {
		f.finishLocked(st, 1)
	}
	w.Header().Set("Location", protov2.StatusPath(reportID))
	w.Header().Set("Retry-After", "2")
	writeJSON(w, http.StatusAccepted, st.Status)
}

func (f *FakePlatform) problemLocked(w http.ResponseWriter, status int, t protov2.ProblemType) {
	f.problem(w, status, t)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func protov2CTISMajor(v string) bool {
	major, _, _ := strings.Cut(strings.TrimSpace(v), ".")
	return major == "1"
}

// finishLocked marks a report committed and computes its outcome, rejecting
// findings whose asset does not resolve in their segment (RFC-026 §10.1).
func (f *FakePlatform) finishLocked(st *StoredReport, count int) {
	st.Committed = true
	exp := count
	st.Status.Segments.Expected = &exp
	st.Status.State = protov2.StateCompleted
	for seq, s := range st.Segments {
		ids := map[string]bool{}
		for _, a := range s.report.Assets {
			ids[a.ID] = true
		}
		st.Status.Accepted.Assets += len(s.report.Assets)
		for i, fd := range s.report.Findings {
			ok := (fd.AssetRef != "" && ids[fd.AssetRef]) || (fd.AssetRef == "" && len(s.report.Assets) == 1)
			if ok {
				st.Status.Accepted.Findings++
				continue
			}
			st.Status.Rejected.Findings++
			sq := seq
			st.Status.Errors = append(st.Status.Errors, protov2.ItemError{
				Segment: &sq, Pointer: fmt.Sprintf("/findings/%d/asset_ref", i), Code: "asset_unresolved", Detail: "finding references no asset in this segment",
			})
		}
	}
}

func (f *FakePlatform) commit(w http.ResponseWriter, body []byte, commandID, reportID string) {
	var req protov2.CommitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		f.problem(w, http.StatusBadRequest, "invalid-request")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.reports[reportID]
	if st == nil {
		f.problemLocked(w, http.StatusNotFound, protov2.ProblemReportNotFound)
		return
	}
	if st.CommandID != commandID {
		f.problemLocked(w, http.StatusConflict, protov2.ProblemBindingMismatch)
		return
	}
	if st.Committed {
		writeJSON(w, http.StatusOK, st.Status)
		return
	}
	if req.SegmentCount != len(st.Segments) || len(req.SegmentDigests) != req.SegmentCount {
		f.problemLocked(w, http.StatusConflict, protov2.ProblemSegmentSetMismatch)
		return
	}
	for i, d := range req.SegmentDigests {
		s, ok := st.Segments[i]
		if !ok || s.digest != d {
			f.problemLocked(w, http.StatusConflict, protov2.ProblemSegmentSetMismatch)
			return
		}
	}
	f.finishLocked(st, req.SegmentCount)
	writeJSON(w, http.StatusAccepted, st.Status)
}
