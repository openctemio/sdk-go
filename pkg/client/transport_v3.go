package client

// Sensor protocol v3 underneath the v2 client (openctem api RFC-059).
//
// Every v3 RPC is one protocol v2 resource, so v3 is installed as an
// http.RoundTripper under the existing v2 client: a request to
// /api/v2/sensor/... is carried by the matching RPC on the selected binding
// (gRPC over mTLS, or Connect over HTTPS) and its answer is turned back into
// the HTTP response v2 would have given (the problem document of a refused
// call included). Retries, the outbox, segmented uploads and every other v2
// behavior run unchanged on top, so v2 and v3 behave the same by
// construction. A route v3 does not carry, or the v2 binding, goes to the
// next transport untouched.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/types/known/timestamppb"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/sdk-go/pkg/sensorproto/v3"
	"github.com/openctemio/sdk-go/pkg/sensorproto/v3/sensorv3connect"
)

// Binding is how the client reaches the platform.
type Binding string

// Bindings.
const (
	BindingGRPC  Binding = "grpc"
	BindingHTTPS Binding = "https"
	BindingV2    Binding = "v2"
)

// v3State is the binding in use: svc is nil on v2. A blocked state
// carries no traffic at all (only the v2 hello that negotiation needs):
// the gRPC endpoint's certificate was refused, or SENSOR_TRANSPORT=grpc
// cannot be honored, and no other binding may stand in.
type v3State struct {
	svc     sensorv3connect.SensorServiceClient
	binding Binding
	reason  string
	since   time.Time
	blocked error
}

// maxV3RequestBytes bounds a request body the round tripper reads (the v2
// results limit is 16 MiB; the outbox may send a little more).
const maxV3RequestBytes = 64 << 20

// v3RoundTripper carries v2 requests over v3 when a v3 binding is selected.
type v3RoundTripper struct {
	next   http.RoundTripper
	state  *atomic.Pointer[v3State]
	prefix string
	// failed tells the manager about a transport failure of the binding.
	failed func(b Binding, err error)
}

// withNext is the same round tripper over another next transport (the
// control client's own pool).
func (t *v3RoundTripper) withNext(next http.RoundTripper) *v3RoundTripper {
	return &v3RoundTripper{next: next, state: t.state, prefix: t.prefix, failed: t.failed}
}

// Unwrap is the v2 transport underneath.
func (t *v3RoundTripper) Unwrap() http.RoundTripper { return t.next }

// RoundTrip implements http.RoundTripper.
func (t *v3RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	st := t.state.Load()
	if st != nil && st.blocked != nil && strings.HasPrefix(req.URL.Path, t.prefix+"/") &&
		(req.Method != http.MethodGet || req.URL.Path != t.prefix+protov2.HelloPath) {
		return nil, st.blocked
	}
	if st != nil && st.svc == nil && req.Method == http.MethodPost && req.URL.Path == t.prefix+protov2.HeartbeatPath {
		return t.next.RoundTrip(withTransportReport(req, st))
	}
	if st == nil || st.svc == nil || !strings.HasPrefix(req.URL.Path, t.prefix+"/") {
		return t.next.RoundTrip(req)
	}
	rest := strings.TrimPrefix(req.URL.Path, t.prefix)
	if !v3Carries(req.Method, rest) {
		return t.next.RoundTrip(req)
	}
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(req.Body, maxV3RequestBytes+1))
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(b) > maxV3RequestBytes {
			return nil, errors.New("request body too large")
		}
		body = b
	}
	resp, err := t.call(req, st, rest, body)
	if err != nil {
		if transportFailure(err) && t.failed != nil {
			t.failed(st.binding, err)
		}
		return nil, err
	}
	resp.Request = req
	return resp, nil
}

// v3Carries reports whether method + path (below /api/v2/sensor) is a
// resource v3 carries. Key renewal (bearer keys) and anything unknown stay
// on v2.
func v3Carries(method, rest string) bool {
	parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	switch {
	case rest == protov2.HelloPath, rest == protov2.ManifestPath:
		return method == http.MethodGet || (rest == protov2.ManifestPath && method == http.MethodPut)
	case rest == protov2.HeartbeatPath, rest == protov2.FingerprintsCheckPath, rest == protov2.BaselineDiffPath:
		return method == http.MethodPost
	case rest == protov2.ConfigReportPath:
		return method == http.MethodPut
	case rest == protov2.SuppressionsPath, rest == protov2.CommandsPath:
		return method == http.MethodGet
	case parts[0] == "results":
		return len(parts) >= 2
	case parts[0] == "commands" && len(parts) >= 3:
		return true
	}
	return false
}

func (t *v3RoundTripper) call(req *http.Request, st *v3State, rest string, body []byte) (*http.Response, error) {
	ctx := req.Context()
	parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	switch {
	case rest == protov2.HelloPath:
		r, err := st.svc.Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
		return answer(r, err, func(m *sensorv3.HelloResponse) *http.Response { return jsonResponse(http.StatusOK, m.GetHelloJson()) })

	case rest == protov2.HeartbeatPath:
		doc, err := plainBody(req, body)
		if err != nil {
			return nil, err
		}
		r, err := st.svc.Heartbeat(ctx, connect.NewRequest(&sensorv3.HeartbeatRequest{
			HeartbeatJson: doc, Transport: transportOf(st),
		}))
		return answer(r, err, func(m *sensorv3.HeartbeatResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetHeartbeatJson())
		})

	case rest == protov2.CommandsPath:
		limit, err := strconv.ParseInt(req.URL.Query().Get("limit"), 10, 32)
		if err != nil || limit <= 0 {
			limit = 10
		}
		limit = min(limit, 100)
		var features []string
		for _, f := range strings.Split(req.Header.Get(protov2.HeaderSensorFeatures), ",") {
			if f = strings.ToLower(strings.TrimSpace(f)); f != "" && len(features) < 16 {
				features = append(features, f)
			}
		}
		r, err := st.svc.ClaimCommands(ctx, connect.NewRequest(&sensorv3.ClaimCommandsRequest{
			Limit: int32(limit), Features: features,
		}))
		return answer(r, err, func(m *sensorv3.ClaimCommandsResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetCommandsJson())
		})

	case parts[0] == "commands" && len(parts) == 3 && parts[2] == "logs":
		doc, err := plainBody(req, body)
		if err != nil {
			return nil, err
		}
		r, err := st.svc.AppendCommandLogs(ctx, connect.NewRequest(&sensorv3.AppendCommandLogsRequest{CommandId: parts[1], BodyJson: doc}))
		return answer(r, err, func(m *sensorv3.AppendCommandLogsResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetResponseJson())
		})

	case parts[0] == "commands" && len(parts) == 3:
		tr, ok := transitions[parts[2]]
		if !ok {
			return nil, fmt.Errorf("protocol v3: unknown command action %q", parts[2])
		}
		doc, err := plainBody(req, body)
		if err != nil {
			return nil, err
		}
		in := &sensorv3.TransitionCommandRequest{CommandId: parts[1], Transition: tr, BodyJson: doc}
		if v := strings.TrimSpace(req.Header.Get(protov2.HeaderLeaseEpoch)); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
				in.LeaseEpoch = &n
			}
		}
		r, err := st.svc.TransitionCommand(ctx, connect.NewRequest(in))
		return answer(r, err, func(m *sensorv3.TransitionCommandResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetCommandJson())
		})

	case parts[0] == "results" || parts[0] == "commands":
		return t.results(req, st, parts, body)

	case rest == protov2.ManifestPath && req.Method == http.MethodPut:
		doc, err := plainBody(req, body)
		if err != nil {
			return nil, err
		}
		r, err := st.svc.PutManifest(ctx, connect.NewRequest(&sensorv3.PutManifestRequest{ManifestJson: doc}))
		return answer(r, err, func(m *sensorv3.PutManifestResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetResponseJson())
		})

	case rest == protov2.ManifestPath:
		r, err := st.svc.GetManifest(ctx, connect.NewRequest(&sensorv3.GetManifestRequest{}))
		return answer(r, err, func(m *sensorv3.GetManifestResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetResponseJson())
		})

	case rest == protov2.ConfigReportPath:
		doc, err := plainBody(req, body)
		if err != nil {
			return nil, err
		}
		r, err := st.svc.PutConfigReport(ctx, connect.NewRequest(&sensorv3.PutConfigReportRequest{ReportJson: doc}))
		return answer(r, err, func(m *sensorv3.PutConfigReportResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetResponseJson())
		})

	case rest == protov2.SuppressionsPath:
		r, err := st.svc.GetSuppressions(ctx, connect.NewRequest(&sensorv3.GetSuppressionsRequest{Etag: req.Header.Get("If-None-Match")}))
		return answer(r, err, func(m *sensorv3.GetSuppressionsResponse) *http.Response {
			var resp *http.Response
			if m.GetNotModified() {
				resp = jsonResponse(http.StatusNotModified, nil)
			} else {
				resp = jsonResponse(http.StatusOK, m.GetSuppressionsJson())
			}
			if m.GetEtag() != "" {
				resp.Header.Set("ETag", m.GetEtag())
			}
			return resp
		})

	case rest == protov2.FingerprintsCheckPath:
		doc, err := plainBody(req, body)
		if err != nil {
			return nil, err
		}
		r, err := st.svc.CheckFingerprints(ctx, connect.NewRequest(&sensorv3.CheckFingerprintsRequest{RequestJson: doc}))
		return answer(r, err, func(m *sensorv3.CheckFingerprintsResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetResponseJson())
		})

	case rest == protov2.BaselineDiffPath:
		doc, err := plainBody(req, body)
		if err != nil {
			return nil, err
		}
		r, err := st.svc.BaselineDiff(ctx, connect.NewRequest(&sensorv3.BaselineDiffRequest{RequestJson: doc}))
		return answer(r, err, func(m *sensorv3.BaselineDiffResponse) *http.Response {
			return jsonResponse(http.StatusOK, m.GetResponseJson())
		})
	}
	return nil, fmt.Errorf("protocol v3: %s %s is not carried", req.Method, rest)
}

var transitions = map[string]sensorv3.CommandTransition{
	"claim":    sensorv3.CommandTransition_COMMAND_TRANSITION_CLAIM,
	"start":    sensorv3.CommandTransition_COMMAND_TRANSITION_START,
	"complete": sensorv3.CommandTransition_COMMAND_TRANSITION_COMPLETE,
	"fail":     sensorv3.CommandTransition_COMMAND_TRANSITION_FAIL,
	"release":  sensorv3.CommandTransition_COMMAND_TRANSITION_RELEASE,
}

// results carries the report resources: PUT (whole or segment), POST commit,
// GET status, DELETE abandon, in their plain and command-bound forms.
func (t *v3RoundTripper) results(req *http.Request, st *v3State, parts []string, body []byte) (*http.Response, error) {
	ctx := req.Context()
	var commandID string
	if parts[0] == "commands" {
		// commands/{c}/results/{r}[/...]
		if len(parts) < 4 || parts[2] != "results" {
			return nil, errors.New("protocol v3: malformed results path")
		}
		commandID, parts = parts[1], parts[2:]
	}
	reportID := parts[1]
	switch {
	case req.Method == http.MethodPut && (len(parts) == 2 || (len(parts) == 4 && parts[2] == "segments")):
		in := &sensorv3.PutResultRequest{
			ReportId: reportID, CommandId: commandID, Content: body,
			ContentType:     req.Header.Get("Content-Type"),
			ContentEncoding: req.Header.Get("Content-Encoding"),
			ContentDigest:   req.Header.Get(protov2.HeaderContentDigest),
		}
		if len(parts) == 4 {
			n, err := strconv.ParseUint(parts[3], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("protocol v3: segment %q: %w", parts[3], err)
			}
			seg := uint32(n)
			in.Segment = &seg
		}
		r, err := st.svc.PutResult(ctx, connect.NewRequest(in))
		return answer(r, err, func(m *sensorv3.PutResultResponse) *http.Response {
			return statusResponse(m.GetCreated(), m.GetStatusJson(), m.GetRetryAfterSeconds(), reportID)
		})
	case req.Method == http.MethodPost && len(parts) == 3 && parts[2] == "commit":
		doc, err := plainBody(req, body)
		if err != nil {
			return nil, err
		}
		r, err := st.svc.CommitResult(ctx, connect.NewRequest(&sensorv3.CommitResultRequest{ReportId: reportID, CommandId: commandID, BodyJson: doc}))
		return answer(r, err, func(m *sensorv3.CommitResultResponse) *http.Response {
			return statusResponse(m.GetCreated(), m.GetStatusJson(), m.GetRetryAfterSeconds(), reportID)
		})
	case req.Method == http.MethodGet && len(parts) == 2:
		r, err := st.svc.GetResultStatus(ctx, connect.NewRequest(&sensorv3.GetResultStatusRequest{ReportId: reportID}))
		return answer(r, err, func(m *sensorv3.GetResultStatusResponse) *http.Response {
			resp := jsonResponse(http.StatusOK, m.GetStatusJson())
			setRetryAfter(resp, m.GetRetryAfterSeconds())
			return resp
		})
	case req.Method == http.MethodDelete && len(parts) == 2:
		r, err := st.svc.AbandonResult(ctx, connect.NewRequest(&sensorv3.AbandonResultRequest{ReportId: reportID}))
		return answer(r, err, func(*sensorv3.AbandonResultResponse) *http.Response { return jsonResponse(http.StatusNoContent, nil) })
	}
	return nil, fmt.Errorf("protocol v3: %s results path is not carried", req.Method)
}

// answer turns an RPC result into the v2 HTTP response: ok builds it from
// the message; a refusal carrying the v2 problem becomes that problem
// response; any other error is returned as a transport error (the v2 client
// retries it as a network failure).
func answer[T any](r *connect.Response[T], err error, ok func(*T) *http.Response) (*http.Response, error) {
	if err == nil {
		return ok(r.Msg), nil
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return nil, err
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if p, isProblem := v.(*sensorv3.Problem); derr == nil && isProblem && p.GetHttpStatus() >= 400 && p.GetHttpStatus() < 600 {
			resp := &http.Response{
				StatusCode: int(p.GetHttpStatus()),
				Header:     http.Header{"Content-Type": []string{protov2.MediaTypeProblem}},
				Body:       io.NopCloser(bytes.NewReader(p.GetProblemJson())),
			}
			setRetryAfter(resp, p.GetRetryAfterSeconds())
			resp.ContentLength = int64(len(p.GetProblemJson()))
			return finish(resp), nil
		}
	}
	// A refusal without a problem (the binding's own guard): the status the
	// code stands for, so the v2 client classifies it as it would on v2.
	if status, ok := statusForCode(ce.Code()); ok {
		body := []byte(`{"title":` + strconv.Quote(ce.Message()) + `}`)
		resp := &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
		return finish(resp), nil
	}
	return nil, err
}

// statusForCode maps the codes a platform answers without a problem
// (authentication, limits, bad input) to their HTTP status. Transport-level
// codes (unavailable, deadline, internal, unknown, unimplemented) are not
// mapped: they are errors of the binding.
func statusForCode(c connect.Code) (int, bool) {
	switch c {
	case connect.CodeUnauthenticated:
		return http.StatusUnauthorized, true
	case connect.CodePermissionDenied:
		return http.StatusForbidden, true
	case connect.CodeNotFound:
		return http.StatusNotFound, true
	case connect.CodeInvalidArgument:
		return http.StatusBadRequest, true
	case connect.CodeResourceExhausted:
		return http.StatusTooManyRequests, true
	case connect.CodeAborted, connect.CodeAlreadyExists:
		return http.StatusConflict, true
	case connect.CodeFailedPrecondition:
		return http.StatusPreconditionFailed, true
	}
	return 0, false
}

// transportFailure reports an error of the binding itself (not a refusal):
// the manager counts these to decide on a fallback.
func transportFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeUnknown, connect.CodeUnimplemented, connect.CodeInternal:
		return true
	}
	return false
}

func jsonResponse(status int, body []byte) *http.Response {
	resp := &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{protov2.MediaTypeJSON}, protov2.HeaderProtocol: []string{"2"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	return finish(resp)
}

func statusResponse(created bool, status []byte, retryAfter int32, reportID string) *http.Response {
	code := http.StatusOK
	if created {
		code = http.StatusAccepted
	}
	resp := jsonResponse(code, status)
	resp.Header.Set("Location", protov2.PathPrefix+protov2.ResultsPath+"/"+url.PathEscape(reportID))
	setRetryAfter(resp, retryAfter)
	return resp
}

func setRetryAfter(resp *http.Response, s int32) {
	if s > 0 {
		resp.Header.Set(protov2.HeaderRetryAfter, strconv.Itoa(int(s)))
	}
}

func finish(resp *http.Response) *http.Response {
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/2.0", 2, 0
	resp.Status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	return resp
}

// plainBody is a JSON document body without its content coding (the v2
// client compresses some bodies; v3 carries documents uncompressed and
// compresses the whole message itself).
func plainBody(req *http.Request, body []byte) ([]byte, error) {
	if body == nil {
		body = []byte{}
	}
	switch strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Encoding"))) {
	case "", "identity":
		return body, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return readBounded(zr)
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderMaxMemory(maxV3RequestBytes))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return readBounded(zr)
	}
	return nil, fmt.Errorf("protocol v3: unsupported content coding %q", req.Header.Get("Content-Encoding"))
}

func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxV3RequestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxV3RequestBytes {
		return nil, errors.New("decompressed body too large")
	}
	return b, nil
}

// withTransportReport is a v2 heartbeat with the transport report added.
func withTransportReport(req *http.Request, st *v3State) *http.Request {
	if req.Body == nil || req.Body == http.NoBody || req.Header.Get("Content-Encoding") != "" {
		return req
	}
	b, err := io.ReadAll(io.LimitReader(req.Body, maxV3RequestBytes+1))
	_ = req.Body.Close()
	if err != nil || len(b) > maxV3RequestBytes {
		req.Body = io.NopCloser(bytes.NewReader(b))
		return req
	}
	b = injectTransport(b, st)
	out := req.Clone(req.Context())
	out.Body = io.NopCloser(bytes.NewReader(b))
	out.ContentLength = int64(len(b))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	return out
}

// unwrapTransport is the transport under a v3 round tripper.
func unwrapTransport(rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*v3RoundTripper); ok {
		return t.next
	}
	return rt
}

// urlPath is the path of the base URL without a trailing slash.
func urlPath(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(u.Path, "/"), nil
}

// transportOf is the heartbeat's transport report.
func transportOf(st *v3State) *sensorv3.Transport {
	b := sensorv3.Binding_BINDING_V2
	switch st.binding {
	case BindingGRPC:
		b = sensorv3.Binding_BINDING_GRPC
	case BindingHTTPS:
		b = sensorv3.Binding_BINDING_HTTPS
	}
	return &sensorv3.Transport{Binding: b, FallbackReason: st.reason, Since: timestamppb.New(st.since)}
}

// injectTransport adds the transport report to a v2 heartbeat body (the v2
// binding carries it as the "transport" member; a platform that does not
// know it ignores it).
func injectTransport(body []byte, st *v3State) []byte {
	var doc map[string]json.RawMessage
	if len(body) == 0 || json.Unmarshal(body, &doc) != nil {
		return body
	}
	raw, err := json.Marshal(map[string]any{
		"binding": string(st.binding), "fallback_reason": st.reason, "since": st.since.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return body
	}
	doc["transport"] = raw
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}
