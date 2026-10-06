package conformance

// The api RFC-029 control plane of the fake platform: heartbeat, commands
// (poll and idempotent claim/start/complete/fail), suppressions with an ETag,
// fingerprint queries and key renewal, strictly as the RFC specifies them.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// fakeSuppressionsETag is the strong ETag of the fake's suppression list.
const fakeSuppressionsETag = `"0123456789abcdef"`

// control serves a control-plane route and reports whether rest was one.
func (f *FakePlatform) control(w http.ResponseWriter, r *http.Request, rest string, body []byte) bool {
	switch {
	case rest == protov2.HeartbeatPath && r.Method == http.MethodPost:
		f.heartbeatV2(w, body)
	case rest == protov2.CommandsPath && r.Method == http.MethodGet:
		f.pollV2(w, r)
	case strings.HasPrefix(rest, protov2.CommandsPath+"/") && r.Method == http.MethodPost && strings.Count(rest, "/") == 3:
		parts := strings.Split(strings.TrimPrefix(rest, protov2.CommandsPath+"/"), "/")
		switch parts[1] {
		case protov2.ClaimAction, protov2.StartAction, protov2.CompleteAction, protov2.FailAction, protov2.ReleaseAction:
			f.transitionV2(w, parts[0], parts[1], body, r.Header.Get(protov2.HeaderLeaseEpoch))
		case protov2.LogsAction:
			f.mu.Lock()
			on := f.logs
			f.mu.Unlock()
			if !on {
				return false
			}
			f.logsV2(w, parts[0], body)
		default:
			return false
		}
	case rest == protov2.SuppressionsPath && r.Method == http.MethodGet:
		w.Header().Set("ETag", fakeSuppressionsETag)
		w.Header().Set(protov2.HeaderProtocol, "2")
		if r.Header.Get("If-None-Match") == fakeSuppressionsETag {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
		writeJSON(w, http.StatusOK, protov2.SuppressionList{Count: 1, Rules: []protov2.SuppressionRule{
			{RuleID: "r1", ToolName: "betterleaks", PathPattern: "testdata/**"}}})
	case (rest == protov2.FingerprintsCheckPath || rest == protov2.BaselineDiffPath) && r.Method == http.MethodPost:
		f.fingerprintsV2(w, rest, body)
	case rest == protov2.ManifestPath && (r.Method == http.MethodPut || r.Method == http.MethodGet):
		f.mu.Lock()
		on := f.Manifest
		f.mu.Unlock()
		if !on {
			return false
		}
		if r.Method == http.MethodGet {
			f.manifestStateV2(w)
			return true
		}
		f.manifestV2(w, body)
	case rest == protov2.ConfigReportPath && r.Method == http.MethodPut:
		f.mu.Lock()
		on := f.configReport
		f.mu.Unlock()
		if !on {
			return false
		}
		f.configReportV2(w, body)
	case rest == protov2.KeysPath && r.Method == http.MethodPost:
		f.mu.Lock()
		f.keys++
		key := "rda_rotated_" + strconv.Itoa(f.keys)
		f.APIKey = key
		f.mu.Unlock()
		exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, protov2.KeyResponse{APIKey: key, ExpiresAt: &exp})
	default:
		return false
	}
	return true
}

// logsV2 stores one batch of a command's logs (idempotent by seq). A
// command the fake does not know is not found.
func (f *FakePlatform) logsV2(w http.ResponseWriter, id string, body []byte) {
	var req protov2.CommandLogsRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Seq < 0 || len(req.Lines) > protov2.MaxCommandLogLines {
		f.problem(w, http.StatusBadRequest, protov2.ProblemSchemaInvalid)
		return
	}
	f.mu.Lock()
	if _, ok := f.commands[id]; !ok {
		f.mu.Unlock()
		f.problem(w, http.StatusNotFound, protov2.ProblemCommandNotFound)
		return
	}
	if f.cmdLogs == nil {
		f.cmdLogs = map[string]map[int]protov2.CommandLogsRequest{}
	}
	if f.cmdLogs[id] == nil {
		f.cmdLogs[id] = map[int]protov2.CommandLogsRequest{}
	}
	if _, dup := f.cmdLogs[id][req.Seq]; !dup {
		f.cmdLogs[id][req.Seq] = req
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, protov2.CommandLogsResponse{Stored: len(req.Lines)})
}

func (f *FakePlatform) heartbeatV2(w http.ResponseWriter, body []byte) {
	f.mu.Lock()
	f.recordHeartbeat(body)
	paused := f.Paused
	var hb struct {
		ManifestDigest string `json:"manifest_digest"`
		ConfigReport   *struct {
			Digest string `json:"digest"`
		} `json:"config_report"`
	}
	_ = json.Unmarshal(body, &hb)
	askManifest := f.Manifest && hb.ManifestDigest != "" && hb.ManifestDigest != f.digest
	askConfig := f.configReport && hb.ConfigReport != nil && hb.ConfigReport.Digest != "" && hb.ConfigReport.Digest != f.configDigest
	pending := 0
	for _, id := range f.cmdQueue {
		if f.commands[id] == "pending" {
			pending++
		}
	}
	f.mu.Unlock()
	resp := protov2.HeartbeatResponse{SensorID: "s1", TenantID: "t1", Status: protov2.HeartbeatStatusOK,
		PendingJobs: pending, NextHeartbeatSeconds: 30, Actions: []string{}, ConfigVersion: "0123456789abcdef"}
	if paused {
		resp.Status, resp.Actions, resp.PendingJobs = protov2.HeartbeatStatusPaused, []string{"pause"}, 0
	} else if pending > 0 {
		resp.NextHeartbeatSeconds = 5
	}
	if askManifest && !paused {
		resp.Actions = append(resp.Actions, "send_manifest")
	}
	if askConfig && !paused {
		resp.Actions = append(resp.Actions, protov2.ActionSendConfigReport)
	}
	writeJSON(w, http.StatusOK, resp)
}

// manifestV2 stores a manifest (api RFC-033): its digest over the canonical
// JSON, and an answer that accepts every tool.
func (f *FakePlatform) manifestV2(w http.ResponseWriter, body []byte) {
	var m struct {
		Schema int `json:"schema"`
		Tools  []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if json.Unmarshal(body, &m) != nil || m.Schema != 1 {
		f.problem(w, http.StatusUnprocessableEntity, protov2.ProblemManifestInvalid)
		return
	}
	var v any
	_ = json.Unmarshal(body, &v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	var names []string
	for _, t := range m.Tools {
		names = append(names, t.Name)
	}
	f.mu.Lock()
	changed := digest != f.digest
	f.digest = digest
	f.manifests = append(f.manifests, append(json.RawMessage(nil), body...))
	f.manifestTools = names
	policy, slim := f.policyLocked(), f.slim
	f.mu.Unlock()
	resp := protov2.ManifestResponse{ManifestDigest: digest, Changed: changed, Ignored: []protov2.ManifestIgnored{},
		Policy: policy, Heartbeat: protov2.ManifestHeartbeat{OmitInventory: slim}}
	resp.Accepted.Capabilities = []string{}
	resp.Accepted.Tools = names
	writeJSON(w, http.StatusOK, resp)
}

// configReportV2 stores a config report: 413 above the limit, 422 for a
// schema other than 1, else its digest over the canonical JSON.
func (f *FakePlatform) configReportV2(w http.ResponseWriter, body []byte) {
	if len(body) > protov2.MaxConfigReportBytes {
		f.problem(w, http.StatusRequestEntityTooLarge, protov2.ProblemContentTooLarge)
		return
	}
	var m struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(body, &m) != nil || m.Schema != 1 {
		f.problem(w, http.StatusUnprocessableEntity, protov2.ProblemSchemaInvalid)
		return
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	f.mu.Lock()
	changed := digest != f.configDigest
	f.configDigest = digest
	f.configReports = append(f.configReports, append(json.RawMessage(nil), body...))
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, protov2.ConfigReportResponse{ConfigReportDigest: digest, Changed: changed,
		Ignored: []protov2.ManifestIgnored{}})
}

// manifestStateV2 answers GET /manifest: the stored digest and the policy.
func (f *FakePlatform) manifestStateV2(w http.ResponseWriter) {
	f.mu.Lock()
	digest, policy, slim := f.digest, f.policyLocked(), f.slim
	f.mu.Unlock()
	if digest == "" {
		f.problem(w, http.StatusNotFound, protov2.ProblemManifestNotFound)
		return
	}
	writeJSON(w, http.StatusOK, protov2.ManifestStateResponse{ManifestDigest: digest, Policy: policy,
		Heartbeat: protov2.ManifestHeartbeat{OmitInventory: slim}})
}

func (f *FakePlatform) policyLocked() *protov2.ManifestPolicy {
	tools := f.policyTools
	if tools == nil {
		tools = append([]string{}, f.manifestTools...)
	}
	return &protov2.ManifestPolicy{AllowedTools: tools, AllowedCapabilities: []string{}}
}

func (f *FakePlatform) pollV2(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 || limit > 100 {
		limit = 10
	}
	f.mu.Lock()
	out := protov2.CommandList{Commands: []protov2.Command{}}
	for _, id := range f.cmdQueue {
		if f.commands[id] != "pending" || len(out.Commands) >= limit {
			continue
		}
		exp := time.Now().Add(time.Hour).UTC()
		typ, payload := "scan", json.RawMessage(`{"scanner":"fake"}`)
		if t := f.cmdType[id]; t != "" {
			typ = t
		}
		if p := f.cmdPayload[id]; len(p) > 0 {
			payload = p
		}
		out.Commands = append(out.Commands, protov2.Command{ID: id, Type: typ, Priority: "normal", Status: "pending",
			Payload: payload, CreatedAt: time.Now().UTC(), ExpiresAt: &exp, Result: json.RawMessage("null"),
			LeaseEpoch: f.cmdEpoch[id]})
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// transitionV2 applies RFC-029 §4.4 for a sensor that owns every command it
// claimed (the fake has one sensor). leaseHdr is the X-OpenCTEM-Lease-Epoch
// the sensor sent: on complete and fail a number other than the command's
// epoch is refused as the platform refuses it (api RFC-035 D6).
func (f *FakePlatform) transitionV2(w http.ResponseWriter, id, action string, body []byte, leaseHdr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.commands[id]
	if !ok {
		f.problem(w, http.StatusNotFound, protov2.ProblemCommandNotFound)
		return
	}
	target := map[string]string{protov2.ClaimAction: "acknowledged", protov2.StartAction: "running",
		protov2.CompleteAction: "completed", protov2.FailAction: "failed", protov2.ReleaseAction: "pending"}[action]
	from := map[string][]string{protov2.ClaimAction: {"pending"}, protov2.StartAction: {"acknowledged"},
		protov2.CompleteAction: {"running"}, protov2.FailAction: {"acknowledged", "running"},
		protov2.ReleaseAction: {"acknowledged", "running"}}[action]
	if target == "" {
		f.problem(w, http.StatusNotFound, protov2.ProblemCommandNotFound)
		return
	}
	var req struct {
		Result       json.RawMessage `json:"result"`
		ErrorMessage string          `json:"error_message"`
		Reason       string          `json:"reason"`
	}
	_ = json.Unmarshal(body, &req)
	if action == protov2.ReleaseAction {
		// Release returns the command to pending (api RFC-030); it is
		// never "the same state again" for a sensor that still holds it.
		if !contains(from, state) {
			f.problemState(w, http.StatusConflict, protov2.ProblemInvalidTransition, state)
			return
		}
		f.commands[id] = "pending"
		f.released = append(f.released, Release{CommandID: id, Reason: req.Reason})
		writeJSON(w, http.StatusOK, f.commandLocked(id, "pending"))
		return
	}

	if state == target {
		same := true
		switch action {
		case protov2.CompleteAction:
			same = sameJSON(f.cmdResult[id], req.Result)
		case protov2.FailAction:
			same = f.cmdErrors[id] == req.ErrorMessage
		}
		if !same {
			f.problem(w, http.StatusConflict, protov2.ProblemTransitionConflict)
			return
		}
		writeJSON(w, http.StatusOK, f.commandLocked(id, state))
		return
	}
	if !contains(from, state) {
		f.problemState(w, http.StatusConflict, protov2.ProblemInvalidTransition, state)
		return
	}
	if action == protov2.CompleteAction || action == protov2.FailAction {
		if n, err := strconv.Atoi(strings.TrimSpace(leaseHdr)); err == nil && n >= 0 && n != f.cmdEpoch[id] {
			f.problemState(w, http.StatusConflict, protov2.ProblemInvalidTransition, state)
			return
		}
	}
	if action == protov2.ClaimAction {
		f.cmdEpoch[id]++
	}
	f.commands[id] = target
	switch action {
	case protov2.CompleteAction:
		f.cmdResult[id] = req.Result
	case protov2.FailAction:
		f.cmdErrors[id] = req.ErrorMessage
	}
	writeJSON(w, http.StatusOK, f.commandLocked(id, target))
}

// commandLocked is the answer of a transition: the command with its lease.
func (f *FakePlatform) commandLocked(id, state string) protov2.Command {
	typ, payload := "scan", json.RawMessage(`{"scanner":"fake"}`)
	if t := f.cmdType[id]; t != "" {
		typ = t
	}
	if p := f.cmdPayload[id]; len(p) > 0 {
		payload = p
	}
	// As the platform does: a transition answers the whole command.
	out := protov2.Command{ID: id, Type: typ, Priority: "normal", Status: state, Payload: payload,
		LeaseEpoch: f.cmdEpoch[id]}
	if state == "acknowledged" || state == "running" {
		exp := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
		out.LeaseExpiresAt = &exp
	}
	return out
}

func sameJSON(a, b json.RawMessage) bool {
	a, b = bytes.TrimSpace(a), bytes.TrimSpace(b)
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	var av, bv any
	return json.Unmarshal(a, &av) == nil && json.Unmarshal(b, &bv) == nil && reflect.DeepEqual(av, bv)
}

func (f *FakePlatform) fingerprintsV2(w http.ResponseWriter, rest string, body []byte) {
	var req struct {
		Fingerprints []string `json:"fingerprints"`
	}
	if json.Unmarshal(body, &req) != nil {
		f.problem(w, http.StatusBadRequest, protov2.ProblemInvalidRequest)
		return
	}
	limit := f.Limits.WithDefaults().MaxFingerprintsPerRequest
	if len(req.Fingerprints) > limit {
		f.problem(w, http.StatusUnprocessableEntity, protov2.ProblemTooManyItems)
		return
	}
	fps := append([]string{}, req.Fingerprints...)
	if rest == protov2.FingerprintsCheckPath {
		writeJSON(w, http.StatusOK, protov2.FingerprintsCheckResponse{Existing: []string{}, Missing: fps})
		return
	}
	writeJSON(w, http.StatusOK, protov2.BaselineDiffResponse{NewFingerprints: fps, PreExistingFingerprints: []string{}, BaseBranchScanned: true})
}
