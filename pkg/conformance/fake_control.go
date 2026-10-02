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
			f.transitionV2(w, parts[0], parts[1], body)
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
	case rest == protov2.ManifestPath && r.Method == http.MethodPut:
		f.mu.Lock()
		on := f.Manifest
		f.mu.Unlock()
		if !on {
			return false
		}
		f.manifestV2(w, body)
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

func (f *FakePlatform) heartbeatV2(w http.ResponseWriter, body []byte) {
	f.mu.Lock()
	f.recordHeartbeat(body)
	paused := f.Paused
	var hb struct {
		ManifestDigest string `json:"manifest_digest"`
	}
	_ = json.Unmarshal(body, &hb)
	askManifest := f.Manifest && hb.ManifestDigest != "" && hb.ManifestDigest != f.digest
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
	f.mu.Lock()
	changed := digest != f.digest
	f.digest = digest
	f.manifests = append(f.manifests, append(json.RawMessage(nil), body...))
	f.mu.Unlock()
	resp := protov2.ManifestResponse{ManifestDigest: digest, Changed: changed, Ignored: []protov2.ManifestIgnored{}}
	resp.Accepted.Capabilities = []string{}
	for _, t := range m.Tools {
		resp.Accepted.Tools = append(resp.Accepted.Tools, t.Name)
	}
	writeJSON(w, http.StatusOK, resp)
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
		out.Commands = append(out.Commands, protov2.Command{ID: id, Type: "scan", Priority: "normal", Status: "pending",
			Payload: json.RawMessage(`{"scanner":"fake"}`), CreatedAt: time.Now().UTC(), ExpiresAt: &exp, Result: json.RawMessage("null")})
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// transitionV2 applies RFC-029 §4.4 for a sensor that owns every command it
// claimed (the fake has one sensor).
func (f *FakePlatform) transitionV2(w http.ResponseWriter, id, action string, body []byte) {
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
		writeJSON(w, http.StatusOK, protov2.Command{ID: id, Status: "pending"})
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
		writeJSON(w, http.StatusOK, protov2.Command{ID: id, Status: state})
		return
	}
	if !contains(from, state) {
		f.problemState(w, http.StatusConflict, protov2.ProblemInvalidTransition, state)
		return
	}
	f.commands[id] = target
	switch action {
	case protov2.CompleteAction:
		f.cmdResult[id] = req.Result
	case protov2.FailAction:
		f.cmdErrors[id] = req.ErrorMessage
	}
	writeJSON(w, http.StatusOK, protov2.Command{ID: id, Status: target})
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
