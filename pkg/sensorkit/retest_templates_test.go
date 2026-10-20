package sensorkit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Retests that carry custom templates (HandleRetestTemplates): the kit
// admits, verifies and writes them before the tool runs, exactly as a
// scan's, and holds each templated verdict to the delivered template.

const (
	rtCmdID    = "0192a3b4-0000-7000-8000-0000000000f1"
	rtSensorID = "sensor-rt"
	rtBody     = "id: probe\ninfo:\n  name: probe\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/x']\n"
	rtCode     = "id: probe\ninfo:\n  name: probe\n  severity: info\ncode:\n  - engine: [sh]\n    source: id\n"
)

func rtTemplate(id, typ, body string) core.EmbeddedTemplate {
	return core.EmbeddedTemplate{ID: id, Name: id + ".yaml", TemplateType: typ, Content: base64.StdEncoding.EncodeToString([]byte(body))}
}

// rtSign is the platform's per-tenant template manifest for cmdID.
func rtSign(t *testing.T, priv ed25519.PrivateKey, cmdID string, tpls []core.EmbeddedTemplate) *core.SignedEnvelope {
	t.Helper()
	m := core.TemplateManifest{Kind: core.TemplateManifestKind, TenantID: "tenant-a", SensorID: rtSensorID, CommandID: cmdID,
		IssuedAt: time.Now().Add(-time.Minute).UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC()}
	for _, tp := range tpls {
		raw, _ := base64.StdEncoding.DecodeString(tp.Content)
		sum := sha256.Sum256(raw)
		m.Templates = append(m.Templates, core.ManifestTemplate{ID: tp.ID, Name: tp.Name, TemplateType: tp.TemplateType, SHA256: hex.EncodeToString(sum[:])})
	}
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &core.SignedEnvelope{PayloadType: core.TemplateManifestPayloadType, Payload: payload,
		Signatures: []core.EnvelopeSignature{{KeyID: core.TemplateKeyID(pub),
			Sig: ed25519.Sign(priv, core.DSSEPreAuthEncoding(core.TemplateManifestPayloadType, payload))}}}
}

// rtFixture is a retest executor for "nuclei" (opted in to templates) whose
// run records the task and answers with verdict().
type rtFixture struct {
	x       *retestExecutor
	priv    ed25519.PrivateKey
	calls   int
	task    tool.Task
	files   map[string]string // item ref -> file content seen during the run
	verdict func(task tool.Task) []tool.RetestVerdict
}

func newRTFixture(t *testing.T, policy *core.LocalPolicy) *rtFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := core.NewTemplateVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	exec := core.NewDefaultCommandExecutor(nil)
	exec.SetTemplateVerifier(v)
	exec.SetSensorID(rtSensorID)
	f := &rtFixture{priv: priv, files: map[string]string{}}
	run := func(_ context.Context, task tool.Task) (*toolhost.Outcome, error) {
		f.calls++
		f.task = task
		for _, it := range task.Retest {
			if it.TemplatePath != "" {
				b, err := os.ReadFile(it.TemplatePath)
				if err != nil {
					t.Errorf("item %s: template file unreadable during the run: %v", it.Ref, err)
				}
				f.files[it.Ref] = string(b)
			}
		}
		out := &toolhost.Outcome{Status: tool.StatusOK}
		if f.verdict != nil {
			out.Verdicts = f.verdict(task)
		}
		return out, nil
	}
	f.x = newRetestExecutor(nil, map[string]RetestFunc{"nuclei": run, "other": run}, map[string]bool{"nuclei": true},
		exec, func() *core.LocalPolicy { return policy })
	return f
}

// command is a retest of tool with items f1 (templated with tmplRef) and f2
// (the tool's own rule), carrying tpls signed by env.
func (f *rtFixture) command(t *testing.T, toolName, tmplRef string, tpls []core.EmbeddedTemplate, env *core.SignedEnvelope) *core.Command {
	t.Helper()
	p := map[string]any{"scanner": toolName, "targets": []string{"https://a.example"},
		"items": []map[string]string{
			{"ref": "f1", "target": "https://a.example", "kind": "finding", "rule_id": "custom", "template": tmplRef},
			{"ref": "f2", "target": "https://a.example", "kind": "finding", "rule_id": "managed-id"}}}
	if tpls != nil {
		p["custom_templates"] = tpls
	}
	if env != nil {
		p["custom_templates_envelope"] = env
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: rtCmdID, Type: RetestCommandType, Payload: raw}
}

func rtVerdicts(t *testing.T, res *core.CommandExecutionResult) map[string]tool.RetestVerdict {
	t.Helper()
	r, ok := res.Metadata["retest"].(RetestResult)
	if !ok {
		t.Fatalf("no retest result: %#v", res.Metadata)
	}
	out := map[string]tool.RetestVerdict{}
	for _, v := range r.Verdicts {
		out[v.Ref] = v
	}
	return out
}

func TestRetestTemplates_DeliveredTemplateRunsAndIsRemoved(t *testing.T) {
	f := newRTFixture(t, nil)
	tpls := []core.EmbeddedTemplate{rtTemplate("t1", "nuclei", rtBody)}
	want := jobsig.TemplateDigest([]byte(rtBody))
	f.verdict = func(task tool.Task) []tool.RetestVerdict {
		return []tool.RetestVerdict{{Ref: "f1", Verdict: tool.StillPresent, TemplateDigest: want},
			{Ref: "f2", Verdict: tool.Fixed, TemplateDigest: "sha256:managed"}}
	}
	res, err := f.x.Execute(context.Background(), f.command(t, "nuclei", "t1", tpls, rtSign(t, f.priv, rtCmdID, tpls)))
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || f.files["f1"] != rtBody {
		t.Fatalf("calls %d, f1 file %q; want one run with the delivered template", f.calls, f.files["f1"])
	}
	if f.task.Retest[1].TemplatePath != "" {
		t.Errorf("an item without a template got %q", f.task.Retest[1].TemplatePath)
	}
	path := f.task.Retest[0].TemplatePath
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the template file outlived the retest: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("the template directory outlived the retest: %v", err)
	}
	v := rtVerdicts(t, res)
	if v["f1"].Verdict != tool.StillPresent || v["f1"].TemplateDigest != want || v["f2"].Verdict != tool.Fixed {
		t.Errorf("verdicts %+v", v)
	}
}

func TestRetestTemplates_VerdictHeldToDeliveredDigest(t *testing.T) {
	f := newRTFixture(t, nil)
	tpls := []core.EmbeddedTemplate{rtTemplate("t1", "nuclei", rtBody)}
	want := jobsig.TemplateDigest([]byte(rtBody))
	f.verdict = func(tool.Task) []tool.RetestVerdict {
		return []tool.RetestVerdict{{Ref: "f1", Verdict: tool.Fixed, TemplateDigest: "sha256:other"},
			{Ref: "f2", Verdict: tool.Unverifiable}}
	}
	res, err := f.x.Execute(context.Background(), f.command(t, "nuclei", "t1", tpls, rtSign(t, f.priv, rtCmdID, tpls)))
	if err != nil {
		t.Fatal(err)
	}
	v := rtVerdicts(t, res)
	if v["f1"].Verdict != tool.Unverifiable || v["f1"].TemplateDigest != want {
		t.Errorf("a fixed verdict from another check stood: %+v", v["f1"])
	}
	if v["f2"].TemplateDigest != "" {
		t.Errorf("an item without a template got a digest: %+v", v["f2"])
	}
	// An unverifiable templated verdict without a digest gets the delivered one.
	f.verdict = func(tool.Task) []tool.RetestVerdict {
		return []tool.RetestVerdict{{Ref: "f1", Verdict: tool.Unverifiable, Detail: "the check could not be loaded"}}
	}
	res, err = f.x.Execute(context.Background(), f.command(t, "nuclei", "t1", tpls, rtSign(t, f.priv, rtCmdID, tpls)))
	if err != nil {
		t.Fatal(err)
	}
	if v := rtVerdicts(t, res); v["f1"].TemplateDigest != want || v["f1"].Verdict != tool.Unverifiable {
		t.Errorf("unverifiable templated verdict: %+v", v["f1"])
	}
}

func TestRetestTemplates_Refusals(t *testing.T) {
	deny, err := core.ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\nallow_custom_templates: false\n"), core.LocalPolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	good := []core.EmbeddedTemplate{rtTemplate("t1", "nuclei", rtBody)}
	code := []core.EmbeddedTemplate{rtTemplate("t1", "nuclei", rtCode)}
	semgrep := []core.EmbeddedTemplate{rtTemplate("t1", "semgrep", rtBody)}
	cases := []struct {
		name   string
		policy *core.LocalPolicy
		cmd    func(f *rtFixture) *core.Command
		want   string
	}{
		{"unsigned", nil, func(f *rtFixture) *core.Command { return f.command(t, "nuclei", "t1", good, nil) }, "custom templates refused"},
		{"signed for another command", nil, func(f *rtFixture) *core.Command {
			return f.command(t, "nuclei", "t1", good, rtSign(t, f.priv, "0192a3b4-0000-7000-8000-0000000000ff", good))
		}, "custom templates refused"},
		{"signed other content", nil, func(f *rtFixture) *core.Command {
			return f.command(t, "nuclei", "t1", good, rtSign(t, f.priv, rtCmdID, []core.EmbeddedTemplate{rtTemplate("t1", "nuclei", rtBody+"# x\n")}))
		}, "custom templates refused"},
		{"policy disallows", deny, func(f *rtFixture) *core.Command {
			return f.command(t, "nuclei", "t1", good, rtSign(t, f.priv, rtCmdID, good))
		}, "allow_custom_templates"},
		{"unknown template", nil, func(f *rtFixture) *core.Command {
			return f.command(t, "nuclei", "t9", good, rtSign(t, f.priv, rtCmdID, good))
		}, "does not carry"},
		{"template without templates", nil, func(f *rtFixture) *core.Command { return f.command(t, "nuclei", "t1", nil, nil) }, "carries none"},
		{"code template signed", nil, func(f *rtFixture) *core.Command {
			return f.command(t, "nuclei", "t1", code, rtSign(t, f.priv, rtCmdID, code))
		}, "refused"},
		{"other tool's template", nil, func(f *rtFixture) *core.Command {
			return f.command(t, "nuclei", "t1", semgrep, rtSign(t, f.priv, rtCmdID, semgrep))
		}, "not one for nuclei"},
		{"tool not opted in", nil, func(f *rtFixture) *core.Command {
			return f.command(t, "other", "t1", good, rtSign(t, f.priv, rtCmdID, good))
		}, "does not run delivered templates"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRTFixture(t, tc.policy)
			_, err := f.x.Execute(context.Background(), tc.cmd(f))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want a refusal naming %q", err, tc.want)
			}
			if f.calls != 0 {
				t.Fatalf("the tool ran %d time(s) on a refused retest", f.calls)
			}
			if tc.policy != nil {
				var pe *core.LocalPolicyError
				if !errors.As(err, &pe) {
					t.Errorf("a policy refusal is not a LocalPolicyError: %T", err)
				}
			}
		})
	}
}

// A retest without templates is unchanged, also on a tool that opted in.
func TestRetestTemplates_PlainRetestUnchanged(t *testing.T) {
	f := newRTFixture(t, nil)
	cmd := &core.Command{ID: rtCmdID, Type: RetestCommandType, Payload: json.RawMessage(`{"scanner":"nuclei","targets":["https://a.example"],
		"items":[{"ref":"f2","target":"https://a.example","kind":"finding","rule_id":"managed-id"}]}`)}
	if _, err := f.x.Execute(context.Background(), cmd); err != nil || f.calls != 1 || f.task.Retest[0].TemplatePath != "" {
		t.Fatalf("err %v, calls %d, task %+v", err, f.calls, f.task.Retest)
	}
}
