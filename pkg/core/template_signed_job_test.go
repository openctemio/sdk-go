package core

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// Custom templates trusted through the signed job (api RFC-040 P2): the job
// signer approves template digests in its scope ledger and names them in
// the statement, so a sensor that verified the job needs no template key.

const sjTemplateBody = "id: probe\ninfo:\n  name: probe\n  severity: info\nhttp:\n  - path: ['{{BaseURL}}']\n"

// signedTemplateJob is a verified-able command carrying tpls, signed with
// the statement edited by mutate (nil: the payload's own digests).
func signedTemplateJob(t *testing.T, s *jobSigner, tpls []EmbeddedTemplate, mutate func(*jobsig.Statement)) *Command {
	t.Helper()
	payload, err := json.Marshal(ScanCommandPayload{Scanner: "nuclei", Target: "https://93.184.215.14", CustomTemplates: tpls})
	if err != nil {
		t.Fatal(err)
	}
	digests, err := jobsig.PayloadTemplateDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	env := s.sign(t, jsCmd, 1, payload, func(st *jobsig.Statement) {
		st.Templates = digests
		if mutate != nil {
			mutate(st)
		}
	})
	return &Command{ID: jsCmd, Type: "scan", Payload: payload, LeaseEpoch: 1, SignedJob: env}
}

func templateGuard(t *testing.T, s *jobSigner) *JobGuard {
	t.Helper()
	keys, err := jobsig.NewKeys(s.pub())
	if err != nil {
		t.Fatal(err)
	}
	v, err := jobsig.NewVerifier(jobsig.Config{Keys: keys, StateFile: filepath.Join(t.TempDir(), "seq.json")})
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewJobGuard(v, true, jsTenant, jsSensor)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func runTemplateCommand(t *testing.T, e *DefaultCommandExecutor, cmd *Command) (*fakeScanner, error) {
	t.Helper()
	sc := &fakeScanner{name: "nuclei"}
	e.AddScanner(sc)
	_, err := e.Execute(context.Background(), cmd)
	return sc, err
}

func TestSignedJobTemplatesRunWithoutTemplateKeys(t *testing.T) {
	s := newJobSigner()
	cmd := signedTemplateJob(t, s, []EmbeddedTemplate{encodedTemplate("t1", "probe.yaml", sjTemplateBody)}, nil)
	if err := templateGuard(t, s).Check(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	e := NewDefaultCommandExecutor(nil) // no SENSOR_TEMPLATE_SIGNING_KEYS
	sc, err := runTemplateCommand(t, e, cmd)
	if err != nil || sc.calls != 1 || sc.opts.CustomTemplateDir == "" {
		t.Fatalf("err = %v, scans = %d, dir = %q; want one scan with the templates", err, sc.calls, sc.opts.CustomTemplateDir)
	}
}

func TestSignedJobTemplatesRefusedWhenTheyDifferFromTheStatement(t *testing.T) {
	tpl := encodedTemplate("t1", "probe.yaml", sjTemplateBody)
	other := encodedTemplate("t2", "other.yaml", sjTemplateBody+"# x\n")
	cases := map[string]func(*jobsig.Statement){
		"one byte differs": func(st *jobsig.Statement) {
			st.Templates = []string{jobsig.TemplateDigest([]byte(sjTemplateBody + " "))}
		},
		"omitted": func(st *jobsig.Statement) { st.Templates = nil },
		"extra":   func(st *jobsig.Statement) { st.Templates = append(st.Templates, st.Templates[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := newJobSigner()
			cmd := signedTemplateJob(t, s, []EmbeddedTemplate{tpl}, mutate)
			err := templateGuard(t, s).Check(context.Background(), cmd)
			var lpe *LocalPolicyError
			if !errors.As(err, &lpe) || lpe.Rule != RefusalRuleJobSignature || !strings.Contains(err.Error(), "custom template") {
				t.Fatalf("Check = %v, want a job_signature refusal on the templates", err)
			}
			if cmd.jobVerified {
				t.Fatal("a refused job was marked verified")
			}
		})
	}

	// The executor compares again: templates swapped after the check are
	// refused, even with the job marked verified.
	s := newJobSigner()
	cmd := signedTemplateJob(t, s, []EmbeddedTemplate{tpl}, nil)
	if err := templateGuard(t, s).Check(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	swapped, _ := json.Marshal(ScanCommandPayload{Scanner: "nuclei", Target: "https://93.184.215.14", CustomTemplates: []EmbeddedTemplate{other}})
	cmd.Payload = swapped
	sc, err := runTemplateCommand(t, NewDefaultCommandExecutor(nil), cmd)
	if err == nil || sc.calls != 0 || !strings.Contains(err.Error(), "signed job") {
		t.Fatalf("err = %v, scans = %d; want refused", err, sc.calls)
	}
}

func TestUnsignedTemplatesStillNeedATemplateKey(t *testing.T) {
	payload, _ := json.Marshal(ScanCommandPayload{Scanner: "nuclei", Target: "https://93.184.215.14",
		CustomTemplates: []EmbeddedTemplate{encodedTemplate("t1", "probe.yaml", sjTemplateBody)}})
	sc, err := runTemplateCommand(t, NewDefaultCommandExecutor(nil), &Command{ID: jsCmd, Type: "scan", Payload: payload})
	if !errors.Is(err, ErrNoTemplateKeys) || sc.calls != 0 {
		t.Fatalf("err = %v, scans = %d; want ErrNoTemplateKeys", err, sc.calls)
	}
}

func TestForgedVerificationFieldsInJSONAreIgnored(t *testing.T) {
	payload, _ := json.Marshal(ScanCommandPayload{Scanner: "nuclei", Target: "https://93.184.215.14",
		CustomTemplates: []EmbeddedTemplate{encodedTemplate("t1", "probe.yaml", sjTemplateBody)}})
	digest := jobsig.TemplateDigest([]byte(sjTemplateBody))
	raw, _ := json.Marshal(map[string]any{"id": jsCmd, "type": "scan", "payload": json.RawMessage(payload),
		"jobVerified": true, "job_verified": true, "signedTemplates": []string{digest}, "signed_templates": []string{digest}})
	var cmd Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.jobVerified || cmd.signedTemplates != nil {
		t.Fatal("the platform's JSON set the verification fields")
	}
	sc, err := runTemplateCommand(t, NewDefaultCommandExecutor(nil), &cmd)
	if !errors.Is(err, ErrNoTemplateKeys) || sc.calls != 0 {
		t.Fatalf("err = %v, scans = %d; want ErrNoTemplateKeys", err, sc.calls)
	}
}

func TestSignedJobTemplatesStillNeedTheLocalOptIn(t *testing.T) {
	lp, err := ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\nallow_custom_templates: false\n"),
		LocalPolicyOptions{LookupEnv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	s := newJobSigner()
	cmd := signedTemplateJob(t, s, []EmbeddedTemplate{encodedTemplate("t1", "probe.yaml", sjTemplateBody)}, nil)
	if err := templateGuard(t, s).Check(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	e := NewDefaultCommandExecutor(nil)
	e.SetLocalPolicy(lp)
	sc, err := runTemplateCommand(t, e, cmd)
	if err == nil || sc.calls != 0 || !strings.Contains(err.Error(), "allow_custom_templates") {
		t.Fatalf("err = %v, scans = %d; want the local policy refusal", err, sc.calls)
	}
}
