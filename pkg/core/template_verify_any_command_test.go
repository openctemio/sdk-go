package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// VerifyCustomTemplates is the one template check for every command type
// that carries templates (a scan, a retest): these tests drive it with a
// retest command.

const vtRetestType = "retest"

// signedRetestJob is a retest command carrying tpls, signed with the
// statement edited by mutate (nil: the payload's own digests).
func signedRetestJob(t *testing.T, s *jobSigner, tpls []EmbeddedTemplate, mutate func(*jobsig.Statement)) *Command {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{"https://93.184.215.14"},
		"custom_templates": tpls, "items": []map[string]string{{"ref": "f1", "target": "https://93.184.215.14", "kind": "finding", "template": "t1"}}})
	if err != nil {
		t.Fatal(err)
	}
	digests, err := jobsig.PayloadTemplateDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	env := s.sign(t, jsCmd, 1, payload, func(st *jobsig.Statement) {
		st.CommandType = vtRetestType
		st.Templates = digests
		if mutate != nil {
			mutate(st)
		}
	})
	return &Command{ID: jsCmd, Type: vtRetestType, Payload: payload, LeaseEpoch: 1, SignedJob: env}
}

func TestVerifyCustomTemplates_SignedRetestJob(t *testing.T) {
	s := newJobSigner()
	tpl := encodedTemplate("t1", "probe.yaml", sjTemplateBody)
	cmd := signedRetestJob(t, s, []EmbeddedTemplate{tpl}, nil)
	if err := templateGuard(t, s).Check(context.Background(), cmd); err != nil {
		t.Fatalf("the guard refused a signed retest with its templates: %v", err)
	}
	e := NewDefaultCommandExecutor(nil) // no template key: the statement is the trust
	got, err := e.VerifyCustomTemplates(cmd, CommandTemplates{CustomTemplates: []EmbeddedTemplate{tpl}})
	if err != nil || len(got) != 1 || string(got[0]) != sjTemplateBody {
		t.Fatalf("got %q, %v; want the decoded template", got, err)
	}
}

func TestVerifyCustomTemplates_RetestStatementMismatch(t *testing.T) {
	s := newJobSigner()
	tpl := encodedTemplate("t1", "probe.yaml", sjTemplateBody)
	// The guard refuses a statement whose digests are not the payload's.
	cmd := signedRetestJob(t, s, []EmbeddedTemplate{tpl}, func(st *jobsig.Statement) {
		st.Templates = []string{jobsig.TemplateDigest([]byte("other"))}
	})
	if err := templateGuard(t, s).Check(context.Background(), cmd); err == nil {
		t.Fatal("the guard admitted a retest whose templates are not the signed ones")
	}
	// The executor refuses templates other than the verified statement's.
	cmd.jobVerified, cmd.signedTemplates = true, []string{jobsig.TemplateDigest([]byte("other"))}
	if _, err := NewDefaultCommandExecutor(nil).VerifyCustomTemplates(cmd, CommandTemplates{CustomTemplates: []EmbeddedTemplate{tpl}}); err == nil ||
		!strings.Contains(err.Error(), "not the templates the signed job names") {
		t.Fatalf("err = %v; want a refusal", err)
	}
}

func TestVerifyCustomTemplates_UnsignedNeedsTemplateKey(t *testing.T) {
	tpl := encodedTemplate("t1", "probe.yaml", sjTemplateBody)
	cmd := &Command{ID: "cmd-r1", Type: vtRetestType}
	if _, err := NewDefaultCommandExecutor(nil).VerifyCustomTemplates(cmd, CommandTemplates{CustomTemplates: []EmbeddedTemplate{tpl}}); !errors.Is(err, ErrNoTemplateKeys) {
		t.Fatalf("err = %v; want ErrNoTemplateKeys", err)
	}
	e := NewDefaultCommandExecutor(nil)
	priv := testTemplateKey(t, e)
	e.SetSensorID("sensor-a")
	tpls := []EmbeddedTemplate{tpl}
	ok := sealManifest(t, priv, manifestFor(t, "cmd-r1", "sensor-a", tpls))
	if _, err := e.VerifyCustomTemplates(cmd, CommandTemplates{CustomTemplates: tpls, CustomTemplatesEnvelope: ok}); err != nil {
		t.Fatalf("a manifest signed for this command and sensor: %v", err)
	}
	for name, env := range map[string]*SignedEnvelope{
		"none":          nil,
		"other command": sealManifest(t, priv, manifestFor(t, "cmd-other", "sensor-a", tpls)),
		"other sensor":  sealManifest(t, priv, manifestFor(t, "cmd-r1", "sensor-b", tpls)),
	} {
		if _, err := e.VerifyCustomTemplates(cmd, CommandTemplates{CustomTemplates: tpls, CustomTemplatesEnvelope: env}); err == nil {
			t.Errorf("%s: templates admitted", name)
		}
	}
}

func TestVerifyCustomTemplates_CodeTemplateRefusedEvenSigned(t *testing.T) {
	tpl := encodedTemplate("t1", "probe.yaml", "id: probe\ninfo:\n  name: probe\n  severity: info\ncode:\n  - engine: [sh]\n    source: id\n")
	cmd := &Command{ID: "cmd-r1", Type: vtRetestType, jobVerified: true}
	c, _ := decodeTemplateContent(&tpl)
	cmd.signedTemplates = []string{jobsig.TemplateDigest(c)}
	if _, err := NewDefaultCommandExecutor(nil).VerifyCustomTemplates(cmd, CommandTemplates{CustomTemplates: []EmbeddedTemplate{tpl}}); err == nil {
		t.Fatal("a signed code template passed the content check")
	}
	if _, err := NewDefaultCommandExecutor(nil).VerifyCustomTemplates(cmd, CommandTemplates{}); err == nil {
		t.Fatal("a command without templates verified")
	}
}

func TestWriteCustomTemplates_PrivateFilesAndCleanup(t *testing.T) {
	tpls := []EmbeddedTemplate{encodedTemplate("t1", "a.yaml", sjTemplateBody), encodedTemplate("t2", "b", sjTemplateBody)}
	dir, files, cleanup, err := WriteCustomTemplates("nuclei", tpls)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")}; !slices.Equal(files, want) {
		t.Fatalf("files %v, want %v", files, want)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v, %v; want 0700", st.Mode().Perm(), err)
	}
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, %v; want 0600", f, st.Mode().Perm(), err)
		}
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the template directory outlived its cleanup: %v", err)
	}
	if _, _, _, err := WriteCustomTemplates("nuclei", []EmbeddedTemplate{encodedTemplate("t1", "../x.yaml", sjTemplateBody)}); err == nil {
		t.Fatal("a traversing template name was written")
	}
}
