package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testTemplateKey pins a fresh key on e and returns its private half.
func testTemplateKey(t *testing.T, e *DefaultCommandExecutor) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewTemplateVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	e.SetTemplateVerifier(v)
	return priv
}

// manifestFor builds the manifest the platform signs for templates.
func manifestFor(t *testing.T, cmdID, sensorID string, templates []EmbeddedTemplate) TemplateManifest {
	t.Helper()
	m := TemplateManifest{
		Kind: TemplateManifestKind, TenantID: "tenant-a", SensorID: sensorID, CommandID: cmdID,
		IssuedAt: time.Now().Add(-time.Minute).UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	for i := range templates {
		c, err := decodeTemplateContent(&templates[i])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(c)
		m.Templates = append(m.Templates, ManifestTemplate{
			ID: templates[i].ID, Name: templates[i].Name, TemplateType: templates[i].TemplateType,
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	return m
}

// sealManifest signs m the way the platform does.
func sealManifest(t *testing.T, priv ed25519.PrivateKey, m any) *SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return sealBytes(priv, payload)
}

func sealBytes(priv ed25519.PrivateKey, payload []byte) *SignedEnvelope {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &SignedEnvelope{
		PayloadType: TemplateManifestPayloadType,
		Payload:     payload,
		Signatures: []EnvelopeSignature{{
			KeyID: TemplateKeyID(pub),
			Sig:   ed25519.Sign(priv, DSSEPreAuthEncoding(TemplateManifestPayloadType, payload)),
		}},
	}
}

// The platform (api pkg/domain/scannertemplate, TestManifestEnvelopeVector)
// signs the same bytes with the same key to the same signature. A change on
// either side must change both vectors.
func TestTemplateManifestEnvelopeVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	payload := []byte(`{"kind":"openctem.template-manifest/v1","tenant_id":"t","command_id":"c","issued_at":"2026-10-03T00:00:00Z","expires_at":"2026-10-03T01:00:00Z","templates":[]}`)
	pae := DSSEPreAuthEncoding(TemplateManifestPayloadType, payload)
	if !strings.HasPrefix(string(pae), "DSSEv1 47 application/vnd.openctem.template-manifest+json 159 {") {
		t.Fatalf("PAE = %q", pae)
	}
	const wantSig = "dbNRZb9aoO+QInKMmpveKLtJjSOCbW9CV6ygkCIMxaNFxXsTMChF6eCOB3h//0BojbrjYqK/sHsc4eNa03rQBg=="
	if got := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, pae)); got != wantSig {
		t.Fatalf("signature = %s, want %s", got, wantSig)
	}
	if got := TemplateKeyID(priv.Public().(ed25519.PublicKey)); got != "65b60673d6ed884b" {
		t.Fatalf("key id = %s", got)
	}
}

func encodedTemplate(id, name, body string) EmbeddedTemplate {
	return EmbeddedTemplate{ID: id, Name: name, TemplateType: "nuclei", Content: base64.StdEncoding.EncodeToString([]byte(body))}
}

func decodeAll(t *testing.T, tpls []EmbeddedTemplate) [][]byte {
	t.Helper()
	out := make([][]byte, len(tpls))
	for i := range tpls {
		c, err := decodeTemplateContent(&tpls[i])
		if err != nil {
			t.Fatal(err)
		}
		out[i] = c
	}
	return out
}

func TestTemplateVerifier(t *testing.T) {
	e := &DefaultCommandExecutor{}
	priv := testTemplateKey(t, e)
	v := e.templates.Load()
	tpls := []EmbeddedTemplate{
		encodedTemplate("t1", "a.yaml", "id: a\n"),
		encodedTemplate("t2", "b.yaml", "id: b\n"),
	}
	bind := TemplateBinding{CommandID: "cmd-1", SensorID: "sensor-1"}
	good := sealManifest(t, priv, manifestFor(t, "cmd-1", "sensor-1", tpls))
	if _, err := v.Verify(good, bind, tpls, decodeAll(t, tpls)); err != nil {
		t.Fatalf("a signed manifest must verify: %v", err)
	}

	type mutation func(env *SignedEnvelope, b *TemplateBinding, tpls *[]EmbeddedTemplate)
	cases := map[string]mutation{
		"no envelope": func(env *SignedEnvelope, _ *TemplateBinding, _ *[]EmbeddedTemplate) { *env = SignedEnvelope{} },
		"content tampered": func(_ *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			(*tp)[0] = encodedTemplate("t1", "a.yaml", "id: a\ncode:\n  - engine: [sh]\n")
		},
		"template renamed": func(_ *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) { (*tp)[0].Name = "c.yaml" },
		"type changed":     func(_ *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) { (*tp)[0].TemplateType = "semgrep" },
		"template held back": func(_ *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			*tp = (*tp)[:1]
		},
		"template added": func(_ *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			*tp = append(*tp, encodedTemplate("t3", "x.yaml", "id: x\n"))
		},
		"templates reordered": func(_ *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			(*tp)[0], (*tp)[1] = (*tp)[1], (*tp)[0]
		},
		"other command": func(_ *SignedEnvelope, b *TemplateBinding, _ *[]EmbeddedTemplate) { b.CommandID = "cmd-2" },
		"other sensor":  func(_ *SignedEnvelope, b *TemplateBinding, _ *[]EmbeddedTemplate) { b.SensorID = "sensor-2" },
		"payload edited": func(env *SignedEnvelope, _ *TemplateBinding, _ *[]EmbeddedTemplate) {
			env.Payload = append([]byte(nil), env.Payload...)
			env.Payload[10] ^= 1
		},
		"payload type": func(env *SignedEnvelope, _ *TemplateBinding, _ *[]EmbeddedTemplate) {
			env.PayloadType = "application/json"
		},
		"garbage signature": func(env *SignedEnvelope, _ *TemplateBinding, _ *[]EmbeddedTemplate) {
			env.Signatures = []EnvelopeSignature{{KeyID: env.Signatures[0].KeyID, Sig: []byte("nope")}}
		},
		"unpinned key": func(env *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			_, other, _ := ed25519.GenerateKey(nil)
			*env = *sealManifest(t, other, manifestFor(t, "cmd-1", "sensor-1", *tp))
		},
		"expired": func(env *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			m := manifestFor(t, "cmd-1", "sensor-1", *tp)
			m.ExpiresAt = time.Now().Add(-time.Second)
			*env = *sealManifest(t, priv, m)
		},
		"no expiry": func(env *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			m := manifestFor(t, "cmd-1", "sensor-1", *tp)
			m.ExpiresAt = time.Time{}
			*env = *sealManifest(t, priv, m)
		},
		"issued in the future": func(env *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			m := manifestFor(t, "cmd-1", "sensor-1", *tp)
			m.IssuedAt = time.Now().Add(time.Hour)
			*env = *sealManifest(t, priv, m)
		},
		"wrong kind": func(env *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			m := manifestFor(t, "cmd-1", "sensor-1", *tp)
			m.Kind = "openctem.sensor.settings/v1"
			*env = *sealManifest(t, priv, m)
		},
		"unknown field": func(env *SignedEnvelope, _ *TemplateBinding, tp *[]EmbeddedTemplate) {
			m := manifestFor(t, "cmd-1", "sensor-1", *tp)
			raw, _ := json.Marshal(m)
			raw = append([]byte(`{"force":true,`), raw[1:]...)
			*env = *sealBytes(priv, raw)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			env := *good
			b := bind
			tp := append([]EmbeddedTemplate(nil), tpls...)
			mutate(&env, &b, &tp)
			if _, err := v.Verify(&env, b, tp, decodeAll(t, tp)); err == nil {
				t.Fatal("verified; want refused")
			}
		})
	}

	// A sensor that does not know its id still checks everything else.
	if _, err := v.Verify(good, TemplateBinding{CommandID: "cmd-1"}, tpls, decodeAll(t, tpls)); err != nil {
		t.Fatalf("without a sensor id: %v", err)
	}
	var none *TemplateVerifier
	if _, err := none.Verify(good, bind, tpls, decodeAll(t, tpls)); !errors.Is(err, ErrNoTemplateKeys) {
		t.Errorf("nil verifier: %v, want ErrNoTemplateKeys", err)
	}
}

func TestParseTemplateSigningKeys(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	v, err := ParseTemplateSigningKeys(base64.StdEncoding.EncodeToString(pub1) + ", " + base64.RawURLEncoding.EncodeToString(pub2))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.KeyIDs()) != 2 {
		t.Fatalf("keys = %v, want 2", v.KeyIDs())
	}
	for _, bad := range []string{"", " , ", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParseTemplateSigningKeys(bad); err == nil {
			t.Errorf("ParseTemplateSigningKeys(%q) accepted", bad)
		}
	}
}

// A scan command whose custom templates are unsigned, signed for another
// command or sensor, or changed after signing fails before any scanner runs.
func TestExecuteScanRefusesUnsignedOrTamperedTemplates(t *testing.T) {
	body := "id: probe\ninfo:\n  name: probe\n  severity: info\nhttp:\n  - path: ['{{BaseURL}}']\n"
	tpl := encodedTemplate("t1", "probe.yaml", body)
	run := func(t *testing.T, e *DefaultCommandExecutor, cmdID string, tpls []EmbeddedTemplate, env *SignedEnvelope) (*fakeScanner, error) {
		t.Helper()
		sc := &fakeScanner{name: "nuclei"}
		e.AddScanner(sc)
		payload, _ := json.Marshal(ScanCommandPayload{
			Scanner: "nuclei", Target: "https://93.184.215.14",
			CustomTemplates: tpls, CustomTemplatesEnvelope: env,
		})
		_, err := e.Execute(context.Background(), &Command{ID: cmdID, Type: "scan", Payload: payload})
		return sc, err
	}

	t.Run("no pinned key", func(t *testing.T) {
		sc, err := run(t, NewDefaultCommandExecutor(nil), "c1", []EmbeddedTemplate{tpl}, nil)
		if !errors.Is(err, ErrNoTemplateKeys) || sc.calls != 0 {
			t.Fatalf("err = %v, scans = %d; want ErrNoTemplateKeys and no scan", err, sc.calls)
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		e := NewDefaultCommandExecutor(nil)
		testTemplateKey(t, e)
		sc, err := run(t, e, "c1", []EmbeddedTemplate{tpl}, nil)
		if !errors.Is(err, ErrTemplatesUnsigned) || sc.calls != 0 {
			t.Fatalf("err = %v, scans = %d; want ErrTemplatesUnsigned and no scan", err, sc.calls)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		e := NewDefaultCommandExecutor(nil)
		priv := testTemplateKey(t, e)
		env := sealManifest(t, priv, manifestFor(t, "c1", "", []EmbeddedTemplate{tpl}))
		bad := encodedTemplate("t1", "probe.yaml", body+"code:\n  - engine: [sh]\n    source: id\n")
		sc, err := run(t, e, "c1", []EmbeddedTemplate{bad}, env)
		if err == nil || !strings.Contains(err.Error(), "does not match") || sc.calls != 0 {
			t.Fatalf("err = %v, scans = %d; want a manifest mismatch and no scan", err, sc.calls)
		}
	})
	t.Run("signed for another command", func(t *testing.T) {
		e := NewDefaultCommandExecutor(nil)
		priv := testTemplateKey(t, e)
		env := sealManifest(t, priv, manifestFor(t, "c-other", "", []EmbeddedTemplate{tpl}))
		sc, err := run(t, e, "c1", []EmbeddedTemplate{tpl}, env)
		if err == nil || sc.calls != 0 {
			t.Fatalf("err = %v, scans = %d; want refused", err, sc.calls)
		}
	})
	t.Run("signed for another sensor", func(t *testing.T) {
		e := NewDefaultCommandExecutor(nil)
		e.SetSensorID("sensor-1")
		priv := testTemplateKey(t, e)
		env := sealManifest(t, priv, manifestFor(t, "c1", "sensor-2", []EmbeddedTemplate{tpl}))
		sc, err := run(t, e, "c1", []EmbeddedTemplate{tpl}, env)
		if err == nil || sc.calls != 0 {
			t.Fatalf("err = %v, scans = %d; want refused", err, sc.calls)
		}
	})
	t.Run("signed", func(t *testing.T) {
		e := NewDefaultCommandExecutor(nil)
		e.SetSensorID("sensor-1")
		priv := testTemplateKey(t, e)
		env := sealManifest(t, priv, manifestFor(t, "c1", "sensor-1", []EmbeddedTemplate{tpl}))
		sc, err := run(t, e, "c1", []EmbeddedTemplate{tpl}, env)
		if err != nil || sc.calls != 1 || sc.opts.CustomTemplateDir == "" {
			t.Fatalf("err = %v, scans = %d, dir = %q; want one scan with the templates", err, sc.calls, sc.opts.CustomTemplateDir)
		}
	})
}

// fakeScanner records the scans it is asked to run.
type fakeScanner struct {
	name  string
	calls int
	opts  ScanOptions
}

func (f *fakeScanner) Name() string           { return f.name }
func (f *fakeScanner) Version() string        { return "test" }
func (f *fakeScanner) Capabilities() []string { return nil }
func (f *fakeScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "test", nil
}

func (f *fakeScanner) Scan(_ context.Context, _ string, opts *ScanOptions) (*ScanResult, error) {
	f.calls++
	if opts != nil {
		f.opts = *opts
	}
	return &ScanResult{ScannerName: f.name}, nil
}
