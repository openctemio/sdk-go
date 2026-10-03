package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// settingsVector is one file of testdata/settings-vectors with a valid
// schema. The platform's validator runs the same files.
type settingsVector struct {
	Description  string          `json:"description"`
	Schema       json.RawMessage `json:"schema"`
	SchemaValid  bool            `json:"schema_valid"`
	SchemaDigest string          `json:"schema_digest"`
	Defaults     json.RawMessage `json:"defaults"`
	Cases        []struct {
		Description string          `json:"description"`
		Values      json.RawMessage `json:"values"`
		Valid       bool            `json:"valid"`
		ErrorPaths  []string        `json:"error_paths"`
	} `json:"cases"`
}

type invalidSchemaVectors struct {
	Cases []struct {
		Description     string          `json:"description"`
		Schema          json.RawMessage `json:"schema"`
		SchemaErrorPath string          `json:"schema_error_path"`
	} `json:"cases"`
	TextCases []struct {
		Description     string `json:"description"`
		SchemaText      string `json:"schema_text"`
		SchemaErrorPath string `json:"schema_error_path"`
	} `json:"text_cases"`
}

const settingsVectorDir = "testdata/settings-vectors"

func uniqueSorted(paths []string) []string {
	out := slices.Clone(paths)
	slices.Sort(out)
	return slices.Compact(out)
}

func TestSettingsVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(settingsVectorDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no vectors: %v", err)
	}
	for _, f := range files {
		if filepath.Base(f) == "invalid-schemas.json" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v settingsVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		t.Run(filepath.Base(f), func(t *testing.T) {
			s, err := ParseSettingsSchema(v.Schema)
			if !v.SchemaValid {
				if err == nil {
					t.Fatal("schema accepted, want refused")
				}
				return
			}
			if err != nil {
				t.Fatalf("schema refused: %v", err)
			}
			if s.Digest() != v.SchemaDigest {
				t.Errorf("digest = %s, want %s", s.Digest(), v.SchemaDigest)
			}
			wantDefaults, err := decodeSettingsJSON(v.Defaults)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Defaults(); !reflect.DeepEqual(got, wantDefaults) {
				gj, _ := json.Marshal(got)
				t.Errorf("defaults = %s, want %s", gj, v.Defaults)
			}
			for _, c := range v.Cases {
				err := s.ValidateJSON(c.Values)
				if c.Valid {
					if err != nil {
						t.Errorf("%s: %v, want valid", c.Description, err)
					}
					continue
				}
				var errs SettingsErrors
				if !errors.As(err, &errs) {
					t.Errorf("%s: err = %v, want SettingsErrors", c.Description, err)
					continue
				}
				if got := uniqueSorted(errs.Paths()); !slices.Equal(got, uniqueSorted(c.ErrorPaths)) {
					t.Errorf("%s: error paths = %q, want %q (%v)", c.Description, got, c.ErrorPaths, err)
				}
			}
		})
	}
}

func TestSettingsInvalidSchemaVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(settingsVectorDir, "invalid-schemas.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v invalidSchemaVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, desc string, schema []byte, wantPath string) {
		t.Helper()
		_, err := ParseSettingsSchema(schema)
		var se *SettingsSchemaError
		if !errors.As(err, &se) {
			t.Errorf("%s: err = %v, want a SettingsSchemaError", desc, err)
			return
		}
		if se.Path != wantPath {
			t.Errorf("%s: path = %q, want %q (%v)", desc, se.Path, wantPath, err)
		}
	}
	for _, c := range v.Cases {
		check(t, c.Description, c.Schema, c.SchemaErrorPath)
	}
	for _, c := range v.TextCases {
		check(t, c.Description, []byte(c.SchemaText), c.SchemaErrorPath)
	}
	if len(v.Cases) < 20 || len(v.TextCases) < 3 {
		t.Fatalf("vectors lost: %d cases, %d text cases", len(v.Cases), len(v.TextCases))
	}
}

const testNucleiSchema = `{
  "x-octm-schema-version": 3,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 150, "x-octm-scope": "scan"},
    "concurrency": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
    "severity": {"type": "array", "uniqueItems": true, "items": {"enum": ["low", "medium", "high", "critical"]}, "default": ["high", "critical"], "x-octm-scope": "scan"},
    "timeout": {"type": "string", "format": "duration", "default": "10s"},
    "net": {"type": "object", "additionalProperties": false, "properties": {
      "retries": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1, "x-octm-scope": "scan"}
    }}
  }
}`

func TestSettingsDigestIgnoresFormatting(t *testing.T) {
	a := MustParseSettingsSchema(testNucleiSchema)
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(testNucleiSchema)); err != nil {
		t.Fatal(err)
	}
	b := MustParseSettingsSchema(compact.String())
	if a.Digest() != b.Digest() || !strings.HasPrefix(a.Digest(), "sha256:") {
		t.Fatalf("digests %s and %s differ", a.Digest(), b.Digest())
	}
	if ms := a.ManifestSettings(); ms.SchemaVersion != 3 || ms.Digest != a.Digest() {
		t.Fatalf("manifest settings = %+v", ms)
	}
	c := MustParseSettingsSchema(strings.Replace(testNucleiSchema, `"maximum": 1000`, `"maximum": 999`, 1))
	if c.Digest() == a.Digest() {
		t.Fatal("a changed schema kept its digest")
	}
}

func TestSettingsValidateGoValues(t *testing.T) {
	s := MustParseSettingsSchema(testNucleiSchema)
	// Values built in Go (not decoded from JSON) are accepted as well.
	if err := s.Validate(map[string]any{"rate_limit": 10, "severity": []string{"high"}, "net": map[string]any{"retries": int64(2)}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(map[string]any{"rate_limit": 10.5}); err == nil {
		t.Fatal("10.5 accepted for an integer")
	}
}

func TestSettingsResolvePrecedenceAndScope(t *testing.T) {
	s := MustParseSettingsSchema(testNucleiSchema)
	ts, err := s.Resolve(
		SettingsLayer{Source: SettingSourceSensor, Values: map[string]any{"rate_limit": 100, "concurrency": 10}},
		SettingsLayer{Source: SettingSourceProfile, Values: map[string]any{"rate_limit": 50}},
		SettingsLayer{Source: SettingSourceScan, Values: map[string]any{"severity": []any{"critical"}, "net": map[string]any{"retries": 3}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	checkInt := func(key string, want int64, src SettingSource) {
		t.Helper()
		got, ok := ts.Int(key)
		if !ok || got != want || ts.Source(key) != src {
			t.Errorf("%s = %d (%v, %s), want %d from %s", key, got, ok, ts.Source(key), want, src)
		}
	}
	checkInt("rate_limit", 50, SettingSourceProfile)
	checkInt("concurrency", 10, SettingSourceSensor)
	checkInt("net.retries", 3, SettingSourceScan)
	if sev, ok := ts.Strings("severity"); !ok || !slices.Equal(sev, []string{"critical"}) || ts.Source("severity") != SettingSourceScan {
		t.Errorf("severity = %v", sev)
	}
	if d, ok := ts.Duration("timeout"); !ok || d.String() != "10s" || ts.Source("timeout") != SettingSourceDefault {
		t.Errorf("timeout = %v %v", d, ok)
	}
	if ts.SchemaDigest() != s.Digest() || ts.SchemaVersion() != 3 {
		t.Error("schema identity lost")
	}
	if _, ok := ts.Bool("rate_limit"); ok {
		t.Error("an integer read as a boolean")
	}
	if _, ok := ts.Secret("anything"); ok {
		t.Error("secrets are not delivered yet")
	}

	// A scan may not set a sensor-scope key.
	_, err = s.Resolve(SettingsLayer{Source: SettingSourceScan, Values: map[string]any{"concurrency": 99}})
	var errs SettingsErrors
	if !errors.As(err, &errs) || !slices.Equal(errs.Paths(), []string{"/concurrency"}) {
		t.Fatalf("scan set a sensor-scope key: %v", err)
	}
	// Each layer is validated on its own.
	if _, err := s.Resolve(SettingsLayer{Source: SettingSourceSensor, Values: map[string]any{"proxy": "x"}}); err == nil {
		t.Fatal("unknown key accepted in a layer")
	}
	if _, err := s.Resolve(SettingsLayer{Source: "tenant", Values: nil}); err == nil {
		t.Fatal("unknown layer source accepted")
	}
}

func TestSettingsResolveRequiredAcrossLayers(t *testing.T) {
	s := MustParseSettingsSchema(`{"x-octm-schema-version":1,"type":"object","additionalProperties":false,"required":["mode"],
	  "properties":{"mode":{"enum":["a","b"],"x-octm-scope":"scan"}}}`)
	if _, err := s.Resolve(); err == nil {
		t.Fatal("required key without a value resolved")
	}
	// The sensor layer need not repeat it when a scan sets it.
	ts, err := s.Resolve(SettingsLayer{Source: SettingSourceSensor}, SettingsLayer{Source: SettingSourceScan, Values: map[string]any{"mode": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ts.String("mode"); v != "b" {
		t.Fatalf("mode = %q", v)
	}
}

func TestToolSettingsNil(t *testing.T) {
	var ts *ToolSettings
	if _, ok := ts.Int("x"); ok {
		t.Fatal("nil settings returned a value")
	}
	if ts.Source("x") != "" || ts.Keys() != nil || ts.SchemaDigest() != "" {
		t.Fatal("nil settings not empty")
	}
	var s *SettingsSchema
	if s.Digest() != "" || s.ManifestSettings() != nil || s.Validate(nil) != nil {
		t.Fatal("nil schema not empty")
	}
	if s.Validate(map[string]any{"a": 1}) == nil {
		t.Fatal("values accepted for a tool without settings")
	}
	if ts, err := s.Resolve(); err != nil || len(ts.Keys()) != 0 {
		t.Fatalf("nil schema resolve: %v", err)
	}
}

func TestSettingsSchemaPropertyLookup(t *testing.T) {
	s := MustParseSettingsSchema(testNucleiSchema)
	if p := s.Property("net.retries"); p == nil || p.Scope != SettingScopeScan || !p.HasDefault {
		t.Fatalf("net.retries = %+v", p)
	}
	if p := s.Property("concurrency"); p == nil || p.Scope != SettingScopeSensor {
		t.Fatalf("concurrency scope = %+v", p)
	}
	if s.Property("nope") != nil || s.Property("net.nope") != nil {
		t.Fatal("unknown key found")
	}
	if names := propertyNames(s.Properties); !slices.IsSorted(names) {
		t.Fatalf("properties not sorted: %v", names)
	}
}

func propertyNames(ps []*SettingProperty) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

func TestSettingsManifestCarriesDigestNotSchema(t *testing.T) {
	s := MustParseSettingsSchema(testNucleiSchema)
	r := NewToolRegistry()
	if err := r.Register(ToolSpec{Name: "nuclei", Settings: s}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(ToolSpec{Name: "trivy"}); err != nil {
		t.Fatal(err)
	}
	rep := r.CapabilityReport(t.Context())
	status := &SensorStatus{Tools: rep.Tools, Capabilities: rep.Capabilities}
	m := BuildManifest(status, nil, "")
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `"settings":{"schema_version":3,"digest":"` + s.Digest() + `"}`
	if !strings.Contains(string(raw), want) || strings.Count(string(raw), `"settings"`) != 1 {
		t.Fatalf("manifest = %s, want one %s", raw, want)
	}
	if strings.Contains(string(raw), "rate_limit") {
		t.Fatal("the manifest carries the schema itself")
	}
	// The heartbeat's tool inventory does not carry it.
	hb, _ := json.Marshal(rep.Tools)
	if strings.Contains(string(hb), "settings") {
		t.Fatalf("heartbeat tools carry settings: %s", hb)
	}
	if r.SettingsSchema("NUCLEI") != s || r.SettingsSchema("trivy") != nil {
		t.Fatal("registry lookup")
	}
	if got := r.SettingsSchemas(); len(got) != 1 || got["nuclei"] != s {
		t.Fatalf("SettingsSchemas = %v", got)
	}
}

func FuzzParseSettingsSchema(f *testing.F) {
	f.Add([]byte(testNucleiSchema))
	f.Add([]byte(`{"x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{}}`))
	f.Add([]byte(`{"a":{"a":{"a":[1,2,{"b":"c"}]}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := ParseSettingsSchema(raw)
		if err != nil {
			return
		}
		// A parsed schema's own defaults are valid, and validation never
		// panics on its own schema text as values.
		if err := s.Validate(s.Defaults()); err != nil && !strings.Contains(err.Error(), "required") {
			t.Fatalf("defaults invalid: %v", err)
		}
		_ = s.ValidateJSON(raw)
	})
}
