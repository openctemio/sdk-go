package core

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testSettingsDoc(version int64, digest string, values map[string]any) *SensorSettings {
	return &SensorSettings{
		Kind: SettingsDocumentKind, SensorID: "s-1", TenantID: "t-1", Version: version,
		IssuedAt: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC),
		Tools:    map[string]ToolSettingsBlock{"nuclei": {SchemaDigest: digest, Values: values}},
	}
}

func TestFileSettingsStoreRoundTripAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st := NewFileSettingsStore(dir)
	got, err := st.Load()
	if err != nil || got != nil {
		t.Fatalf("empty store: %v %v", got, err)
	}
	s := MustParseSettingsSchema(testNucleiSchema)
	if err := st.Save(testSettingsDoc(1, s.Digest(), map[string]any{"rate_limit": 50})); err != nil {
		t.Fatal(err)
	}
	got, err = st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Tools["nuclei"].SchemaDigest != s.Digest() {
		t.Fatalf("loaded %+v", got)
	}
	// Numbers survive exactly and validate against the schema.
	if rej := got.ValidateAgainst(map[string]*SettingsSchema{"nuclei": s}); len(rej) != 0 {
		t.Fatalf("rejected after round trip: %v", rej)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(st.Path())
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode %o, want 600", fi.Mode().Perm())
		}
		di, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if di.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %o, want 700", di.Mode().Perm())
		}
	}
	// No temporary files are left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries", len(entries))
	}
}

func TestFileSettingsStoreRefusesOlderOrEqualVersions(t *testing.T) {
	st := NewFileSettingsStore(t.TempDir())
	if err := st.Save(testSettingsDoc(5, "sha256:a", nil)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []int64{5, 4} {
		if err := st.Save(testSettingsDoc(v, "sha256:b", nil)); !errors.Is(err, ErrSettingsVersionNotNewer) {
			t.Fatalf("version %d: err = %v, want ErrSettingsVersionNotNewer", v, err)
		}
	}
	got, _ := st.Load()
	if got.Version != 5 || got.Tools["nuclei"].SchemaDigest != "sha256:a" {
		t.Fatalf("stored document changed: %+v", got)
	}
	if err := st.Save(testSettingsDoc(6, "sha256:c", nil)); err != nil {
		t.Fatal(err)
	}
}

func TestSensorSettingsCheck(t *testing.T) {
	cases := map[string]*SensorSettings{
		"nil":          nil,
		"kind":         {Kind: "other", Version: 1},
		"version":      {Kind: SettingsDocumentKind, Version: 0},
		"no digest":    {Kind: SettingsDocumentKind, Version: 1, Tools: map[string]ToolSettingsBlock{"x": {}}},
		"neg. version": {Kind: SettingsDocumentKind, Version: -3},
	}
	for name, d := range cases {
		if err := d.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := NewFileSettingsStore(t.TempDir()).Save(d); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
}

func TestFileSettingsStoreRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	st := NewFileSettingsStore(dir)
	if err := os.WriteFile(st.Path(), []byte(`{"kind":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil {
		t.Fatal("corrupt document loaded")
	}
	if err := os.WriteFile(st.Path(), []byte(`{"kind":"other","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("wrong kind loaded: %v", err)
	}
	big := make([]byte, MaxSettingsDocumentBytes+10)
	if err := os.WriteFile(st.Path(), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil {
		t.Fatal("oversized document loaded")
	}
}

func TestSensorSettingsValidateAgainst(t *testing.T) {
	s := MustParseSettingsSchema(testNucleiSchema)
	d := &SensorSettings{Kind: SettingsDocumentKind, Version: 2, Tools: map[string]ToolSettingsBlock{
		"nuclei":  {SchemaDigest: s.Digest(), Values: map[string]any{"rate_limit": 5000}},
		"trivy":   {SchemaDigest: "sha256:x", Values: map[string]any{}},
		"semgrep": {SchemaDigest: s.Digest(), Values: map[string]any{"rate_limit": 5}},
	}}
	schemas := map[string]*SettingsSchema{"nuclei": s, "semgrep": s}
	rej := d.ValidateAgainst(schemas)
	if len(rej) != 2 || rej["nuclei"] == nil || rej["trivy"] == nil || rej["semgrep"] != nil {
		t.Fatalf("rejections = %v", rej)
	}
	// A digest from another build of the tool is refused even when the
	// values happen to fit.
	d.Tools["semgrep"] = ToolSettingsBlock{SchemaDigest: "sha256:other", Values: map[string]any{}}
	if rej := d.ValidateAgainst(schemas); rej["semgrep"] == nil || !strings.Contains(rej["semgrep"].Error(), "schema mismatch") {
		t.Fatalf("digest mismatch accepted: %v", rej)
	}
}
