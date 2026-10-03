package core

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// settingsTestSchema is a port scanner's schema: ports and tags may be set
// per scan, the resolver only in the sensor's own settings.
const settingsTestSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ports": {"type": "string", "maxLength": 64, "pattern": "^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$", "x-octm-scope": "scan"},
    "tags": {"type": "array", "maxItems": 4, "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"}, "x-octm-scope": "scan"},
    "retries": {"type": "integer", "minimum": 0, "maximum": 5, "x-octm-scope": "scan"},
    "resolver": {"type": "string", "format": "hostname"}
  }
}`

// settingsScanner is a recordingScanner that declares a settings schema.
type settingsScanner struct {
	recordingScanner
	schema *SettingsSchema
}

func (s *settingsScanner) SettingsSchema() *SettingsSchema { return s.schema }

func newSettingsExecutor(t *testing.T) (*DefaultCommandExecutor, *settingsScanner) {
	t.Helper()
	sc := &settingsScanner{schema: MustParseSettingsSchema(settingsTestSchema)}
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(newTestPolicy(t.TempDir()))
	return e, sc
}

// configCommand is a scan command whose config is decoded from JSON, as the
// platform's payload is (numbers arrive as float64).
func configCommand(t *testing.T, config string) *Command {
	t.Helper()
	raw := `{"scanner":"rec","target":"https://example.com","config":` + config + `}`
	if !json.Valid([]byte(raw)) {
		t.Fatalf("bad test JSON: %s", raw)
	}
	return &Command{ID: "c1", Type: "scan", Payload: json.RawMessage(raw)}
}

// The config a pipeline step sends reaches the scanner as typed settings.
// Before this, every key but allow_interactsh and exclude was dropped, so a
// step with ports "80" scanned the scanner's default ports.
func TestExecuteScan_ConfigBecomesSettings(t *testing.T) {
	e, sc := newSettingsExecutor(t)
	res, err := e.Execute(context.Background(), configCommand(t, `{"ports":"80","tags":["cve","exposure"],"retries":2,"threads":40}`))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	st := sc.options.Settings
	if st == nil {
		t.Fatal("ScanOptions.Settings is nil: the command's config was dropped")
	}
	if v, ok := st.String("ports"); !ok || v != "80" {
		t.Errorf("ports = %q, %v; want \"80\"", v, ok)
	}
	if v, ok := st.Strings("tags"); !ok || !reflect.DeepEqual(v, []string{"cve", "exposure"}) {
		t.Errorf("tags = %v, %v", v, ok)
	}
	if v, ok := st.Int("retries"); !ok || v != 2 {
		t.Errorf("retries = %d, %v", v, ok)
	}
	if st.Source("ports") != SettingSourceScan {
		t.Errorf("ports source = %q, want scan", st.Source("ports"))
	}
	// A key the scanner does not declare is reported, not silently dropped.
	if got := res.Metadata["ignored_config_keys"]; !reflect.DeepEqual(got, []string{"threads"}) {
		t.Errorf("ignored_config_keys = %v, want [threads]", got)
	}
	if got := res.Metadata["settings_applied"]; !reflect.DeepEqual(got, []string{"ports", "retries", "tags"}) {
		t.Errorf("settings_applied = %v", got)
	}
}

// A command that sets no declared key leaves Settings nil: the scanner runs
// as it always did.
func TestExecuteScan_NoDeclaredKeysNoSettings(t *testing.T) {
	for _, cfg := range []string{`null`, `{}`, `{"allow_interactsh":false,"exclude":["a"]}`, `{"rate_limit":10,"bulk_size":2,"concurrency":3}`, `{"threads":3}`} {
		e, sc := newSettingsExecutor(t)
		if _, err := e.Execute(context.Background(), configCommand(t, cfg)); err != nil {
			t.Fatalf("%s: execute: %v", cfg, err)
		}
		if sc.options.Settings != nil {
			t.Errorf("%s: Settings = %v, want nil", cfg, sc.options.Settings.Keys())
		}
	}
}

// SECURITY: config values are attacker-influenced (a malicious platform or
// tenant admin). Anything the schema does not allow fails the command before
// the scanner runs; nothing is passed on as text.
func TestExecuteScan_RefusesInvalidSettings(t *testing.T) {
	cases := map[string]string{
		"flag injection in ports":         `{"ports":"-p 1-65535 -proxy http://evil"}`,
		"flag as ports":                   `{"ports":"-"}`,
		"newline in ports":                `{"ports":"80\n-o /etc/x"}`,
		"space separated flag in tag":     `{"tags":["cve -code"]}`,
		"tag that is a flag":              `{"tags":["-code"]}`,
		"comma smuggles a second tag":     `{"tags":["cve,code"]}`,
		"wrong type":                      `{"ports":80}`,
		"out of range":                    `{"retries":99}`,
		"too many items":                  `{"tags":["a","b","c","d","e"]}`,
		"sensor-level key from a command": `{"resolver":"attacker.example"}`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			e, sc := newSettingsExecutor(t)
			_, err := e.Execute(context.Background(), configCommand(t, cfg))
			if err == nil {
				t.Fatalf("config %s accepted", cfg)
			}
			if !strings.Contains(err.Error(), "invalid rec settings") {
				t.Errorf("error = %v", err)
			}
			if sc.calls != 0 {
				t.Fatal("scanner ran with refused settings")
			}
		})
	}
}

// A scanner without a schema keeps today's behavior: no settings, and the
// keys it cannot take are reported.
func TestExecuteScan_ScannerWithoutSchema(t *testing.T) {
	sc := &recordingScanner{}
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(newTestPolicy(t.TempDir()))
	res, err := e.Execute(context.Background(), configCommand(t, `{"ports":"80","allow_interactsh":true}`))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if sc.options.Settings != nil {
		t.Error("Settings set for a scanner without a schema")
	}
	if !sc.options.AllowInteractsh {
		t.Error("allow_interactsh no longer read by the executor")
	}
	if got := res.Metadata["ignored_config_keys"]; !reflect.DeepEqual(got, []string{"ports"}) {
		t.Errorf("ignored_config_keys = %v", got)
	}
}

// The registry's schema is used for a scanner that does not declare one
// itself (a tool registered with ToolSpec.Settings).
func TestExecuteScan_SchemaFromRegistry(t *testing.T) {
	sc := &recordingScanner{}
	reg := NewToolRegistry()
	if err := reg.Register(ToolSpec{Name: "rec", Settings: MustParseSettingsSchema(settingsTestSchema)}); err != nil {
		t.Fatal(err)
	}
	e := NewDefaultCommandExecutor(nil)
	e.SetToolRegistry(reg)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(newTestPolicy(t.TempDir()))
	if _, err := e.Execute(context.Background(), configCommand(t, `{"ports":"443"}`)); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if v, _ := sc.options.Settings.String("ports"); v != "443" {
		t.Errorf("ports = %q", v)
	}
}

// RegisterScanner reports a provider's schema in the manifest.
func TestRegisterScanner_TakesProviderSchema(t *testing.T) {
	schema := MustParseSettingsSchema(settingsTestSchema)
	reg := NewToolRegistry()
	if err := reg.RegisterScanner(&settingsScanner{schema: schema}); err != nil {
		t.Fatal(err)
	}
	if reg.SettingsSchema("rec") != schema {
		t.Error("registry has no settings schema for a scanner that declares one")
	}
}

func TestBoundIgnoredKeys(t *testing.T) {
	var keys []string
	for i := 0; i < maxIgnoredConfigKeys+5; i++ {
		keys = append(keys, "k"+strings.Repeat("a", i))
	}
	got := boundIgnoredKeys(append(keys, keys[0]))
	if len(got) != maxIgnoredConfigKeys+1 || got[len(got)-1] != "<5 more>" {
		t.Errorf("bounded = %d entries, last %q", len(got), got[len(got)-1])
	}
	if got := ignoredKeyName("Bad Key\n"); got != invalidConfigKey {
		t.Errorf("ignoredKeyName = %q", got)
	}
}

// The executor's own keys (scan limits included) are neither settings nor
// reported as ignored.
func TestExecuteScan_ExecutorKeysNotIgnored(t *testing.T) {
	e, _ := newSettingsExecutor(t)
	res, err := e.Execute(context.Background(), configCommand(t, `{"rate_limit":10,"allow_interactsh":false,"exclude":["a"],"ports":"80"}`))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, ok := res.Metadata["ignored_config_keys"]; ok {
		t.Errorf("ignored_config_keys = %v", got)
	}
}
