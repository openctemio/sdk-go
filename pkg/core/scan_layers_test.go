package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// layersTestSchema declares the common options the job layer maps onto.
const layersTestSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {"type": "integer", "maximum": 5000, "default": 150, "x-octm-common": "rate", "x-octm-flag": "-rate-limit", "x-octm-scope": "scan"},
    "threads": {"type": "integer", "maximum": 200, "x-octm-common": "concurrency", "x-octm-flag": "-c", "x-octm-scope": "scan"},
    "timeout": {"type": "integer", "default": 10, "x-octm-common": "timeout", "x-octm-flag": "-timeout", "x-octm-scope": "scan"},
    "retries": {"type": "integer", "maximum": 5, "default": 1, "x-octm-common": "retries", "x-octm-scope": "scan"},
    "resolver": {"type": "string", "format": "hostname"}
  }
}`

func layersSchema() *SettingsSchema { return MustParseSettingsSchema(layersTestSchema) }

func intSetting(t *testing.T, ts *ToolSettings, key string) (int64, SettingSource) {
	t.Helper()
	v, ok := ts.Int(key)
	if !ok {
		t.Fatalf("%s not set", key)
	}
	return v, ts.Source(key)
}

func TestResolveScanSettings_AdminLayers(t *testing.T) {
	ts, _, err := resolveScanSettings(layersSchema(),
		&SettingsLayers{Tenant: map[string]any{"rate_limit": 400}, Sensor: map[string]any{"rate_limit": 300, "resolver": "dns.internal"}},
		map[string]any{"threads": float64(20)}, jobSettings{})
	if err != nil {
		t.Fatal(err)
	}
	if v, src := intSetting(t, ts, "rate_limit"); v != 300 || src != SettingSourceSensor {
		t.Fatalf("rate_limit %d from %s", v, src)
	}
	if v, src := intSetting(t, ts, "threads"); v != 20 || src != SettingSourceScan {
		t.Fatalf("threads %d from %s", v, src)
	}
	if v, _ := ts.String("resolver"); v != "dns.internal" {
		t.Fatalf("resolver %q", v)
	}
}

func TestResolveScanSettings_Refusals(t *testing.T) {
	cases := map[string]struct {
		layers *SettingsLayers
		config map[string]any
		schema *SettingsSchema
	}{
		"unknown key in the sensor layer":    {&SettingsLayers{Sensor: map[string]any{"proxy": "http://x"}}, nil, layersSchema()},
		"out of range in the tenant layer":   {&SettingsLayers{Tenant: map[string]any{"rate_limit": 999999}}, nil, layersSchema()},
		"scan raises the sensor's retries":   {&SettingsLayers{Sensor: map[string]any{"retries": 1}}, map[string]any{"retries": float64(3)}, layersSchema()},
		"scan sets a sensor-scope key":       {nil, map[string]any{"resolver": "x.example"}, layersSchema()},
		"layers for a tool without settings": {&SettingsLayers{Sensor: map[string]any{"a": 1}}, nil, nil},
	}
	for name, c := range cases {
		if _, _, err := resolveScanSettings(c.schema, c.layers, c.config, jobSettings{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The job's limits are fitted under what administrators and the scan set;
// a default is not a cap.
func TestResolveScanSettings_JobLayerFits(t *testing.T) {
	ts, _, err := resolveScanSettings(layersSchema(), &SettingsLayers{Sensor: map[string]any{"threads": 10}}, nil,
		jobSettings{rate: 1000, concurrency: 50})
	if err != nil {
		t.Fatal(err)
	}
	if v, src := intSetting(t, ts, "rate_limit"); v != 1000 || src != SettingSourceJob {
		t.Fatalf("rate above the tool default: %d from %s", v, src)
	}
	if v, _ := intSetting(t, ts, "threads"); v != 10 {
		t.Fatalf("job raised the sensor's concurrency to %d", v)
	}
}

// The per-target budget becomes the tool's per-request timeout:
// budget ÷ (retries + 1), at least 2 s, never longer than the timeout in
// force.
func TestResolveScanSettings_BudgetToTimeout(t *testing.T) {
	ts, _, err := resolveScanSettings(layersSchema(), nil, nil, jobSettings{targetBudget: 12 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if v, src := intSetting(t, ts, "timeout"); v != 6 || src != SettingSourceJob {
		t.Fatalf("timeout %d from %s, want 6 (12 s / 2)", v, src)
	}
	ts, _, _ = resolveScanSettings(layersSchema(), nil, map[string]any{"retries": float64(0)}, jobSettings{targetBudget: time.Second})
	if v, _ := intSetting(t, ts, "timeout"); v != 2 {
		t.Fatalf("floor: timeout %d", v)
	}
	// A long budget does not lengthen the tool's timeout: nothing but
	// defaults applies, so the scanner gets no settings at all.
	if ts, _, _ = resolveScanSettings(layersSchema(), nil, nil, jobSettings{targetBudget: 10 * time.Minute}); ts != nil {
		t.Fatalf("settings %v", ts.Values())
	}
	// An administrator's shorter timeout stays.
	ts, _, _ = resolveScanSettings(layersSchema(), &SettingsLayers{Sensor: map[string]any{"timeout": 3}}, nil, jobSettings{targetBudget: 20 * time.Second})
	if v, src := intSetting(t, ts, "timeout"); v != 3 || src != SettingSourceSensor {
		t.Fatalf("timeout %d from %s", v, src)
	}
}

// The local policy's rate cap lowers whatever the layers above asked.
func TestResolveScanSettings_LocalCap(t *testing.T) {
	capAt := func(n int) func(int) int {
		return func(r int) int { return min(r, n) }
	}
	ts, _, err := resolveScanSettings(layersSchema(), &SettingsLayers{Sensor: map[string]any{"rate_limit": 300}}, nil, jobSettings{capRate: capAt(50)})
	if err != nil {
		t.Fatal(err)
	}
	if v, src := intSetting(t, ts, "rate_limit"); v != 50 || src != SettingSourceLocal {
		t.Fatalf("rate_limit %d from %s", v, src)
	}
	// Under the cap: untouched (only defaults, no settings).
	if ts, _, _ = resolveScanSettings(layersSchema(), nil, nil, jobSettings{capRate: capAt(500)}); ts != nil {
		t.Fatalf("settings %v", ts.Values())
	}
}

func TestResolveScanSettings_NothingSetIsNil(t *testing.T) {
	ts, _, err := resolveScanSettings(layersSchema(), nil, map[string]any{"rate_limit_unknown": 1.0}, jobSettings{})
	if err != nil || ts != nil {
		t.Fatalf("settings %v err %v", ts, err)
	}
}

// End to end: the payload's settings layers reach the scanner and the
// result says what ran and from where.
func TestExecuteScan_SettingsLayersFromPayload(t *testing.T) {
	sc := &settingsScanner{schema: layersSchema()}
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(newTestPolicy(t.TempDir()))
	raw := `{"scanner":"rec","target":"https://example.com","config":{"rate_limit":80},
	  "settings_layers":{"sensor":{"rate_limit":200,"threads":12}}}`
	res, err := e.Execute(context.Background(), &Command{ID: "c1", Type: "scan", Payload: json.RawMessage(raw)})
	if err != nil {
		t.Fatal(err)
	}
	st := sc.options.Settings
	if v, src := intSetting(t, st, "threads"); v != 12 || src != SettingSourceSensor {
		t.Fatalf("threads %d from %s", v, src)
	}
	eff, _ := json.Marshal(res.Metadata["effective_settings"])
	if !strings.Contains(string(eff), `"threads":{"source":"sensor","value":12}`) {
		t.Fatalf("effective_settings %s", eff)
	}
	// A sensor layer the tool's schema refuses fails the command.
	bad := `{"scanner":"rec","target":"https://example.com","settings_layers":{"sensor":{"threads":100000}}}`
	if _, err := e.Execute(context.Background(), &Command{ID: "c2", Type: "scan", Payload: json.RawMessage(bad)}); err == nil {
		t.Fatal("an out-of-range sensor layer ran")
	}
}
