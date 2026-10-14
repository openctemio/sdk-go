package core

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/openctemio/ctis/tooloption"
)

// SettingsSchemaProvider is a Scanner that declares its settings schema (api
// RFC-038). The command executor resolves a scan command's config against it
// into ScanOptions.Settings, and the tool registry reports it in the
// manifest. A wrapper around a scanner should forward it.
type SettingsSchemaProvider interface {
	SettingsSchema() *SettingsSchema
}

// executorConfigKeys are the scan-command config keys the command executor
// reads itself (see executeScan), besides ScanLimitKeys; a scanner's schema
// never receives them.
var executorConfigKeys = map[string]bool{
	"allow_interactsh": true,
	"exclude":          true,
}

// isExecutorConfigKey reports whether the executor reads key itself.
func isExecutorConfigKey(key string) bool {
	return executorConfigKeys[key] || slices.Contains(ScanLimitKeys, key)
}

// maxIgnoredConfigKeys bounds how many ignored keys a result names.
const maxIgnoredConfigKeys = 32

// invalidConfigKey stands for an ignored key that is not a setting name
// (keys come from the platform; they are reported, so they are not echoed
// verbatim).
const invalidConfigKey = "<invalid key>"

// scanSettings resolves the scan-command config keys that the scanner's
// schema declares into the scan's settings, at scan level (so only keys
// whose x-octm-scope is "scan" may be set; sensor-level keys are refused).
//
// The values are checked against the schema: a wrong type, a value out of
// range or a pattern mismatch fails the command instead of being dropped, so
// a setting the platform asked for is never silently not applied. Keys the
// schema does not declare (and the executor does not read) are returned in
// ignored, so the result can say they had no effect.
//
// settings is nil when the command sets no declared key: the scanner then
// runs exactly as without settings.
func scanSettings(schema *SettingsSchema, config map[string]any) (settings *ToolSettings, ignored []string, err error) {
	return resolveScanSettings(schema, nil, config, jobSettings{})
}

func ignoredKeyName(k string) string {
	if isSettingName(k) {
		return k
	}
	return invalidConfigKey
}

func boundIgnoredKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	if len(keys) > maxIgnoredConfigKeys {
		more := len(keys) - maxIgnoredConfigKeys
		keys = append(keys[:maxIgnoredConfigKeys], fmt.Sprintf("<%d more>", more))
	}
	return keys
}

// scannerSettingsSchema is the settings schema of the scanner a command
// runs: its own (SettingsSchemaProvider), else the one registered for its
// name in the tool registry; nil when it has none.
func (e *DefaultCommandExecutor) scannerSettingsSchema(name string, s Scanner) *SettingsSchema {
	if p, ok := s.(SettingsSchemaProvider); ok {
		if schema := p.SettingsSchema(); schema != nil {
			return schema
		}
	}
	if e.tools != nil {
		return e.tools.SettingsSchema(name)
	}
	return nil
}

// SettingsLayers are the administrators' layers of a scan command's tool
// settings: the tenant's policy and the sensor's configuration, set on the
// platform and carried in the command payload (covered by the job
// signature). Each is checked against the tool's own schema here, like the
// scan's config.
type SettingsLayers struct {
	Tenant map[string]any `json:"tenant,omitempty"`
	Sensor map[string]any `json:"sensor,omitempty"`
}

// jobSettings is what the executor knows about one job besides its config:
// the platform's limits and per-target budget, and the local policy's rate
// cap. They reach the tool through its common options (x-octm-common).
type jobSettings struct {
	rate        int
	concurrency int
	// targetBudget is the platform's per-target budget (0: none).
	targetBudget time.Duration
	// capRate is the local policy's rate cap (nil: none).
	capRate func(int) int
}

// minRequestTimeout is the shortest per-request timeout a budget maps to.
const minRequestTimeout = 2 * time.Second

// resolveScanSettings resolves a scan command's settings for a tool with
// schema, layer by layer: the tool's defaults, the tenant's and the
// sensor's layers, the scan's config (declared keys only), the job's
// decision mapped onto the tool's common options, and the local policy's
// caps. A layer that is invalid, sets a key it may not, or raises a value
// an earlier layer narrowed fails the command; nothing is silently dropped.
//
// The job layer is the platform's per-job decision, so it is fitted, not
// refused: its rate and concurrency never exceed the value in force (the
// tool's default or what an administrator set),
// and the per-request timeout derived from the per-target budget
// (budget ÷ (retries + 1), at least 2 s) only ever shortens the timeout.
// The local layer lowers the common rate to the local policy's cap.
//
// settings is nil when nothing but defaults applies: the scanner then runs
// exactly as without settings.
func resolveScanSettings(schema *SettingsSchema, layers *SettingsLayers, config map[string]any, job jobSettings) (settings *ToolSettings, ignored []string, err error) {
	var upper []SettingsLayer
	if layers != nil {
		if len(layers.Tenant) > 0 {
			upper = append(upper, SettingsLayer{Source: SettingSourceTenant, Values: layers.Tenant})
		}
		if len(layers.Sensor) > 0 {
			upper = append(upper, SettingsLayer{Source: SettingSourceSensor, Values: layers.Sensor})
		}
	}
	scanLayer := map[string]any{}
	for k, v := range config {
		if isExecutorConfigKey(k) {
			continue
		}
		if schema != nil && isSettingName(k) && schema.Property(k) != nil {
			scanLayer[k] = v
			continue
		}
		ignored = append(ignored, ignoredKeyName(k))
	}
	ignored = boundIgnoredKeys(ignored)
	if schema == nil {
		if len(upper) > 0 {
			return nil, ignored, SettingsErrors{{Path: "", Message: "the tool has no settings"}}
		}
		return nil, ignored, nil
	}
	if len(scanLayer) > 0 {
		upper = append(upper, SettingsLayer{Source: SettingSourceScan, Values: scanLayer})
	}
	base, err := schema.Resolve(upper...)
	if err != nil {
		return nil, ignored, err
	}
	jobLayer, localLayer := fitJobLayers(schema, base, job)
	all := upper
	if len(jobLayer) > 0 {
		all = append(all, SettingsLayer{Source: SettingSourceJob, Values: jobLayer})
	}
	if len(localLayer) > 0 {
		all = append(all, SettingsLayer{Source: SettingSourceLocal, Values: localLayer})
	}
	if len(all) == 0 {
		return nil, ignored, nil
	}
	ts, err := schema.Resolve(all...)
	if err != nil {
		return nil, ignored, err
	}
	return ts, ignored, nil
}

// fitJobLayers maps the job's decision and the local policy's caps onto the
// tool's common options, fitted under what base (the earlier layers)
// already has.
func fitJobLayers(schema *SettingsSchema, base *ToolSettings, job jobSettings) (jobLayer, localLayer map[string]any) {
	jobLayer, localLayer = map[string]any{}, map[string]any{}
	keyOf := map[string]*SettingProperty{}
	for _, p := range schema.Properties {
		if p.Common != "" {
			keyOf[p.Common] = p
		}
	}
	// current returns the effective value of a common option and whether an
	// administrator or the scan set it (a default is not a cap).
	current := func(p *SettingProperty) (int64, bool, bool) {
		v, ok := base.Int(p.Name)
		return v, ok, ok && base.Source(p.Name) != SettingSourceDefault
	}
	fit := func(option string, want int64) {
		p := keyOf[option]
		if p == nil || p.Scope != SettingScopeScan || want <= 0 {
			return
		}
		// Never above the value in force (an administrator raises it, not
		// the job), the tool's default included.
		if cur, ok, _ := current(p); ok {
			if want >= cur {
				return
			}
		}
		jobLayer[p.Name] = clampToProperty(p, want)
	}
	fit("rate", int64(job.rate))
	fit("concurrency", int64(job.concurrency))
	if p := keyOf["timeout"]; p != nil && p.Scope == SettingScopeScan && job.targetBudget > 0 {
		var retries int64
		if rp := keyOf["retries"]; rp != nil {
			retries, _ = base.Int(rp.Name)
		}
		derived := job.targetBudget / time.Duration(retries+1)
		derived = max(derived, minRequestTimeout)
		secs := int64(math.Ceil(derived.Seconds()))
		if cur, ok, _ := current(p); !ok || secs < cur {
			jobLayer[p.Name] = clampToProperty(p, secs)
		}
	}
	if p := keyOf["rate"]; p != nil && job.capRate != nil {
		eff, ok := jobLayer[p.Name].(int64)
		if !ok {
			eff, _ = base.Int(p.Name)
		}
		if eff > 0 {
			if capped := int64(job.capRate(int(eff))); capped > 0 && capped < eff {
				localLayer[p.Name] = clampToProperty(p, capped)
			}
		}
	}
	return jobLayer, localLayer
}

// clampToProperty keeps v inside the property's bounds (the common bounds
// at least, set when the schema was parsed).
func clampToProperty(p *SettingProperty, v int64) int64 {
	if p.Minimum != nil && float64(v) < *p.Minimum {
		v = int64(math.Ceil(*p.Minimum))
	}
	if p.Maximum != nil && float64(v) > *p.Maximum {
		v = int64(math.Floor(*p.Maximum))
	}
	if o, ok := tooloption.Lookup(p.Common); ok && !o.InBounds(float64(v)) {
		v = min(max(v, o.Minimum), o.Maximum)
	}
	return v
}

// effectiveSettings is what a result says the tool ran with: every key
// with its value and the layer that set it.
func effectiveSettings(ts *ToolSettings) map[string]any {
	if ts == nil {
		return nil
	}
	values := ts.Values()
	out := make(map[string]any, len(values))
	for _, k := range ts.Keys() {
		out[k] = map[string]any{"value": values[k], "source": string(ts.Source(k))}
	}
	return out
}
