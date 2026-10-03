package core

import (
	"fmt"
	"slices"
)

// SettingsSchemaProvider is a Scanner that declares its settings schema (api
// RFC-038). The command executor resolves a scan command's config against it
// into ScanOptions.Settings, and the tool registry reports it in the
// manifest. A wrapper around a scanner should forward it.
type SettingsSchemaProvider interface {
	SettingsSchema() *SettingsSchema
}

// executorConfigKeys are the scan-command config keys the command executor
// reads itself (see executeScan); a scanner's schema never receives them.
var executorConfigKeys = map[string]bool{
	"allow_interactsh": true,
	"exclude":          true,
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
	layer := map[string]any{}
	for k, v := range config {
		if executorConfigKeys[k] {
			continue
		}
		if schema != nil && settingNameRE.MatchString(k) && schema.Property(k) != nil {
			layer[k] = v
			continue
		}
		ignored = append(ignored, ignoredKeyName(k))
	}
	ignored = boundIgnoredKeys(ignored)
	if len(layer) == 0 {
		return nil, ignored, nil
	}
	ts, err := schema.Resolve(SettingsLayer{Source: SettingSourceScan, Values: layer})
	if err != nil {
		return nil, ignored, err
	}
	return ts, ignored, nil
}

func ignoredKeyName(k string) string {
	if settingNameRE.MatchString(k) {
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
