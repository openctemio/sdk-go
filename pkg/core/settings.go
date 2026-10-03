package core

// Tool settings: what a tool lets an administrator configure, declared as a
// small JSON Schema, and the values that come back from the platform. See
// api RFC-038 (docs/rfcs/RFC-038-sensor-tool-settings.md).
//
// A tool declares a SettingsSchema (ToolSpec.Settings). The manifest carries
// only the schema's version and digest (ManifestTool.Settings); the platform
// validates what an administrator enters against the same schema, and the
// sensor validates it again before a scan uses it. Values reach a tool as
// typed ToolSettings (ScanOptions.Settings), never as command-line text: the
// tool's adapter maps each typed value to a specific flag.
//
// The schema language is a closed subset of JSON Schema 2020-12 plus x-octm-*
// annotations. Anything outside the subset makes the schema invalid, so a
// schema cannot hide a field behind $ref, oneOf or a conditional, and the
// platform's and the sensor's validators cannot disagree.
//
// Shared test vectors. The platform keeps its own copy of this validator (it
// does not import the SDK). Both copies must give the same verdicts, error
// paths, defaults and digests for every file in
// pkg/core/testdata/settings-vectors; the platform copies that directory byte
// for byte. Change a vector only together with both validators.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Limits of a settings schema.
const (
	// MaxSettingsSchemaBytes bounds a schema document.
	MaxSettingsSchemaBytes = 32 << 10
	// MaxSettingsProperties bounds the properties of a schema, nested ones
	// included.
	MaxSettingsProperties = 64
	// MaxSettingsEnum bounds an enum.
	MaxSettingsEnum = 256
	// MaxSettingsPatternLen bounds a pattern's length.
	MaxSettingsPatternLen = 512
	// MaxSettingsStringLen bounds any string value (a maxLength, when set,
	// may only lower it).
	MaxSettingsStringLen = 4096
	// MaxSettingsItems bounds any array value (a maxItems, when set, may
	// only lower it).
	MaxSettingsItems = 256
)

// SettingScope is the lowest level allowed to set a key.
type SettingScope string

// Setting scopes (x-octm-scope).
const (
	// SettingScopeSensor: only the sensor's own settings may set the key
	// (the default).
	SettingScopeSensor SettingScope = "sensor"
	// SettingScopeScan: the sensor's settings, a scan profile and a scan may
	// set the key.
	SettingScopeScan SettingScope = "scan"
)

// SettingSource is where an effective value came from.
type SettingSource string

// Setting sources, from lowest to highest precedence.
const (
	SettingSourceDefault SettingSource = "default"
	SettingSourceSensor  SettingSource = "sensor"
	SettingSourceProfile SettingSource = "profile"
	SettingSourceScan    SettingSource = "scan"
)

// Setting types.
const (
	settingTypeBoolean = "boolean"
	settingTypeInteger = "integer"
	settingTypeNumber  = "number"
	settingTypeString  = "string"
	settingTypeArray   = "array"
	settingTypeObject  = "object"
)

var (
	settingNameRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	settingFormats = map[string]bool{"hostname": true, "uri": true, "duration": true}
	settingWidgets = map[string]bool{"slider": true, "textarea": true, "tags": true}
	settingTiers   = map[string]bool{"T0": true, "T1": true, "T2": true}
	hostnameRE     = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)
)

// Keywords a property may carry (the root additionally allows $schema and
// x-octm-schema-version).
var settingKeywords = map[string]bool{
	"title": true, "description": true, "type": true, "enum": true, "const": true,
	"default": true, "minimum": true, "maximum": true, "exclusiveMinimum": true,
	"exclusiveMaximum": true, "multipleOf": true, "minLength": true, "maxLength": true,
	"pattern": true, "format": true, "items": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "properties": true, "required": true, "additionalProperties": true,
	"deprecated": true, "writeOnly": true, "examples": true,
	"x-octm-scope": true, "x-octm-tier": true, "x-octm-sensitive": true, "x-octm-restart": true,
	"x-octm-group": true, "x-octm-order": true, "x-octm-widget": true,
}

// SettingsSchemaError is why a schema is invalid. Path is a JSON pointer
// into the schema document.
type SettingsSchemaError struct {
	Path    string
	Message string
}

func (e *SettingsSchemaError) Error() string {
	return "settings schema " + e.Path + ": " + e.Message
}

// SettingsError is one invalid value. Path is a JSON pointer into the values
// document ("/rate_limit", "/group/key", "/tags/2").
type SettingsError struct {
	Path    string
	Message string
}

// SettingsErrors is every problem of a values document, sorted by path.
type SettingsErrors []SettingsError

func (e SettingsErrors) Error() string {
	parts := make([]string, len(e))
	for i, x := range e {
		parts[i] = x.Path + ": " + x.Message
	}
	return "invalid settings: " + strings.Join(parts, "; ")
}

// Paths returns the error paths.
func (e SettingsErrors) Paths() []string {
	out := make([]string, len(e))
	for i, x := range e {
		out[i] = x.Path
	}
	return out
}

// SettingProperty is one key of a schema.
type SettingProperty struct {
	Name        string
	Title       string
	Description string
	// Type is "boolean", "integer", "number", "string", "array" or
	// "object" (a group of keys, one level deep); empty for a key that only
	// has enum or const.
	Type string
	// Items describes an array's elements.
	Items *SettingProperty
	// Properties are a group's keys, sorted by name.
	Properties []*SettingProperty
	Required   []string
	Enum       []any
	Const      any
	HasConst   bool
	Default    any
	HasDefault bool

	Minimum, Maximum                   *float64
	ExclusiveMinimum, ExclusiveMaximum *float64
	MultipleOf                         *float64
	MinLength, MaxLength               *int
	MinItems, MaxItems                 *int
	UniqueItems                        bool
	Pattern                            string
	Format                             string

	Deprecated bool
	WriteOnly  bool
	Scope      SettingScope
	// Tier is the minimum tier whose policy permits a non-default value
	// ("T0", "T1", "T2"); empty: any tier.
	Tier      string
	Sensitive bool
	Restart   bool
	Group     string
	Order     int
	Widget    string

	pattern *regexp.Regexp
}

// SettingsSchema is a tool's parsed settings schema.
type SettingsSchema struct {
	// Raw is the schema document as declared.
	Raw json.RawMessage
	// Version is x-octm-schema-version: it increases when a key is removed
	// or narrowed.
	Version int
	// Title and Description describe the tool's settings.
	Title       string
	Description string
	// Properties are the top-level keys, sorted by name.
	Properties []*SettingProperty
	// Required are the keys that must have a value (given or default).
	Required []string

	digest string
}

// ParseSettingsSchema parses and checks a schema: the allowed keywords
// only, additionalProperties false on every object, one level of grouping,
// defaults and enums that satisfy their own constraints, RE2 patterns, and
// the size limits.
func ParseSettingsSchema(raw []byte) (*SettingsSchema, error) {
	if len(raw) > MaxSettingsSchemaBytes {
		return nil, &SettingsSchemaError{Path: "", Message: fmt.Sprintf("larger than %d bytes", MaxSettingsSchemaBytes)}
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	root, err := decodeSettingsJSON(raw)
	if err != nil {
		return nil, &SettingsSchemaError{Path: "", Message: "not JSON: " + err.Error()}
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, &SettingsSchemaError{Path: "", Message: "not an object"}
	}
	for _, k := range settingKeys(obj) {
		if k == "$schema" || k == "x-octm-schema-version" {
			continue
		}
		if !settingKeywords[k] {
			return nil, &SettingsSchemaError{Path: pointer("", k), Message: "keyword not allowed"}
		}
	}
	if s, ok := obj["$schema"]; ok {
		if v, isStr := s.(string); !isStr || v != "https://json-schema.org/draft/2020-12/schema" {
			return nil, &SettingsSchemaError{Path: "/$schema", Message: "must be the JSON Schema 2020-12 URI"}
		}
	}
	version, err := intKeyword(obj, "", "x-octm-schema-version")
	if err != nil {
		return nil, err
	}
	if version == nil || *version < 1 {
		return nil, &SettingsSchemaError{Path: "/x-octm-schema-version", Message: "required, an integer of at least 1"}
	}
	if t, _ := obj["type"].(string); t != settingTypeObject {
		return nil, &SettingsSchemaError{Path: "/type", Message: `the root must be of type "object"`}
	}
	for _, k := range []string{"x-octm-scope", "x-octm-tier", "x-octm-sensitive", "x-octm-restart",
		"x-octm-group", "x-octm-order", "x-octm-widget", "enum", "const", "default", "items",
		"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength",
		"maxLength", "pattern", "format", "minItems", "maxItems", "uniqueItems", "writeOnly"} {
		if _, ok := obj[k]; ok {
			return nil, &SettingsSchemaError{Path: pointer("", k), Message: "not allowed on the root object"}
		}
	}
	count := 0
	group, err := parseSettingProperty(obj, "", "", 0, &count)
	if err != nil {
		return nil, err
	}
	digest, err := canonicalDigest(root)
	if err != nil {
		return nil, &SettingsSchemaError{Path: "", Message: err.Error()}
	}
	return &SettingsSchema{
		Raw:         json.RawMessage(slices.Clone(raw)),
		Version:     *version,
		Title:       group.Title,
		Description: group.Description,
		Properties:  group.Properties,
		Required:    group.Required,
		digest:      digest,
	}, nil
}

// MustParseSettingsSchema is ParseSettingsSchema for a schema compiled into
// the program; it panics on an invalid one (a programming error).
func MustParseSettingsSchema(raw string) *SettingsSchema {
	s, err := ParseSettingsSchema([]byte(raw))
	if err != nil {
		panic(err)
	}
	return s
}

// Digest is "sha256:" + the hex SHA-256 of the schema's canonical JSON
// (object members sorted, no insignificant whitespace, numbers as written,
// no HTML escaping). The manifest carries it; the platform stores schemas by
// it.
func (s *SettingsSchema) Digest() string {
	if s == nil {
		return ""
	}
	return s.digest
}

// Property returns a key by its path ("rate_limit", "group.key"), or nil.
func (s *SettingsSchema) Property(path string) *SettingProperty {
	if s == nil {
		return nil
	}
	name, rest, nested := strings.Cut(path, ".")
	for _, p := range s.Properties {
		if p.Name != name {
			continue
		}
		if !nested {
			return p
		}
		for _, c := range p.Properties {
			if c.Name == rest {
				return c
			}
		}
	}
	return nil
}

// ManifestSettings is what the manifest carries for the schema.
func (s *SettingsSchema) ManifestSettings() *ManifestToolSettings {
	if s == nil {
		return nil
	}
	return &ManifestToolSettings{SchemaVersion: s.Version, Digest: s.digest}
}

// Validate checks a values document: every key known, every value of the
// right type and within its constraints, sensitive keys absent (secrets
// never travel as plain values), and every required key given or
// defaulted. The error is SettingsErrors with every problem.
func (s *SettingsSchema) Validate(values map[string]any) error {
	if s == nil {
		if len(values) == 0 {
			return nil
		}
		return SettingsErrors{{Path: "", Message: "the tool has no settings"}}
	}
	return s.validate(normalizeSettings(values), true)
}

func (s *SettingsSchema) validate(values map[string]any, checkRequired bool) error {
	var errs SettingsErrors
	validateGroup(s.Properties, s.Required, values, "", checkRequired, &errs)
	if len(errs) == 0 {
		return nil
	}
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Path < errs[j].Path })
	return errs
}

// ValidateJSON is Validate for a JSON object (numbers kept exact).
func (s *SettingsSchema) ValidateJSON(raw []byte) error {
	v, err := decodeSettingsJSON(raw)
	if err != nil {
		return SettingsErrors{{Path: "", Message: "not JSON: " + err.Error()}}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return SettingsErrors{{Path: "", Message: "not an object"}}
	}
	return s.Validate(m)
}

// Defaults returns every key that has a default, groups as nested objects.
// The map is the caller's.
func (s *SettingsSchema) Defaults() map[string]any {
	out := map[string]any{}
	if s == nil {
		return out
	}
	for _, p := range s.Properties {
		if p.Type == settingTypeObject {
			sub := map[string]any{}
			for _, c := range p.Properties {
				if c.HasDefault {
					sub[c.Name] = cloneSettingValue(c.Default)
				}
			}
			if len(sub) > 0 {
				out[p.Name] = sub
			}
			continue
		}
		if p.HasDefault {
			out[p.Name] = cloneSettingValue(p.Default)
		}
	}
	return out
}

// SettingsLayer is one level of values, applied over the ones below it.
type SettingsLayer struct {
	Source SettingSource
	Values map[string]any
}

// Resolve computes the effective settings: the defaults, then each layer in
// order (sensor, then profile, then scan). Each layer must be valid on its
// own, and a profile or scan layer may set only keys whose scope is "scan".
// A nil schema gives empty settings (the tool's own defaults).
func (s *SettingsSchema) Resolve(layers ...SettingsLayer) (*ToolSettings, error) {
	ts := &ToolSettings{values: map[string]any{}, sources: map[string]SettingSource{}}
	if s == nil {
		for _, l := range layers {
			if len(l.Values) > 0 {
				return nil, SettingsErrors{{Path: "", Message: "the tool has no settings"}}
			}
		}
		return ts, nil
	}
	ts.digest, ts.version = s.digest, s.Version
	for k, v := range flattenSettings(s.Defaults()) {
		ts.values[k], ts.sources[k] = v, SettingSourceDefault
	}
	for _, l := range layers {
		switch l.Source {
		case SettingSourceSensor, SettingSourceProfile, SettingSourceScan:
		default:
			return nil, fmt.Errorf("settings layer: unknown source %q", l.Source)
		}
		values := normalizeSettings(l.Values)
		if err := s.validate(values, false); err != nil {
			return nil, err
		}
		var errs SettingsErrors
		for k, v := range flattenSettings(values) {
			if l.Source != SettingSourceSensor {
				if p := s.Property(k); p == nil || p.Scope != SettingScopeScan {
					errs = append(errs, SettingsError{Path: "/" + strings.ReplaceAll(k, ".", "/"),
						Message: fmt.Sprintf("may be set only in the sensor's settings, not by a %s", l.Source)})
					continue
				}
			}
			ts.values[k], ts.sources[k] = cloneSettingValue(v), l.Source
		}
		if len(errs) > 0 {
			sort.SliceStable(errs, func(i, j int) bool { return errs[i].Path < errs[j].Path })
			return nil, errs
		}
	}
	var missing SettingsErrors
	checkRequiredFlat(s.Properties, s.Required, "", ts.values, &missing)
	if len(missing) > 0 {
		sort.SliceStable(missing, func(i, j int) bool { return missing[i].Path < missing[j].Path })
		return nil, missing
	}
	return ts, nil
}

func checkRequiredFlat(props []*SettingProperty, required []string, prefix string, values map[string]any, errs *SettingsErrors) {
	for _, r := range required {
		if _, ok := values[prefix+r]; !ok {
			if p := findProperty(props, r); p != nil && p.Type != settingTypeObject {
				*errs = append(*errs, SettingsError{Path: "/" + strings.ReplaceAll(prefix+r, ".", "/"), Message: "required"})
			}
		}
	}
	for _, p := range props {
		if p.Type == settingTypeObject {
			checkRequiredFlat(p.Properties, p.Required, p.Name+".", values, errs)
		}
	}
}

// ToolSettings are a tool's effective settings for one scan. A nil
// *ToolSettings has no values: every getter reports false and the tool uses
// its own defaults. Keys of a group are addressed as "group.key".
type ToolSettings struct {
	values  map[string]any
	sources map[string]SettingSource
	digest  string
	version int
}

// Int returns an integer value.
func (t *ToolSettings) Int(key string) (int64, bool) {
	v, ok := t.get(key)
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		f, ferr := n.Float64()
		if ferr != nil || f != math.Trunc(f) || f > math.MaxInt64 || f < math.MinInt64 {
			return 0, false
		}
		return int64(f), true
	}
	return i, true
}

// Float returns a number (or integer) value.
func (t *ToolSettings) Float(key string) (float64, bool) {
	v, ok := t.get(key)
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// Bool returns a boolean value.
func (t *ToolSettings) Bool(key string) (bool, bool) {
	v, ok := t.get(key)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// String returns a string value.
func (t *ToolSettings) String(key string) (string, bool) {
	v, ok := t.get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Duration returns a string value of format "duration" as a time.Duration.
func (t *ToolSettings) Duration(key string) (time.Duration, bool) {
	s, ok := t.String(key)
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	return d, err == nil
}

// Strings returns an array of strings (a copy).
func (t *ToolSettings) Strings(key string) ([]string, bool) {
	v, ok := t.get(key)
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// Secret returns a sensitive value. Secret settings are not delivered yet,
// so it always reports false; a tool that asks for one keeps working when
// they are.
func (t *ToolSettings) Secret(string) ([]byte, bool) { return nil, false }

// Source returns where a key's value came from; empty when it has none.
func (t *ToolSettings) Source(key string) SettingSource {
	if t == nil {
		return ""
	}
	return t.sources[key]
}

// Keys returns the keys that have a value, sorted.
func (t *ToolSettings) Keys() []string {
	if t == nil {
		return nil
	}
	return settingKeys(t.values)
}

// SchemaDigest and SchemaVersion identify the schema the settings were
// resolved against.
func (t *ToolSettings) SchemaDigest() string {
	if t == nil {
		return ""
	}
	return t.digest
}

// SchemaVersion is the schema's x-octm-schema-version.
func (t *ToolSettings) SchemaVersion() int {
	if t == nil {
		return 0
	}
	return t.version
}

func (t *ToolSettings) get(key string) (any, bool) {
	if t == nil {
		return nil, false
	}
	v, ok := t.values[key]
	return v, ok
}

// --- parsing ---------------------------------------------------------------

func parseSettingProperty(obj map[string]any, path, name string, depth int, count *int) (*SettingProperty, error) {
	p := &SettingProperty{Name: name, Scope: SettingScopeSensor}
	for _, k := range settingKeys(obj) {
		if depth > 0 && !settingKeywords[k] {
			if strings.HasPrefix(k, "x-octm-") {
				return nil, &SettingsSchemaError{Path: pointer(path, k), Message: "unknown annotation"}
			}
			return nil, &SettingsSchemaError{Path: pointer(path, k), Message: "keyword not allowed"}
		}
	}
	var err error
	if p.Title, err = strKeyword(obj, path, "title"); err != nil {
		return nil, err
	}
	if p.Description, err = strKeyword(obj, path, "description"); err != nil {
		return nil, err
	}
	if p.Type, err = strKeyword(obj, path, "type"); err != nil {
		return nil, err
	}
	switch p.Type {
	case "", settingTypeBoolean, settingTypeInteger, settingTypeNumber, settingTypeString, settingTypeArray:
	case settingTypeObject:
		if depth > 1 {
			return nil, &SettingsSchemaError{Path: pointer(path, "type"), Message: "groups may not be nested"}
		}
	default:
		return nil, &SettingsSchemaError{Path: pointer(path, "type"), Message: fmt.Sprintf("type %q not allowed", p.Type)}
	}
	if p.Deprecated, err = boolKeyword(obj, path, "deprecated"); err != nil {
		return nil, err
	}
	if p.WriteOnly, err = boolKeyword(obj, path, "writeOnly"); err != nil {
		return nil, err
	}
	if p.Sensitive, err = boolKeyword(obj, path, "x-octm-sensitive"); err != nil {
		return nil, err
	}
	if p.Restart, err = boolKeyword(obj, path, "x-octm-restart"); err != nil {
		return nil, err
	}
	if p.Sensitive {
		p.WriteOnly = true
	}
	if scope, err := strKeyword(obj, path, "x-octm-scope"); err != nil {
		return nil, err
	} else if scope != "" {
		switch SettingScope(scope) {
		case SettingScopeSensor, SettingScopeScan:
			p.Scope = SettingScope(scope)
		default:
			return nil, &SettingsSchemaError{Path: pointer(path, "x-octm-scope"), Message: `must be "sensor" or "scan"`}
		}
	}
	if p.Tier, err = strKeyword(obj, path, "x-octm-tier"); err != nil {
		return nil, err
	}
	if p.Tier != "" && !settingTiers[p.Tier] {
		return nil, &SettingsSchemaError{Path: pointer(path, "x-octm-tier"), Message: `must be "T0", "T1" or "T2"`}
	}
	if p.Group, err = strKeyword(obj, path, "x-octm-group"); err != nil {
		return nil, err
	}
	if order, err := intKeyword(obj, path, "x-octm-order"); err != nil {
		return nil, err
	} else if order != nil {
		p.Order = *order
	}
	if p.Widget, err = strKeyword(obj, path, "x-octm-widget"); err != nil {
		return nil, err
	}
	if p.Widget != "" && !settingWidgets[p.Widget] {
		return nil, &SettingsSchemaError{Path: pointer(path, "x-octm-widget"), Message: "unknown widget"}
	}
	if ex, ok := obj["examples"]; ok {
		if _, isArr := ex.([]any); !isArr {
			return nil, &SettingsSchemaError{Path: pointer(path, "examples"), Message: "must be an array"}
		}
	}

	if p.Type == settingTypeObject {
		return parseSettingGroup(p, obj, path, depth, count)
	}
	for _, k := range []string{"properties", "required", "additionalProperties"} {
		if _, ok := obj[k]; ok {
			return nil, &SettingsSchemaError{Path: pointer(path, k), Message: "allowed only on an object"}
		}
	}
	if err := parseSettingConstraints(p, obj, path, depth, count); err != nil {
		return nil, err
	}
	return p, nil
}

func parseSettingGroup(p *SettingProperty, obj map[string]any, path string, depth int, count *int) (*SettingProperty, error) {
	for _, k := range []string{"enum", "const", "default", "items", "minimum", "maximum", "exclusiveMinimum",
		"exclusiveMaximum", "multipleOf", "minLength", "maxLength", "pattern", "format", "minItems",
		"maxItems", "uniqueItems"} {
		if _, ok := obj[k]; ok {
			return nil, &SettingsSchemaError{Path: pointer(path, k), Message: "not allowed on an object"}
		}
	}
	ap, ok := obj["additionalProperties"]
	if b, isBool := ap.(bool); !ok || !isBool || b {
		return nil, &SettingsSchemaError{Path: pointer(path, "additionalProperties"), Message: "must be false"}
	}
	rawProps, ok := obj["properties"]
	if !ok {
		return nil, &SettingsSchemaError{Path: pointer(path, "properties"), Message: "required on an object"}
	}
	props, ok := rawProps.(map[string]any)
	if !ok {
		return nil, &SettingsSchemaError{Path: pointer(path, "properties"), Message: "must be an object"}
	}
	for _, name := range settingKeys(props) {
		ppath := pointer(pointer(path, "properties"), name)
		if !settingNameRE.MatchString(name) {
			return nil, &SettingsSchemaError{Path: ppath, Message: "key names are lowercase letters, digits and '_', starting with a letter, at most 64"}
		}
		*count++
		if *count > MaxSettingsProperties {
			return nil, &SettingsSchemaError{Path: ppath, Message: fmt.Sprintf("more than %d properties", MaxSettingsProperties)}
		}
		sub, ok := props[name].(map[string]any)
		if !ok {
			return nil, &SettingsSchemaError{Path: ppath, Message: "must be an object"}
		}
		child, err := parseSettingProperty(sub, ppath, name, depth+1, count)
		if err != nil {
			return nil, err
		}
		if child.Type == settingTypeObject && depth > 0 {
			return nil, &SettingsSchemaError{Path: pointer(ppath, "type"), Message: "groups may not be nested"}
		}
		p.Properties = append(p.Properties, child)
	}
	if rawReq, ok := obj["required"]; ok {
		arr, isArr := rawReq.([]any)
		if !isArr {
			return nil, &SettingsSchemaError{Path: pointer(path, "required"), Message: "must be an array of key names"}
		}
		for i, r := range arr {
			name, isStr := r.(string)
			if !isStr || !slices.ContainsFunc(p.Properties, func(c *SettingProperty) bool { return c.Name == name }) {
				return nil, &SettingsSchemaError{Path: pointer(pointer(path, "required"), strconv.Itoa(i)), Message: "not a property"}
			}
			if slices.Contains(p.Required, name) {
				return nil, &SettingsSchemaError{Path: pointer(pointer(path, "required"), strconv.Itoa(i)), Message: "listed twice"}
			}
			p.Required = append(p.Required, name)
		}
	}
	return p, nil
}

func parseSettingConstraints(p *SettingProperty, obj map[string]any, path string, depth int, count *int) error {
	if err := parseSettingItems(p, obj, path, depth, count); err != nil {
		return err
	}
	if err := checkSettingKeywordPlacement(p, obj, path); err != nil {
		return err
	}
	if err := parseSettingBounds(p, obj, path); err != nil {
		return err
	}
	if err := parseSettingStringRules(p, obj, path); err != nil {
		return err
	}
	// Enum, const and default last: they are checked against the key's
	// own constraints.
	return parseSettingValues(p, obj, path)
}

func parseSettingItems(p *SettingProperty, obj map[string]any, path string, depth int, count *int) error {
	if p.Type == settingTypeArray {
		rawItems, ok := obj["items"]
		if !ok {
			return &SettingsSchemaError{Path: pointer(path, "items"), Message: "required on an array"}
		}
		sub, ok := rawItems.(map[string]any)
		if !ok {
			return &SettingsSchemaError{Path: pointer(path, "items"), Message: "must be an object"}
		}
		ipath := pointer(path, "items")
		for _, k := range []string{"default", "items", "x-octm-scope", "x-octm-tier", "x-octm-sensitive",
			"x-octm-restart", "x-octm-group", "x-octm-order", "x-octm-widget", "deprecated", "writeOnly",
			"minItems", "maxItems", "uniqueItems"} {
			if _, ok := sub[k]; ok {
				return &SettingsSchemaError{Path: pointer(ipath, k), Message: "not allowed on array items"}
			}
		}
		item, err := parseSettingProperty(sub, ipath, "", depth+1, count)
		if err != nil {
			return err
		}
		if item.Type == settingTypeArray || item.Type == settingTypeObject {
			return &SettingsSchemaError{Path: pointer(ipath, "type"), Message: "array items are scalars"}
		}
		p.Items = item
	} else if _, ok := obj["items"]; ok {
		return &SettingsSchemaError{Path: pointer(path, "items"), Message: "allowed only on an array"}
	}

	return nil
}

func checkSettingKeywordPlacement(p *SettingProperty, obj map[string]any, path string) error {
	numeric := p.Type == settingTypeInteger || p.Type == settingTypeNumber
	for _, k := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"} {
		if _, ok := obj[k]; ok && !numeric {
			return &SettingsSchemaError{Path: pointer(path, k), Message: "allowed only on an integer or number"}
		}
	}
	for _, k := range []string{"minLength", "maxLength", "pattern", "format"} {
		if _, ok := obj[k]; ok && p.Type != settingTypeString {
			return &SettingsSchemaError{Path: pointer(path, k), Message: "allowed only on a string"}
		}
	}
	for _, k := range []string{"minItems", "maxItems", "uniqueItems"} {
		if _, ok := obj[k]; ok && p.Type != settingTypeArray {
			return &SettingsSchemaError{Path: pointer(path, k), Message: "allowed only on an array"}
		}
	}
	return nil
}

func parseSettingBounds(p *SettingProperty, obj map[string]any, path string) error {
	var err error
	if p.Minimum, err = numKeyword(obj, path, "minimum"); err != nil {
		return err
	}
	if p.Maximum, err = numKeyword(obj, path, "maximum"); err != nil {
		return err
	}
	if p.ExclusiveMinimum, err = numKeyword(obj, path, "exclusiveMinimum"); err != nil {
		return err
	}
	if p.ExclusiveMaximum, err = numKeyword(obj, path, "exclusiveMaximum"); err != nil {
		return err
	}
	if p.MultipleOf, err = numKeyword(obj, path, "multipleOf"); err != nil {
		return err
	}
	if p.MultipleOf != nil && *p.MultipleOf <= 0 {
		return &SettingsSchemaError{Path: pointer(path, "multipleOf"), Message: "must be greater than 0"}
	}
	if p.Minimum != nil && p.Maximum != nil && *p.Minimum > *p.Maximum {
		return &SettingsSchemaError{Path: pointer(path, "minimum"), Message: "greater than maximum"}
	}
	if p.MinLength, err = intKeyword(obj, path, "minLength"); err != nil {
		return err
	}
	if p.MaxLength, err = intKeyword(obj, path, "maxLength"); err != nil {
		return err
	}
	if p.MinItems, err = intKeyword(obj, path, "minItems"); err != nil {
		return err
	}
	if p.MaxItems, err = intKeyword(obj, path, "maxItems"); err != nil {
		return err
	}
	for _, c := range []struct {
		k   string
		v   *int
		max int
	}{{"minLength", p.MinLength, MaxSettingsStringLen}, {"maxLength", p.MaxLength, MaxSettingsStringLen},
		{"minItems", p.MinItems, MaxSettingsItems}, {"maxItems", p.MaxItems, MaxSettingsItems}} {
		if c.v != nil && (*c.v < 0 || *c.v > c.max) {
			return &SettingsSchemaError{Path: pointer(path, c.k), Message: fmt.Sprintf("must be between 0 and %d", c.max)}
		}
	}
	if p.MinLength != nil && p.MaxLength != nil && *p.MinLength > *p.MaxLength {
		return &SettingsSchemaError{Path: pointer(path, "minLength"), Message: "greater than maxLength"}
	}
	if p.MinItems != nil && p.MaxItems != nil && *p.MinItems > *p.MaxItems {
		return &SettingsSchemaError{Path: pointer(path, "minItems"), Message: "greater than maxItems"}
	}
	if p.UniqueItems, err = boolKeyword(obj, path, "uniqueItems"); err != nil {
		return err
	}
	return nil
}

func parseSettingStringRules(p *SettingProperty, obj map[string]any, path string) error {
	var err error
	if p.Pattern, err = strKeyword(obj, path, "pattern"); err != nil {
		return err
	}
	if p.Pattern != "" {
		if len(p.Pattern) > MaxSettingsPatternLen {
			return &SettingsSchemaError{Path: pointer(path, "pattern"), Message: fmt.Sprintf("longer than %d", MaxSettingsPatternLen)}
		}
		re, rerr := regexp.Compile(p.Pattern)
		if rerr != nil {
			return &SettingsSchemaError{Path: pointer(path, "pattern"), Message: "not an RE2 expression: " + rerr.Error()}
		}
		p.pattern = re
	}
	if p.Format, err = strKeyword(obj, path, "format"); err != nil {
		return err
	}
	if p.Format != "" && !settingFormats[p.Format] {
		return &SettingsSchemaError{Path: pointer(path, "format"), Message: `must be "hostname", "uri" or "duration"`}
	}

	return nil
}

func parseSettingValues(p *SettingProperty, obj map[string]any, path string) error {
	if rawEnum, ok := obj["enum"]; ok {
		arr, isArr := rawEnum.([]any)
		if !isArr || len(arr) == 0 || len(arr) > MaxSettingsEnum {
			return &SettingsSchemaError{Path: pointer(path, "enum"), Message: fmt.Sprintf("must be an array of 1 to %d values", MaxSettingsEnum)}
		}
		for i, e := range arr {
			epath := pointer(pointer(path, "enum"), strconv.Itoa(i))
			if !isScalar(e) {
				return &SettingsSchemaError{Path: epath, Message: "enum values are scalars"}
			}
			for _, prev := range arr[:i] {
				if settingValuesEqual(prev, e) {
					return &SettingsSchemaError{Path: epath, Message: "listed twice"}
				}
			}
			var errs SettingsErrors
			validateScalar(&SettingProperty{Type: p.Type, Format: p.Format, pattern: p.pattern, Pattern: p.Pattern,
				Minimum: p.Minimum, Maximum: p.Maximum, ExclusiveMinimum: p.ExclusiveMinimum,
				ExclusiveMaximum: p.ExclusiveMaximum, MultipleOf: p.MultipleOf, MinLength: p.MinLength,
				MaxLength: p.MaxLength}, e, "", &errs)
			if len(errs) > 0 {
				return &SettingsSchemaError{Path: epath, Message: "does not satisfy the key's own constraints: " + errs[0].Message}
			}
		}
		p.Enum = arr
	}
	if c, ok := obj["const"]; ok {
		if !isScalar(c) {
			return &SettingsSchemaError{Path: pointer(path, "const"), Message: "must be a scalar"}
		}
		p.Const, p.HasConst = c, true
	}
	if p.Type == "" && p.Enum == nil && !p.HasConst {
		return &SettingsSchemaError{Path: pointer(path, "type"), Message: "required unless enum or const is given"}
	}
	if d, ok := obj["default"]; ok {
		if p.Sensitive {
			return &SettingsSchemaError{Path: pointer(path, "default"), Message: "a sensitive key has no default"}
		}
		var errs SettingsErrors
		validateValue(p, d, "", &errs)
		if len(errs) > 0 {
			return &SettingsSchemaError{Path: pointer(path, "default"), Message: "does not satisfy the key's own constraints: " + errs[0].Message}
		}
		p.Default, p.HasDefault = d, true
	}
	return nil
}

// --- validation ------------------------------------------------------------

func validateGroup(props []*SettingProperty, required []string, values map[string]any, path string, checkRequired bool, errs *SettingsErrors) {
	for _, k := range settingKeys(values) {
		p := findProperty(props, k)
		if p == nil {
			*errs = append(*errs, SettingsError{Path: pointer(path, k), Message: "unknown key"})
			continue
		}
		if p.Sensitive {
			*errs = append(*errs, SettingsError{Path: pointer(path, k), Message: "a sensitive key is not set as a plain value"})
			continue
		}
		if p.Type == settingTypeObject {
			sub, ok := values[k].(map[string]any)
			if !ok {
				*errs = append(*errs, SettingsError{Path: pointer(path, k), Message: "must be an object"})
				continue
			}
			validateGroup(p.Properties, p.Required, sub, pointer(path, k), checkRequired, errs)
			continue
		}
		validateValue(p, values[k], pointer(path, k), errs)
	}
	if !checkRequired {
		return
	}
	for _, p := range props {
		if _, given := values[p.Name]; !given && p.Type == settingTypeObject {
			validateGroup(p.Properties, p.Required, map[string]any{}, pointer(path, p.Name), true, errs)
		}
	}
	for _, r := range required {
		if _, ok := values[r]; ok {
			continue
		}
		if p := findProperty(props, r); p != nil && (p.HasDefault || p.Type == settingTypeObject) {
			continue
		}
		*errs = append(*errs, SettingsError{Path: pointer(path, r), Message: "required"})
	}
}

func validateValue(p *SettingProperty, v any, path string, errs *SettingsErrors) {
	if p.Type != settingTypeArray {
		validateScalar(p, v, path, errs)
		return
	}
	arr, ok := v.([]any)
	if !ok {
		*errs = append(*errs, SettingsError{Path: path, Message: "must be an array"})
		return
	}
	if len(arr) > MaxSettingsItems {
		*errs = append(*errs, SettingsError{Path: path, Message: fmt.Sprintf("more than %d items", MaxSettingsItems)})
		return
	}
	if p.MinItems != nil && len(arr) < *p.MinItems {
		*errs = append(*errs, SettingsError{Path: path, Message: fmt.Sprintf("fewer than %d items", *p.MinItems)})
	}
	if p.MaxItems != nil && len(arr) > *p.MaxItems {
		*errs = append(*errs, SettingsError{Path: path, Message: fmt.Sprintf("more than %d items", *p.MaxItems)})
	}
	for i, e := range arr {
		validateScalar(p.Items, e, pointer(path, strconv.Itoa(i)), errs)
		if p.UniqueItems {
			for _, prev := range arr[:i] {
				if settingValuesEqual(prev, e) {
					*errs = append(*errs, SettingsError{Path: pointer(path, strconv.Itoa(i)), Message: "duplicate item"})
					break
				}
			}
		}
	}
	if p.HasConst && !settingValuesEqual(p.Const, v) {
		*errs = append(*errs, SettingsError{Path: path, Message: "must equal the constant"})
	}
}

func validateScalar(p *SettingProperty, v any, path string, errs *SettingsErrors) {
	add := func(msg string) { *errs = append(*errs, SettingsError{Path: path, Message: msg}) }
	if !isScalar(v) {
		add("must be a scalar")
		return
	}
	switch p.Type {
	case settingTypeBoolean:
		if _, ok := v.(bool); !ok {
			add("must be a boolean")
			return
		}
	case settingTypeInteger, settingTypeNumber:
		n, ok := v.(json.Number)
		if !ok {
			if p.Type == settingTypeInteger {
				add("must be an integer")
			} else {
				add("must be a number")
			}
			return
		}
		f, err := n.Float64()
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			add("not a finite number")
			return
		}
		if p.Type == settingTypeInteger && (f != math.Trunc(f) || math.Abs(f) > 1<<53) {
			add("must be an integer")
			return
		}
		if p.Minimum != nil && f < *p.Minimum {
			add(fmt.Sprintf("less than %s", formatSettingNumber(*p.Minimum)))
		}
		if p.Maximum != nil && f > *p.Maximum {
			add(fmt.Sprintf("greater than %s", formatSettingNumber(*p.Maximum)))
		}
		if p.ExclusiveMinimum != nil && f <= *p.ExclusiveMinimum {
			add(fmt.Sprintf("not greater than %s", formatSettingNumber(*p.ExclusiveMinimum)))
		}
		if p.ExclusiveMaximum != nil && f >= *p.ExclusiveMaximum {
			add(fmt.Sprintf("not less than %s", formatSettingNumber(*p.ExclusiveMaximum)))
		}
		if p.MultipleOf != nil {
			q := f / *p.MultipleOf
			if math.Abs(q-math.Round(q)) > 1e-9 {
				add(fmt.Sprintf("not a multiple of %s", formatSettingNumber(*p.MultipleOf)))
			}
		}
	case settingTypeString:
		s, ok := v.(string)
		if !ok {
			add("must be a string")
			return
		}
		n := len([]rune(s))
		if len(s) > MaxSettingsStringLen*4 || n > MaxSettingsStringLen {
			add(fmt.Sprintf("longer than %d characters", MaxSettingsStringLen))
			return
		}
		if p.MinLength != nil && n < *p.MinLength {
			add(fmt.Sprintf("shorter than %d characters", *p.MinLength))
		}
		if p.MaxLength != nil && n > *p.MaxLength {
			add(fmt.Sprintf("longer than %d characters", *p.MaxLength))
		}
		if p.pattern != nil && !p.pattern.MatchString(s) {
			add("does not match the pattern")
		}
		if p.Format != "" && !validFormat(p.Format, s) {
			add("not a valid " + p.Format)
		}
	}
	if p.Enum != nil && !slices.ContainsFunc(p.Enum, func(e any) bool { return settingValuesEqual(e, v) }) {
		add("not one of the allowed values")
	}
	if p.HasConst && !settingValuesEqual(p.Const, v) {
		add("must equal the constant")
	}
}

func validFormat(format, s string) bool {
	switch format {
	case "hostname":
		return len(s) <= 253 && hostnameRE.MatchString(s)
	case "uri":
		scheme, rest, ok := strings.Cut(s, "://")
		if !ok || rest == "" || strings.ContainsAny(s, " \t\r\n") {
			return false
		}
		return scheme == "http" || scheme == "https"
	case "duration":
		d, err := time.ParseDuration(s)
		return err == nil && d >= 0
	}
	return false
}

// --- helpers ---------------------------------------------------------------

// decodeSettingsJSON decodes one JSON value with exact numbers and refuses
// trailing data.
func decodeSettingsJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// checkNoDuplicateKeys refuses an object with a member listed twice: a
// decoder keeps the last, so a reviewer and a validator could read
// different schemas.
func checkNoDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		obj  bool
		keys map[string]bool
		path string
		idx  int
		key  string
	}
	var stack []*frame
	child := func() string {
		if len(stack) == 0 {
			return ""
		}
		f := stack[len(stack)-1]
		if f.obj {
			return pointer(f.path, f.key)
		}
		p := pointer(f.path, strconv.Itoa(f.idx))
		f.idx++
		return p
	}
	expectKey := func() bool {
		return len(stack) > 0 && stack[len(stack)-1].obj && stack[len(stack)-1].key == ""
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return &SettingsSchemaError{Path: "", Message: "not JSON: " + err.Error()}
		}
		if expectKey() {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].key = ""
				}
				continue
			}
			k, _ := tok.(string)
			f := stack[len(stack)-1]
			if f.keys[k] {
				return &SettingsSchemaError{Path: pointer(f.path, k), Message: "member listed twice"}
			}
			f.keys[k] = true
			f.key = k
			continue
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, path: child()})
			case '[':
				stack = append(stack, &frame{path: child()})
			case '}', ']':
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].key = ""
				}
			}
		default:
			if len(stack) > 0 {
				f := stack[len(stack)-1]
				if f.obj {
					f.key = ""
				} else {
					f.idx++
				}
			}
		}
	}
}

// canonicalDigest is "sha256:" + hex SHA-256 of v's canonical JSON: object
// members sorted by key, no insignificant whitespace, numbers exactly as
// written, no HTML escaping (Go's encoding of the decoded value).
func canonicalDigest(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SettingsDigest is the canonical digest of any JSON document (a values
// document, a settings document): "sha256:" + hex SHA-256 of its canonical
// JSON, as for SettingsSchema.Digest.
func SettingsDigest(raw []byte) (string, error) {
	v, err := decodeSettingsJSON(raw)
	if err != nil {
		return "", err
	}
	return canonicalDigest(v)
}

func pointer(base, token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	token = strings.ReplaceAll(token, "/", "~1")
	return base + "/" + token
}

func settingKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func findProperty(props []*SettingProperty, name string) *SettingProperty {
	for _, p := range props {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func isScalar(v any) bool {
	switch v.(type) {
	case bool, string, json.Number:
		return true
	}
	return false
}

// settingValuesEqual compares scalars (numbers by value) and arrays of them.
func settingValuesEqual(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		fx, ex := x.Float64()
		fy, ey := y.Float64()
		return ex == nil && ey == nil && fx == fy
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !settingValuesEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func cloneSettingValue(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = cloneSettingValue(x[i])
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneSettingValue(e)
		}
		return out
	}
	return v
}

// normalizeSettings returns a copy of values with Go numbers turned into
// json.Number and []string into []any, the form the validator reads.
func normalizeSettings(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for k, v := range values {
		out[k] = normalizeSettingValue(v)
	}
	return out
}

func normalizeSettingValue(v any) any {
	switch x := v.(type) {
	case int:
		return json.Number(strconv.FormatInt(int64(x), 10))
	case int32:
		return json.Number(strconv.FormatInt(int64(x), 10))
	case int64:
		return json.Number(strconv.FormatInt(x, 10))
	case uint:
		return json.Number(strconv.FormatUint(uint64(x), 10))
	case uint32:
		return json.Number(strconv.FormatUint(uint64(x), 10))
	case uint64:
		return json.Number(strconv.FormatUint(x, 10))
	case float32:
		return json.Number(strconv.FormatFloat(float64(x), 'g', -1, 32))
	case float64:
		return json.Number(strconv.FormatFloat(x, 'g', -1, 64))
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = normalizeSettingValue(x[i])
		}
		return out
	case map[string]any:
		return normalizeSettings(x)
	}
	return v
}

// flattenSettings turns {"group": {"key": v}} into {"group.key": v}.
func flattenSettings(values map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range values {
		if sub, ok := v.(map[string]any); ok {
			for sk, sv := range sub {
				out[k+"."+sk] = sv
			}
			continue
		}
		out[k] = v
	}
	return out
}

func formatSettingNumber(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func strKeyword(obj map[string]any, path, k string) (string, error) {
	v, ok := obj[k]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", &SettingsSchemaError{Path: pointer(path, k), Message: "must be a string"}
	}
	return s, nil
}

func boolKeyword(obj map[string]any, path, k string) (bool, error) {
	v, ok := obj[k]
	if !ok {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, &SettingsSchemaError{Path: pointer(path, k), Message: "must be a boolean"}
	}
	return b, nil
}

func numKeyword(obj map[string]any, path, k string) (*float64, error) {
	v, ok := obj[k]
	if !ok {
		return nil, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return nil, &SettingsSchemaError{Path: pointer(path, k), Message: "must be a number"}
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, &SettingsSchemaError{Path: pointer(path, k), Message: "must be a finite number"}
	}
	return &f, nil
}

func intKeyword(obj map[string]any, path, k string) (*int, error) {
	v, ok := obj[k]
	if !ok {
		return nil, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return nil, &SettingsSchemaError{Path: pointer(path, k), Message: "must be an integer"}
	}
	i, err := n.Int64()
	if err != nil || i < math.MinInt32 || i > math.MaxInt32 {
		return nil, &SettingsSchemaError{Path: pointer(path, k), Message: "must be an integer"}
	}
	x := int(i)
	return &x, nil
}
