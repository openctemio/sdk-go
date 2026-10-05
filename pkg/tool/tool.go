package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
)

// Tool is the one contract for every workload a sensor runs.
type Tool interface {
	// Manifest describes the tool. It is static: the runtime reads it
	// before any tool code runs.
	Manifest() Manifest
	// Run does the work of one task.
	Run(ctx Context, task Task) error
}

// Validator is optional: semantic checks beyond the manifest's schemas,
// run before any target is touched.
type Validator interface {
	Validate(ctx context.Context, task Task) error
}

// NoConfig is the configuration type of a tool without configuration.
type NoConfig struct{}

// New builds a Tool from a manifest and a typed run function. C is the
// tool's configuration: the runtime validates the task's configuration
// against the manifest's schema, then the tool decodes it into C (defaults
// filled, unknown keys refused).
//
// When m.Config is nil and C has fields, the schema is derived from C's
// struct tags: json (the key), default, min, max, enum (comma-separated),
// pattern, maxLength, maxItems, title, description, scope ("scan" lets a
// scan set the key), required ("true"). A field tagged secret:"true" is
// refused: secrets are credentials, never configuration.
//
// New panics when the manifest is invalid: a tool compiled into a sensor
// with a broken manifest must stop the sensor at start, not run.
func New[C any](m Manifest, run func(ctx Context, task Task, cfg C) error) Tool {
	m = m.withDefaults()
	if len(m.Config) == 0 {
		schema, err := SchemaFor[C]()
		if err != nil {
			panic(fmt.Sprintf("tool %s: %v", m.Name, err))
		}
		m.Config = schema
	}
	if err := m.Validate(); err != nil {
		panic(fmt.Sprintf("tool %s: %v", m.Name, err))
	}
	schema, _ := m.ConfigSchema()
	return &typedTool[C]{m: m, schema: schema, run: run}
}

type typedTool[C any] struct {
	m      Manifest
	schema *core.SettingsSchema
	run    func(Context, Task, C) error
}

func (t *typedTool[C]) Manifest() Manifest { return t.m }

func (t *typedTool[C]) Run(ctx Context, task Task) error {
	cfg, err := DecodeConfig[C](t.schema, task.Config)
	if err != nil {
		return err
	}
	return t.run(ctx, task, cfg)
}

// DecodeConfig validates raw against schema (nil: no configuration),
// fills the defaults and decodes it into C, refusing unknown keys.
func DecodeConfig[C any](schema *core.SettingsSchema, raw json.RawMessage) (C, error) {
	var cfg C
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		raw = []byte("{}")
	}
	if schema == nil {
		if !bytes.Equal(raw, []byte("{}")) {
			return cfg, Invalid("the tool takes no configuration")
		}
		return cfg, nil
	}
	if err := schema.ValidateJSON(raw); err != nil {
		return cfg, Invalid("%v", err)
	}
	var given map[string]any
	if err := json.Unmarshal(raw, &given); err != nil {
		return cfg, Invalid("configuration: %v", err)
	}
	merged := schema.Defaults()
	for k, v := range given {
		if sub, ok := v.(map[string]any); ok {
			if def, ok := merged[k].(map[string]any); ok {
				for sk, sv := range sub {
					def[sk] = sv
				}
				continue
			}
		}
		merged[k] = v
	}
	b, err := json.Marshal(merged)
	if err != nil {
		return cfg, Invalid("configuration: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, Invalid("configuration: %v", err)
	}
	return cfg, nil
}

// SchemaFor derives a configuration schema (the settings schema subset)
// from C's struct tags; nil when C has no fields. The output is
// deterministic.
func SchemaFor[C any]() (json.RawMessage, error) {
	t := reflect.TypeFor[C]()
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("config type %s must be a struct", t)
	}
	props, required, err := structProps(t, 0)
	if err != nil {
		return nil, err
	}
	if len(props) == 0 {
		return nil, nil
	}
	root := map[string]any{
		"type":                  "object",
		"additionalProperties":  false,
		"properties":            props,
		"x-octm-schema-version": 1,
	}
	if len(required) > 0 {
		root["required"] = required
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil { // maps encode with sorted keys
		return nil, err
	}
	out := json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n"))
	if _, err := core.ParseSettingsSchema(out); err != nil {
		return nil, fmt.Errorf("derived config schema: %w", err)
	}
	return out, nil
}

func structProps(t reflect.Type, depth int) (map[string]any, []string, error) {
	props := map[string]any{}
	var required []string
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			return nil, nil, fmt.Errorf("config field %s needs a json tag", f.Name)
		}
		if f.Tag.Get("secret") == "true" {
			return nil, nil, fmt.Errorf("config field %s is a secret: declare a credential (permissions.credentials) instead", f.Name)
		}
		p, err := fieldProp(f, depth)
		if err != nil {
			return nil, nil, err
		}
		props[name] = p
		if f.Tag.Get("required") == "true" {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	return props, required, nil
}

func fieldProp(f reflect.StructField, depth int) (map[string]any, error) {
	p := map[string]any{}
	ft := f.Type
	switch ft.Kind() {
	case reflect.Bool:
		p["type"] = "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		p["type"] = "integer"
	case reflect.Float32, reflect.Float64:
		p["type"] = "number"
	case reflect.String:
		p["type"] = "string"
	case reflect.Slice:
		item := map[string]any{}
		switch ft.Elem().Kind() {
		case reflect.String:
			item["type"] = "string"
		case reflect.Int, reflect.Int32, reflect.Int64:
			item["type"] = "integer"
		default:
			return nil, fmt.Errorf("config field %s: only lists of strings or integers", f.Name)
		}
		p["type"], p["items"] = "array", item
	case reflect.Struct:
		if depth > 0 {
			return nil, fmt.Errorf("config field %s: groups nest one level only", f.Name)
		}
		sub, req, err := structProps(ft, depth+1)
		if err != nil {
			return nil, err
		}
		p["type"], p["properties"], p["additionalProperties"] = "object", sub, false
		if len(req) > 0 {
			p["required"] = req
		}
	default:
		return nil, fmt.Errorf("config field %s: unsupported type %s", f.Name, ft)
	}
	tag := f.Tag
	for _, k := range []string{"title", "description"} {
		if v := tag.Get(k); v != "" {
			p[k] = v
		}
	}
	if v := tag.Get("pattern"); v != "" {
		p["pattern"] = v
	}
	if v := tag.Get("scope"); v != "" {
		p["x-octm-scope"] = v
	}
	for tagName, key := range map[string]string{"min": "minimum", "max": "maximum"} {
		if v := tag.Get(tagName); v != "" {
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("config field %s: %s=%q is not a number", f.Name, tagName, v)
			}
			p[key] = n
		}
	}
	for tagName, key := range map[string]string{"maxLength": "maxLength", "maxItems": "maxItems"} {
		if v := tag.Get(tagName); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config field %s: %s=%q is not an integer", f.Name, tagName, v)
			}
			p[key] = n
		}
	}
	if v, ok := tag.Lookup("enum"); ok {
		vals := []any{}
		for _, e := range strings.Split(v, ",") {
			ev, err := scalarValue(p["type"], strings.TrimSpace(e))
			if err != nil {
				return nil, fmt.Errorf("config field %s: enum: %w", f.Name, err)
			}
			vals = append(vals, ev)
		}
		p["enum"] = vals
	}
	if v, ok := tag.Lookup("default"); ok {
		var dv any
		var err error
		if p["type"] == "array" {
			items := []any{}
			for _, e := range strings.Split(v, ",") {
				if e = strings.TrimSpace(e); e == "" {
					continue
				}
				iv, err := scalarValue(p["items"].(map[string]any)["type"], e)
				if err != nil {
					return nil, fmt.Errorf("config field %s: default: %w", f.Name, err)
				}
				items = append(items, iv)
			}
			dv = items
		} else if dv, err = scalarValue(p["type"], v); err != nil {
			return nil, fmt.Errorf("config field %s: default: %w", f.Name, err)
		}
		p["default"] = dv
	}
	return p, nil
}

func scalarValue(typ any, s string) (any, error) {
	switch typ {
	case "boolean":
		return strconv.ParseBool(s)
	case "integer":
		return strconv.ParseInt(s, 10, 64)
	case "number":
		return strconv.ParseFloat(s, 64)
	case "string":
		return s, nil
	}
	return nil, fmt.Errorf("no scalar value for type %v", typ)
}
