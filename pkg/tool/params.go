package tool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/capability"
)

// Bounds of a standard param value.
const (
	maxParamListItems = 256
	maxParamString    = 2048
)

var portListRE = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$`)

// Exceeds reports whether t is more intrusive than ceiling. An unknown tier
// exceeds every ceiling.
func (t Tier) Exceeds(ceiling Tier) bool {
	r := tierRank(t)
	return r < 0 || r > tierRank(ceiling)
}

// ApplyParams maps a task's standard params onto the tool's config keys,
// through the implements entry of the task's capability, and returns the
// task with Params cleared and Config set. Every value is checked against
// the capability's param (type, enum, bounds) and against the tool's
// narrowing (values, min, max); a param the tool does not map, a value it
// does not support and a config key the task also sets to another value are
// invalid_input. Nothing is dropped silently.
//
// A task without a capability must carry no params. A capability the tool
// does not implement is invalid_input.
func (m Manifest) ApplyParams(task Task) (Task, error) {
	if task.Capability == "" {
		if len(task.Params) > 0 {
			return task, Invalid("standard params need the task's capability")
		}
		return task, nil
	}
	im, ok := m.Implementation(task.Capability)
	if !ok {
		return task, Invalid("%s does not implement %s", m.Name, task.Capability)
	}
	c, ok := capability.Lookup(task.Capability)
	if !ok {
		return task, Invalid("%s is not in the capability taxonomy", task.Capability)
	}
	if len(task.Params) == 0 {
		task.Params = nil
		return task, nil
	}
	schema, err := m.ConfigSchema()
	if err != nil {
		return task, Invalid("config schema: %v", err)
	}
	cfg := map[string]any{}
	if raw := bytes.TrimSpace(task.Config); len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &cfg); err != nil || cfg == nil {
			return task, Invalid("config must be a JSON object")
		}
	}
	names := make([]string, 0, len(task.Params))
	for n := range task.Params {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, name := range names {
		std, ok := c.Param(name)
		if !ok {
			return task, Invalid("%s has no standard param %q", c.Ref(), name)
		}
		pm, ok := im.Params[name]
		if !ok {
			return task, Invalid("%s does not take %s's param %q", m.Name, c.Ref(), name)
		}
		key := pm.ConfigKey(name)
		v, err := checkParamValue(std, pm, task.Params[name])
		if err != nil {
			return task, Invalid("param %q: %v", name, err)
		}
		if std.Type == capability.ParamPortList && schema != nil {
			if p := schema.Property(key); p != nil && p.Type == "array" {
				v = strings.Split(v.(string), ",")
			}
		}
		if old, set := cfg[key]; set && !sameJSON(old, v) {
			return task, Invalid("config key %q is set and standard param %q sets it to another value", key, name)
		}
		cfg[key] = v
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return task, Invalid("%v", err)
	}
	task.Config = b
	task.Params = nil
	return task, nil
}

// checkParamValue decodes and checks one standard param value.
func checkParamValue(std capability.Param, pm ParamMapping, raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("not JSON")
	}
	allowed := func(s string) error {
		if len(std.Enum) > 0 && !slices.Contains(std.Enum, s) {
			return fmt.Errorf("%q is not one of %s", s, strings.Join(std.Enum, ", "))
		}
		if len(pm.Values) > 0 && !slices.Contains(pm.Values, s) {
			return fmt.Errorf("%q is not supported by this tool (supported: %s)", s, strings.Join(pm.Values, ", "))
		}
		return nil
	}
	switch std.Type {
	case capability.ParamString:
		s, ok := v.(string)
		if !ok || len(s) > maxParamString {
			return nil, fmt.Errorf("must be a string of at most %d bytes", maxParamString)
		}
		return s, allowed(s)
	case capability.ParamStringList:
		list, ok := v.([]any)
		if !ok || len(list) > maxParamListItems {
			return nil, fmt.Errorf("must be a list of at most %d strings", maxParamListItems)
		}
		out := make([]string, 0, len(list))
		for _, e := range list {
			s, ok := e.(string)
			if !ok || s == "" || len(s) > 256 {
				return nil, fmt.Errorf("every item must be a string of 1 to 256 bytes")
			}
			if err := allowed(s); err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	case capability.ParamBoolean:
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("must be true or false")
		}
		return b, nil
	case capability.ParamInteger:
		n, ok := v.(json.Number)
		if !ok {
			return nil, fmt.Errorf("must be an integer")
		}
		i, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("must be an integer")
		}
		for _, b := range []struct {
			lo, hi *int
			who    string
		}{{std.Min, std.Max, "the capability"}, {pm.Min, pm.Max, "this tool"}} {
			if b.lo != nil && i < int64(*b.lo) {
				return nil, fmt.Errorf("%d is below the minimum %d of %s", i, *b.lo, b.who)
			}
			if b.hi != nil && i > int64(*b.hi) {
				return nil, fmt.Errorf("%d is above the maximum %d of %s", i, *b.hi, b.who)
			}
		}
		return i, nil
	case capability.ParamPortList:
		s, ok := v.(string)
		if !ok {
			if list, isList := v.([]any); isList {
				parts := make([]string, 0, len(list))
				for _, e := range list {
					switch x := e.(type) {
					case string:
						parts = append(parts, x)
					case json.Number:
						parts = append(parts, x.String())
					default:
						return nil, fmt.Errorf("ports must be numbers or ranges")
					}
				}
				s, ok = strings.Join(parts, ","), true
			}
		}
		s = strings.ReplaceAll(s, " ", "")
		if !ok || len(s) > maxParamString || !portListRE.MatchString(s) {
			return nil, fmt.Errorf("must be ports and ranges (80,443,8000-8100)")
		}
		for _, part := range strings.Split(s, ",") {
			lo, hi, isRange := strings.Cut(part, "-")
			a, _ := strconv.Atoi(lo)
			b := a
			if isRange {
				b, _ = strconv.Atoi(hi)
			}
			if a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("%q is not a port or a range within 1-65535", part)
			}
		}
		return s, nil
	}
	return nil, fmt.Errorf("unknown param type %s", std.Type)
}

func sameJSON(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}
