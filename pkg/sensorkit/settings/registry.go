// Package settings is the sensor settings registry: every setting a sensor
// reads, declared once with its name, type, whether it is required, its
// default, whether it is a secret, a description, a docs link and a
// validation. The kit reports, per declared setting, only whether it is set,
// where it came from and whether its value is valid; the value itself never
// leaves the sensor host (OpenCTEM research/26, F3/F4: values of non-secret
// settings are a later phase, secret values never).
//
// Design: https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-033-sensor-manifest.md
// (config report section) and OpenCTEM research/26.
package settings

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Type is a setting's value type.
type Type string

// Setting types.
const (
	String   Type = "string"
	Int      Type = "int"
	Bool     Type = "bool"
	Duration Type = "duration"
	Bytes    Type = "bytes"
	Enum     Type = "enum"
	List     Type = "list"
	Path     Type = "path"
	URL      Type = "url"
)

// Source says where a setting's value came from.
type Source string

// Sources of a setting's value.
const (
	// SourceEnv: the environment variable is set.
	SourceEnv Source = "env"
	// SourceOption: the sensor set it itself (a command-line flag or its
	// configuration file), not the environment.
	SourceOption Source = "option"
	// SourceDefault: unset, a default applies.
	SourceDefault Source = "default"
	// SourceUnset: unset, no default.
	SourceUnset Source = "unset"
)

// DocsBase is the root of the sensor settings reference.
const DocsBase = "https://docs.openctem.io/sensor/settings"

// Setting is one declared setting.
type Setting struct {
	// Name is the environment variable ("SENSOR_MAX_JOBS"); it is the
	// setting's identity on the wire.
	Name string
	// Type is the value type.
	Type Type
	// Required: the sensor cannot run without it (it refuses to start).
	Required bool
	// Default is the default, as text for the docs ("" = none).
	Default string
	// Secret: the value is a credential. It is never logged, reported or
	// exported; only its presence is.
	Secret bool
	// Description is one line for the docs and the platform's checklist.
	Description string
	// Docs is the docs link (default DocsBase#<Name>).
	Docs string
	// Group is the area: platform, identity, policy, tools, content,
	// network, storage, runtime, connector.
	Group string
	// Validate checks a set value (nil: any value). Its error must not
	// contain the value.
	Validate func(value string) error
	// Enum lists the allowed values of an Enum.
	Enum []string
}

// DocsURL is the setting's docs link.
func (s Setting) DocsURL() string {
	if s.Docs != "" {
		return s.Docs
	}
	return DocsBase + "#" + s.Name
}

// Registry is an ordered set of settings, unique by name. It is safe for
// concurrent use.
type Registry struct {
	mu       sync.RWMutex
	settings []Setting
	byName   map[string]int
	options  map[string]bool // names a sensor set itself (SourceOption)
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{byName: map[string]int{}, options: map[string]bool{}}
}

// Register adds settings. A name registered twice panics: two declarations
// of one setting would disagree.
func (r *Registry) Register(ss ...Setting) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range ss {
		if s.Name == "" {
			panic("settings: a setting without a name")
		}
		if _, dup := r.byName[s.Name]; dup {
			panic("settings: " + s.Name + " registered twice")
		}
		r.byName[s.Name] = len(r.settings)
		r.settings = append(r.settings, s)
	}
}

// Has reports whether name is registered.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.byName[name]
	return ok
}

// Lookup returns the setting named name.
func (r *Registry) Lookup(name string) (Setting, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	i, ok := r.byName[name]
	if !ok {
		return Setting{}, false
	}
	return r.settings[i], true
}

// All returns the settings in registration order.
func (r *Registry) All() []Setting {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.settings)
}

// MarkOption records that the sensor set name itself (from a flag or its
// configuration file): it is reported as set, with source "option", when
// the environment does not set it.
func (r *Registry) MarkOption(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.options[name] = true
}

// State is one setting's reported state: presence, source and validity.
// It has no value member by construction.
type State struct {
	Name   string `json:"name"`
	Set    bool   `json:"set"`
	Source Source `json:"source"`
	Secret bool   `json:"secret"`
	Valid  bool   `json:"valid"`
}

// States resolves every setting against lookup (os.LookupEnv when nil):
// whether it is set, its source and whether its value is valid. Values
// are read only to validate them and are not kept.
func (r *Registry) States(lookup func(string) (string, bool)) []State {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]State, 0, len(r.settings))
	for _, s := range r.settings {
		st := State{Name: s.Name, Secret: s.Secret, Valid: true}
		v, ok := lookup(s.Name)
		switch {
		case ok && strings.TrimSpace(v) != "":
			st.Set, st.Source = true, SourceEnv
			st.Valid = s.valid(v)
		case r.options[s.Name]:
			st.Set, st.Source = true, SourceOption
		case s.Default != "":
			st.Source = SourceDefault
		default:
			st.Source = SourceUnset
			st.Valid = !s.Required
		}
		out = append(out, st)
	}
	return out
}

func (s Setting) valid(v string) bool {
	if s.Type == Enum && len(s.Enum) > 0 && !slices.Contains(s.Enum, strings.ToLower(strings.TrimSpace(v))) {
		return false
	}
	if s.Validate != nil && s.Validate(v) != nil {
		return false
	}
	return true
}

// SecretValues returns the values of the secret settings that are set in
// lookup (os.LookupEnv when nil), so a report builder can scrub them from
// any free text before it leaves the host.
func (r *Registry) SecretValues(lookup func(string) (string, bool)) []string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for _, s := range r.settings {
		if !s.Secret {
			continue
		}
		if v, ok := lookup(s.Name); ok && strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

// Unknown returns the environment variables in environ (os.Environ when
// nil) that carry one of prefixes but are not registered, sorted, each with
// the closest registered name within edit distance 2 ("" when none).
func (r *Registry) Unknown(environ []string, prefixes ...string) []Suggestion {
	if environ == nil {
		environ = os.Environ()
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]bool{}
	var out []Suggestion
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if seen[name] || !hasAnyPrefix(name, prefixes) {
			continue
		}
		seen[name] = true
		if _, ok := r.byName[name]; ok {
			continue
		}
		out = append(out, Suggestion{Name: name, DidYouMean: r.closestLocked(name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Suggestion is an unknown name and the closest registered one.
type Suggestion struct {
	Name       string
	DidYouMean string
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (r *Registry) closestLocked(name string) string {
	best, bestD := "", 3
	for _, s := range r.settings {
		if d := Distance(name, s.Name); d < bestD {
			best, bestD = s.Name, d
		}
	}
	return best
}

// Closest returns the candidate within edit distance 2 of name (case
// insensitive), the nearest first; "" when none is.
func Closest(name string, candidates []string) string {
	best, bestD := "", 3
	for _, c := range candidates {
		if d := Distance(strings.ToLower(name), strings.ToLower(c)); d < bestD {
			best, bestD = c, d
		}
	}
	return best
}

// Distance is the Levenshtein distance of a and b (bytes).
func Distance(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// Markdown renders the registry as a docs table (name, type, required,
// default, secret, description).
func (r *Registry) Markdown() string {
	var b strings.Builder
	b.WriteString("| Setting | Type | Required | Default | Secret | Description |\n|---|---|---|---|---|---|\n")
	for _, s := range r.All() {
		req, sec := "", ""
		if s.Required {
			req = "yes"
		}
		if s.Secret {
			sec = "yes"
		}
		def := s.Default
		if def != "" {
			def = "`" + def + "`"
		}
		fmt.Fprintf(&b, "| [`%s`](%s) | %s | %s | %s | %s | %s |\n", s.Name, s.DocsURL(), s.Type, req, def, sec,
			strings.ReplaceAll(s.Description, "|", "\\|"))
	}
	return b.String()
}
