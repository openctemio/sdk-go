package tool

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/capability"
)

// Everything here only words error messages: it never changes what a
// manifest accepts. Suggestions come from closed vocabularies (the
// taxonomy, CTIS types, the manifest's own keys); input echoed back is
// quoted with %q and truncated, so a hostile descriptor cannot inject
// terminal control characters.

const maxEcho = 64

// echo quotes s for a message, cut to maxEcho bytes.
func echo(s string) string {
	if len(s) > maxEcho {
		s = strings.ToValidUTF8(s[:maxEcho], "") + "..."
	}
	return fmt.Sprintf("%q", s)
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

// nearest returns up to max candidates close to word: within an edit
// distance of a third of the longer word (at least 2), or sharing a prefix
// of at least 4 bytes. Closest first, ties alphabetical.
func nearest(word string, candidates []string, max int) []string {
	type scored struct {
		s string
		d int
	}
	var got []scored
	for _, c := range candidates {
		d := levenshtein(word, c)
		limit := max3(len(word), len(c)) / 3
		if limit < 2 {
			limit = 2
		}
		if d <= limit || (len(word) >= 4 && len(c) >= 4 && (strings.HasPrefix(c, word[:4]) || strings.HasPrefix(word, c[:4]))) {
			got = append(got, scored{c, d})
		}
	}
	sort.SliceStable(got, func(i, j int) bool {
		if got[i].d != got[j].d {
			return got[i].d < got[j].d
		}
		return got[i].s < got[j].s
	})
	var out []string
	for _, g := range got {
		if len(out) == max {
			break
		}
		if !slices.Contains(out, g.s) {
			out = append(out, g.s)
		}
	}
	return out
}

func max3(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func quoteAll(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, ", ")
}

// unknownCapabilityMessage explains a capability reference that is not in
// the taxonomy: the majors that exist, the nearest ids, or the docs.
func unknownCapabilityMessage(ref string) string {
	const docs = " (see docs/capabilities.md of ctis)"
	base := echo(ref) + " is not in the capability taxonomy"
	id, major, ok := capability.ParseRef(ref)
	if !ok {
		return base + docs
	}
	var majors []string
	var ids []string
	seen := map[string]bool{}
	for _, c := range capability.All() {
		if c.ID == id {
			majors = append(majors, fmt.Sprintf("%d", c.Major))
		}
		if !seen[c.ID] {
			seen[c.ID] = true
			ids = append(ids, c.ID)
		}
	}
	if len(majors) > 0 {
		return fmt.Sprintf("%s: %s has major %s, not %d", base, id, strings.Join(majors, ", "), major)
	}
	if near := nearest(id, ids, 3); len(near) > 0 {
		refs := make([]string, 0, len(near))
		for _, n := range near {
			if c, ok := capability.Lookup(n); ok {
				refs = append(refs, c.Ref())
			}
		}
		if len(refs) > 0 {
			return base + "; did you mean " + strings.Join(refs, " or ") + "?"
		}
	}
	return base + docs
}

// assetAliases maps words authors reach for to the CTIS asset type.
var assetAliases = map[string]string{
	"url":   "http_service (or discovered_url, website)",
	"ip":    "ip_address",
	"port":  "open_port",
	"repo":  "repository",
	"image": "container",
}

func assetTypeNames() []string {
	all := ctis.AllAssetTypes()
	out := make([]string, len(all))
	for i, t := range all {
		out[i] = string(t)
	}
	return out
}

func findingTypeNames() []string {
	all := ctis.AllFindingTypes()
	out := make([]string, len(all))
	for i, t := range all {
		out[i] = string(t)
	}
	return out
}

const maxListedTypes = 16

// unknownTypeMessage words an unknown CTIS asset or finding type.
func unknownTypeMessage(what, typ string, allowed []string) string {
	msg := "unknown CTIS " + what + " type " + echo(typ)
	var hint string
	if a, ok := assetAliases[strings.ToLower(typ)]; ok && what == "asset" {
		hint = "use " + a
	} else if near := nearest(strings.ToLower(typ), allowed, 2); len(near) > 0 {
		hint = "did you mean " + quoteAll(near) + "?"
	}
	if hint != "" {
		msg += "; " + hint
	}
	if len(allowed) <= maxListedTypes {
		msg += " (allowed: " + strings.Join(allowed, ", ") + ")"
	}
	return msg
}

// misplacedKeys maps a top-level key authors put in the wrong place to
// where it belongs.
var misplacedKeys = map[string]string{
	"timeout":      "/resources/timeout",
	"memory":       "/resources/memory",
	"cpu":          "/resources/cpu",
	"network":      "/permissions/network",
	"credentials":  "/permissions/credentials",
	"filesystem":   "/permissions/filesystem",
	"argv":         "/run/argv",
	"profile":      "/run/profile",
	"output":       "/run/output",
	"capability":   "/implements/0/capability",
	"display_name": "/presentation/display_name",
	"icon":         "/presentation/icon",
	"category":     "/presentation/category",
}

// manifestDecodeError turns an error of the strict JSON decode of a
// manifest into one that names the key and the fix. doc is the decoded
// document, used to find where an unknown key sits.
func manifestDecodeError(err error, doc any) ManifestError {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return typeMismatch(te)
	}
	const prefix = "json: unknown field "
	if rest, ok := strings.CutPrefix(err.Error(), prefix); ok {
		var key string
		if json.Unmarshal([]byte(rest), &key) == nil {
			return unknownKey(key, doc)
		}
	}
	return ManifestError{Message: err.Error()}
}

func unknownKey(key string, doc any) ManifestError {
	ptr, known := locateUnknown(doc, reflect.TypeOf(Manifest{}), "", key)
	if known == nil {
		// not found by walking (a type that decodes itself): name the key only
		return ManifestError{Message: "unknown key " + echo(key)}
	}
	at := ptr + "/" + key
	msg := "unknown key"
	if ptr == "" {
		if to, ok := misplacedKeys[key]; ok {
			return ManifestError{Path: clipPath(at), Message: msg + "; did you mean " + to + "?"}
		}
	}
	if near := nearest(key, known, 2); len(near) > 0 {
		sug := make([]string, len(near))
		for i, n := range near {
			sug[i] = ptr + "/" + n
		}
		return ManifestError{Path: clipPath(at), Message: msg + "; did you mean " + strings.Join(sug, " or ") + "?"}
	}
	return ManifestError{Path: clipPath(at), Message: msg}
}

// clipPath keeps a pointer built from document keys short and printable.
func clipPath(p string) string {
	q := echo(p)
	return q[1 : len(q)-1]
}

var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

func jsonName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return f.Name
	}
	return name
}

func structJSONKeys(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		if n := jsonName(f); n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// locateUnknown walks doc along the manifest's Go types and returns the
// pointer of the first object (keys in sorted order, as the decoder sees
// them) that holds key unknown to its type, with that type's known keys.
func locateUnknown(v any, t reflect.Type, ptr, key string) (string, []string) {
	t = deref(t)
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return "", nil
	}
	switch val := v.(type) {
	case map[string]any:
		if t.Kind() == reflect.Map {
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if p, kn := locateUnknown(val[k], t.Elem(), ptr+"/"+k, key); kn != nil {
					return p, kn
				}
			}
			return "", nil
		}
		if t.Kind() != reflect.Struct {
			return "", nil
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.IsExported() && jsonName(f) != "" {
				fields[jsonName(f)] = f.Type
			}
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ft, ok := fields[k]
			if !ok {
				if k == key {
					return ptr, structJSONKeys(t)
				}
				continue
			}
			if p, kn := locateUnknown(val[k], ft, ptr+"/"+k, key); kn != nil {
				return p, kn
			}
		}
	case []any:
		if t.Kind() == reflect.Slice {
			for i, e := range val {
				if p, kn := locateUnknown(e, t.Elem(), fmt.Sprintf("%s/%d", ptr, i), key); kn != nil {
					return p, kn
				}
			}
		}
	}
	return "", nil
}

// typeMismatch words a JSON value of the wrong type.
func typeMismatch(te *json.UnmarshalTypeError) ManifestError {
	ptr, leaf := fieldPointer(reflect.TypeOf(Manifest{}), te.Field)
	if leaf == nil {
		leaf = te.Type
	}
	want := jsonTypeWord(leaf)
	msg := "must be " + article(want)
	if want == "string" && (te.Value == "number" || te.Value == "bool") {
		msg += "; quote it"
		if ptr == "/version" {
			msg += ` ("1.0.0")`
		}
	} else if ptr == "/version" {
		msg += ` (semver in quotes, "1.0.0")`
	}
	return ManifestError{Path: ptr, Message: msg}
}

func article(w string) string {
	if w == "array" || w == "object" || w == "integer" {
		return "an " + w
	}
	return "a " + w
}

// jsonTypeWord names the JSON type a Go type decodes from, in plain words.
func jsonTypeWord(t reflect.Type) string {
	if t == nil {
		return "value of another type"
	}
	switch deref(t).Kind() {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Struct, reflect.Map:
		return "object"
	}
	return "value of another type"
}

// fieldPointer converts the decoder's dotted field path (JSON names, no
// array indexes) into a JSON pointer, writing "*" for each array, and
// returns the type of the last field.
func fieldPointer(root reflect.Type, field string) (string, reflect.Type) {
	if field == "" {
		return "", nil
	}
	t := root
	var b strings.Builder
	var last reflect.Type
	for _, seg := range strings.Split(field, ".") {
		t = deref(t)
		for t.Kind() == reflect.Slice {
			b.WriteString("/*")
			t = deref(t.Elem())
		}
		b.WriteString("/" + seg)
		last = nil
		if t.Kind() == reflect.Struct {
			for i := 0; i < t.NumField(); i++ {
				if f := t.Field(i); f.IsExported() && jsonName(f) == seg {
					t, last = f.Type, f.Type
					break
				}
			}
		}
		if last == nil {
			return b.String(), nil
		}
	}
	return b.String(), last
}
