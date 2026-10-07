package toolcli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// topOrder is the order of a tool.yaml's top-level keys: identity, what it
// does, configuration, runtime needs, how it runs.
var topOrder = []string{"apiVersion", "name", "version", "description", "publisher", "license", "engine", "presentation",
	"class", "modes", "tier", "implements", "consumes", "produces", "input", "config", "permissions", "resources",
	"safety", "features", "run", "selftest", "protocol", "sdk", "deprecated"}

// toYAML writes a JSON-like value as block YAML. Scalars are written as
// JSON (valid YAML); keys are ordered by topOrder at the top, sorted below.
func toYAML(v map[string]any, indent int) string {
	var b strings.Builder
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, c string) int {
		ia, ic := slices.Index(topOrder, a), slices.Index(topOrder, c)
		if indent == 0 && ia >= 0 && ic >= 0 {
			return ia - ic
		}
		if indent == 0 && (ia >= 0) != (ic >= 0) {
			if ia >= 0 {
				return -1
			}
			return 1
		}
		return strings.Compare(a, c)
	})
	pad := strings.Repeat("  ", indent)
	for _, k := range keys {
		writeValue(&b, pad, yamlKey(k)+":", v[k], indent)
	}
	return b.String()
}

func writeValue(b *strings.Builder, pad, prefix string, val any, indent int) {
	switch x := val.(type) {
	case map[string]any:
		if len(x) == 0 {
			fmt.Fprintf(b, "%s%s {}\n", pad, prefix)
			return
		}
		fmt.Fprintf(b, "%s%s\n%s", pad, prefix, toYAML(x, indent+1))
	case []any:
		if len(x) == 0 {
			fmt.Fprintf(b, "%s%s []\n", pad, prefix)
			return
		}
		if allScalars(x) {
			parts := make([]string, len(x))
			for i, e := range x {
				parts[i] = scalar(e)
			}
			fmt.Fprintf(b, "%s%s [%s]\n", pad, prefix, strings.Join(parts, ", "))
			return
		}
		fmt.Fprintf(b, "%s%s\n", pad, prefix)
		for _, e := range x {
			m, ok := e.(map[string]any)
			if !ok {
				fmt.Fprintf(b, "%s  - %s\n", pad, scalar(e))
				continue
			}
			body := toYAML(m, indent+2)
			lines := strings.SplitAfter(body, "\n")
			fmt.Fprintf(b, "%s  - %s", pad, strings.TrimPrefix(lines[0], strings.Repeat("  ", indent+2)))
			for _, l := range lines[1:] {
				b.WriteString(l)
			}
		}
	default:
		fmt.Fprintf(b, "%s%s %s\n", pad, prefix, scalar(x))
	}
}

func allScalars(xs []any) bool {
	for _, x := range xs {
		switch x.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

// plainRE is a string YAML reads back as the same string without quotes.
var plainRE = regexp.MustCompile(`^[A-Za-z_./][A-Za-z0-9_./@-]*$`)

// yamlWords are plain words YAML would read as something else.
var yamlWords = []string{"true", "false", "null", "yes", "no", "on", "off", "y", "n", "~"}

func scalar(v any) string {
	if s, ok := v.(string); ok && plainRE.MatchString(s) && !slices.Contains(yamlWords, strings.ToLower(s)) {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// yamlKey quotes a key that is not a plain word.
func yamlKey(k string) string {
	for _, r := range k {
		if !(r == '_' || r == '-' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return scalar(k)
		}
	}
	return k
}
