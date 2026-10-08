package tool

import (
	"regexp"
	"strings"
)

// ArgForm is how a {{config.<key>}} placeholder of an exec argv expands.
type ArgForm int

// Forms of a config placeholder.
const (
	// ArgScalar, {{config.k}}: the value ("" when the key is not set).
	ArgScalar ArgForm = iota
	// ArgOptional, {{config.k?}}: the value; the whole argv element is
	// left out when the key is not set, empty or false.
	ArgOptional
	// ArgList, {{config.k...}}: an array key. As the whole element, one
	// argument per item; inside a larger element, the items joined with
	// commas. Left out when the list is empty or not set.
	ArgList
	// ArgSwitch, {{config.k?:-flag}}: a boolean key. The whole element
	// becomes the literal flag when the key is true and is left out
	// otherwise.
	ArgSwitch
)

var (
	configArgRE = regexp.MustCompile(`^config\.([a-z][a-z0-9_]{0,63})(\?|\.\.\.|\?:(--?[A-Za-z0-9][A-Za-z0-9_-]{0,63}))?$`)
	argvPHRE    = regexp.MustCompile(`\{\{\s*([^{}]*?)\s*\}\}`)
)

// ConfigArg parses a placeholder name of the config family ("config.k",
// "config.k?", "config.k...", "config.k?:-x"): its key, form and, for a
// switch, the flag. ok is false for any other name.
func ConfigArg(name string) (key string, form ArgForm, flag string, ok bool) {
	m := configArgRE.FindStringSubmatch(strings.TrimSpace(name))
	if m == nil {
		return "", 0, "", false
	}
	switch m[2] {
	case "":
		return m[1], ArgScalar, "", true
	case "?":
		return m[1], ArgOptional, "", true
	case "...":
		return m[1], ArgList, "", true
	default:
		return m[1], ArgSwitch, m[3], true
	}
}

// ArgvPlaceholders returns the placeholder names in an argv element.
func ArgvPlaceholders(element string) []string {
	var out []string
	for _, m := range argvPHRE.FindAllStringSubmatch(element, -1) {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}
