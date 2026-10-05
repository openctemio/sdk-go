package core

// Structured policy refusals (api research/25 §3.6 and D8 in
// openctemio/openctem): a command a policy refused is reported with the
// layer and rule that refused it, so the platform can re-queue routed work
// to another sensor and never offer it to this one again. The failure text
// stays as before ("refused by local policy: <rule>: <detail>"), which older
// platforms parse.

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

// Refusal layers (the closed set the platform accepts).
const (
	RefusalLayerBuiltin          = "builtin"
	RefusalLayerLocal            = "local"
	RefusalLayerManaged          = "managed"
	RefusalLayerScope            = "scope"
	RefusalLayerPlatformToolGate = "platform_tool_gate"
)

// RefusalRuleToolsAllowed is the rule of a command refused by the platform's
// own tool policy (ErrToolNotAllowed, api RFC-033 §6.12).
const RefusalRuleToolsAllowed = "tools.allowed"

// MaxRefusalDetail bounds a refusal's detail.
const MaxRefusalDetail = 512

// Refusal is why a policy refused a command: the layer (RefusalLayer*), the
// rule (a policy key: "tools.allow", "allow_interactsh", "kill_switch") and
// a short detail.
type Refusal struct {
	Layer  string `json:"layer"`
	Rule   string `json:"rule"`
	Detail string `json:"detail,omitempty"`
}

var refusalRuleRE = regexp.MustCompile(`^[a-z][a-z_.]{0,63}$`)

// RefusalOf returns the structured refusal of err, or nil when err is not a
// policy refusal: a *LocalPolicyError (its layer, "local" when unset) or
// ErrToolNotAllowed (the platform's tool gate). The values are bounded:
// a rule outside the platform's pattern becomes "unknown", the detail loses
// control and bidi characters and is cut at MaxRefusalDetail bytes.
func RefusalOf(err error) *Refusal {
	if err == nil {
		return nil
	}
	var lpe *LocalPolicyError
	switch {
	case errors.As(err, &lpe):
		layer := lpe.Layer
		if layer == "" {
			layer = RefusalLayerLocal
		}
		return newRefusal(layer, lpe.Rule, lpe.Detail)
	case errors.Is(err, ErrToolNotAllowed):
		return newRefusal(RefusalLayerPlatformToolGate, RefusalRuleToolsAllowed, err.Error())
	}
	return nil
}

func newRefusal(layer, rule, detail string) *Refusal {
	switch layer {
	case RefusalLayerBuiltin, RefusalLayerLocal, RefusalLayerManaged, RefusalLayerScope, RefusalLayerPlatformToolGate:
	default:
		layer = RefusalLayerLocal
	}
	if !refusalRuleRE.MatchString(rule) {
		rule = "unknown"
	}
	return &Refusal{Layer: layer, Rule: rule, Detail: cleanRefusalDetail(detail)}
}

// cleanRefusalDetail drops control and bidi-override characters and bounds
// the text (valid UTF-8 is kept whole).
func cleanRefusalDetail(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == unicode.ReplacementChar {
			continue
		}
		if b.Len()+len(string(r)) > MaxRefusalDetail {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
