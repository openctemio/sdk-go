package tool

// The contract part of a tool descriptor: which capabilities of the
// OpenCTEM capability taxonomy (github.com/openctemio/ctis/capability) the
// tool implements and how its configuration maps to their standard params,
// how it takes targets, how it presents itself, what engine it wraps and
// what it does to its targets besides reading them.
//
// The capability carries the phase, the tier floor, the typed ports and the
// required output of the act; the tool only names it. A tool cannot declare
// a tier below the floor of a capability it implements, and the platform
// assigns the effective tier (the tool's tier is a request).

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/openctemio/ctis/capability"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sdk"
)

// Implementation is one capability a tool implements.
type Implementation struct {
	// Capability is the capability reference with its major
	// ("scan.ports@1").
	Capability string `json:"capability"`
	// Params maps the capability's standard params this tool accepts to
	// its own config keys. A standard param not listed is one the tool
	// does not take: a workflow node that sets it cannot run this tool.
	Params map[string]ParamMapping `json:"params,omitempty"`
	// OutputShape names which of the capability's accepted output shapes
	// the tool emits, when the capability has several.
	OutputShape string `json:"output_shape,omitempty"`
}

// ParamMapping maps one standard param to a config key, optionally
// narrowing the values the tool supports.
type ParamMapping struct {
	// Key is the top-level config key; empty means the param's own name.
	Key string `json:"key,omitempty"`
	// Values narrows an enum param (or the items of a list param) to the
	// values the tool supports. A value outside makes the tool ineligible
	// for that node; it is never silently dropped.
	Values []string `json:"values,omitempty"`
	// Min and Max narrow an integer param.
	Min *int `json:"min,omitempty"`
	Max *int `json:"max,omitempty"`
}

// ConfigKey is the config key the param maps to.
func (p ParamMapping) ConfigKey(param string) string {
	if p.Key != "" {
		return p.Key
	}
	return param
}

// Batch shapes.
const (
	// BatchOne: one target per task (the default).
	BatchOne = "one"
	// BatchList: a list of targets per task.
	BatchList = "list"
)

// InputSpec is how a tool takes its targets.
type InputSpec struct {
	// Batch is BatchOne (default) or BatchList.
	Batch string `json:"batch,omitempty"`
	// MaxTargets bounds a list task (BatchList only).
	MaxTargets int `json:"max_targets,omitempty"`
}

// Presentation is how the platform shows a tool. Every string is rendered
// as text; the icon is a name from a closed set, never a URL, and the docs
// URL is a link the platform never fetches.
type Presentation struct {
	DisplayName string `json:"display_name,omitempty"`
	Category    string `json:"category,omitempty"`
	Icon        string `json:"icon,omitempty"`
	DocsURL     string `json:"docs_url,omitempty"`
}

// Engine is the program a tool wraps. Its version is probed at run time,
// never trusted from the descriptor.
type Engine struct {
	Name    string `json:"name"`
	License string `json:"license,omitempty"`
	// MinVersion: an older probed engine reports the tool as outdated.
	MinVersion string `json:"min_version,omitempty"`
	// VersionProbe is the argv that prints the engine's version (no
	// shell, no placeholders).
	VersionProbe []string `json:"version_probe,omitempty"`
}

// Safety says what a tool does to its targets beyond reading them.
type Safety struct {
	// RateParam is the integer config key that bounds requests or packets
	// per second; the runtime caps it by the sensor's local policy.
	RateParam string `json:"rate_param,omitempty"`
	// SideEffects the tool may cause. Any entry makes the tool intrusive
	// (tier T2).
	SideEffects []string `json:"side_effects,omitempty"`
	// ExpandsTargets: the tool discovers new targets. They go to the
	// platform as assets; the tool never scans them in the same task.
	ExpandsTargets bool `json:"expands_targets,omitempty"`
}

// Side effects a tool may declare.
const (
	SideEffectIOCInLogs          = "ioc_in_logs"
	SideEffectArtifactsOnTarget  = "artifacts_on_target"
	SideEffectStateChange        = "state_change"
	SideEffectAccountLockout     = "account_lockout"
	SideEffectServiceDisruption  = "service_disruption"
	SideEffectThirdPartyContacts = "third_party_contact"
)

var sideEffects = []string{SideEffectIOCInLogs, SideEffectArtifactsOnTarget, SideEffectStateChange,
	SideEffectAccountLockout, SideEffectServiceDisruption, SideEffectThirdPartyContacts}

// Features are optional protocol features a tool supports.
type Features struct {
	// Retest: the tool can check again what it reported (see Retester).
	Retest bool `json:"retest,omitempty"`
	// Cancel: the tool stops promptly on a cancel message.
	Cancel bool `json:"cancel,omitempty"`
	// WebScope: the tool keeps every request inside the job's web scope
	// (Task.WebScope): it maps the scope onto its own flags, or requests
	// only through Context.HTTP, which enforces it. A job with a web scope
	// is refused for a networked tool that does not declare it.
	WebScope bool `json:"web_scope,omitempty"`
	// Streaming is reserved: feeding records to the next stage while the
	// task runs is not part of protocol v1.
	Streaming bool `json:"streaming,omitempty"`
}

// SDKRequirement is the oldest SDK that understands every key a descriptor
// uses.
type SDKRequirement struct {
	Min string `json:"min,omitempty"`
}

// Deprecation marks a tool version that is being replaced.
type Deprecation struct {
	Since      string `json:"since"`
	ReplacedBy string `json:"replaced_by,omitempty"`
	Message    string `json:"message,omitempty"`
}

// Proxy behaviors.
const (
	// ProxyHonors: the tool sends its traffic through the zone's proxy.
	ProxyHonors = "honors"
	// ProxyIgnores: the tool connects directly; it is ineligible in a zone
	// that requires a proxy.
	ProxyIgnores = "ignores"
)

// Closed sets of the presentation.
var (
	presentationCategories = []string{"network", "dns", "web", "vulnerability", "code", "secrets",
		"dependencies", "container", "cloud", "connector", "import", "other"}
	presentationIcons = []string{"radar", "globe", "network", "server", "link", "search", "bug", "shield",
		"code", "key", "package", "container", "cloud", "plug", "file", "lock", "terminal", "tool"}
)

var (
	spdxRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}( (AND|OR|WITH) [A-Za-z0-9][A-Za-z0-9.+-]{0,63}){0,7}$`)
	shapeRE      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	maxProbeArgv = 8
)

// tierRank orders tiers.
func tierRank(t Tier) int {
	switch t {
	case T0:
		return 0
	case T1:
		return 1
	case T2:
		return 2
	}
	return -1
}

// tierOf is the tier of a rank.
func tierOf(rank int) Tier {
	switch {
	case rank <= 0:
		return T0
	case rank == 1:
		return T1
	}
	return T2
}

// ImplementedCapabilities returns the capabilities the tool implements, in
// declaration order. A reference that does not resolve is skipped
// (Validate refuses it).
func (m Manifest) ImplementedCapabilities() []capability.Capability {
	var out []capability.Capability
	for _, im := range m.Implements {
		if c, ok := capability.Lookup(im.Capability); ok {
			out = append(out, c)
		}
	}
	return out
}

// Implementation returns the implements entry of a capability reference
// ("scan.ports@1").
func (m Manifest) Implementation(ref string) (Implementation, bool) {
	for _, im := range m.Implements {
		if im.Capability == ref {
			return im, true
		}
	}
	return Implementation{}, false
}

// MinimumTier is the lowest tier the tool can be assigned: the highest of
// its declared tier, the tier floors of the capabilities it implements, and
// T2 when it declares a side effect. The platform may assign a higher one;
// never a lower one.
func (m Manifest) MinimumTier() Tier {
	rank := tierRank(m.Tier)
	for _, c := range m.ImplementedCapabilities() {
		rank = max(rank, c.TierFloor)
	}
	if m.Safety != nil && len(m.Safety.SideEffects) > 0 {
		rank = 2
	}
	return tierOf(rank)
}

// Batches reports whether the tool takes a list of targets per task.
func (m Manifest) Batches() bool { return m.Input != nil && m.Input.Batch == BatchList }

// RetestFeature reports whether the tool can retest (features.retest or
// the older top-level retest key).
func (m Manifest) RetestFeature() bool {
	return m.Retest || (m.Features != nil && m.Features.Retest)
}

// validateContract checks the contract keys against the capability
// taxonomy and the config schema.
func (m Manifest) validateContract(add func(p, format string, args ...any), schema *core.SettingsSchema) {
	if len(m.Implements) > maxListItems {
		add("/implements", "more than %d entries", maxListItems)
		return
	}
	var caps []capability.Capability
	for i, im := range m.Implements {
		p := fmt.Sprintf("/implements/%d", i)
		id, major, ok := capability.ParseRef(im.Capability)
		if !ok || major == 0 {
			add(p+"/capability", "must be a capability reference with its major (scan.ports@1)")
			continue
		}
		if slices.IndexFunc(m.Implements, func(o Implementation) bool { return o.Capability == im.Capability }) != i {
			add(p+"/capability", "duplicate")
		}
		c, ok := capability.Lookup(im.Capability)
		if !ok {
			add(p+"/capability", "%s is not in the capability taxonomy (see docs/capabilities.md of ctis)", im.Capability)
			continue
		}
		if c.Status == capability.StatusLater {
			add(p+"/capability", "%s is reserved and cannot be implemented yet", id)
			continue
		}
		if c.Deprecated != nil {
			add(p+"/capability", "%s is deprecated: %s", im.Capability, c.Deprecated.Message)
		}
		if tierRank(m.Tier) >= 0 && tierRank(m.Tier) < c.TierFloor {
			add("/tier", "%s needs at least T%d (its tier floor)", im.Capability, c.TierFloor)
		}
		if im.OutputShape != "" && (!shapeRE.MatchString(im.OutputShape) || !slices.Contains(c.Shapes(), im.OutputShape)) {
			add(p+"/output_shape", "must be one of the shapes of %s: %s", im.Capability, strings.Join(c.Shapes(), ", "))
		}
		validateParamMappings(add, p+"/params", c, im.Params, schema)
		caps = append(caps, c)
	}

	// The legacy capability words: with implements, they may only repeat it.
	if len(m.Implements) > 0 {
		for i, w := range m.Capabilities {
			if !slices.ContainsFunc(m.Implements, func(im Implementation) bool {
				id, _, _ := capability.ParseRef(im.Capability)
				return w == im.Capability || w == id
			}) {
				add(fmt.Sprintf("/capabilities/%d", i), "capabilities is replaced by implements; %q is not implemented", w)
			}
		}
	}

	if len(caps) > 0 {
		if m.Class == TargetScan {
			for i, t := range m.Consumes {
				if !slices.ContainsFunc(caps, func(c capability.Capability) bool { return c.Accepts(t) }) {
					add(fmt.Sprintf("/consumes/%d", i), "%s is not an input of any implemented capability", t)
				}
			}
		}
		for i, k := range m.Produces {
			if !slices.ContainsFunc(caps, func(c capability.Capability) bool { return c.MayEmit(k) }) {
				add(fmt.Sprintf("/produces/%d", i), "%s is not an output of any implemented capability", k)
			}
		}
	}

	m.validateInput(add)
	m.validateSafety(add, schema)
	m.validatePresentation(add)
	m.validateIdentityExtras(add)
}

func validateParamMappings(add func(p, format string, args ...any), p string, c capability.Capability, params map[string]ParamMapping, schema *core.SettingsSchema) {
	names := make([]string, 0, len(params))
	for n := range params {
		names = append(names, n)
	}
	slices.Sort(names) // stable error order
	keys := map[string]string{}
	for _, name := range names {
		pm := params[name]
		pp := p + "/" + name
		std, ok := c.Param(name)
		if !ok {
			add(pp, "%s has no standard param %q", c.Ref(), name)
			continue
		}
		key := pm.ConfigKey(name)
		if other, dup := keys[key]; dup {
			add(pp+"/key", "config key %q is already mapped from %q", key, other)
		}
		keys[key] = name
		var prop *core.SettingProperty
		if schema != nil {
			prop = schema.Property(key)
		}
		if prop == nil || strings.Contains(key, ".") {
			add(pp+"/key", "%q is not a top-level key of the config schema", key)
			continue
		}
		if msg := paramTypeMatches(std.Type, prop); msg != "" {
			add(pp+"/key", "%s", msg)
		}
		if len(pm.Values) > 0 {
			switch {
			case std.Type != capability.ParamString && std.Type != capability.ParamStringList:
				add(pp+"/values", "only string and list params take values")
			case len(std.Enum) == 0:
				add(pp+"/values", "%s is not an enum param", name)
			default:
				for i, v := range pm.Values {
					if !slices.Contains(std.Enum, v) {
						add(fmt.Sprintf("%s/values/%d", pp, i), "%q is not a value of %s", v, name)
					}
				}
			}
		}
		if pm.Min != nil || pm.Max != nil {
			if std.Type != capability.ParamInteger {
				add(pp, "min and max are for integer params")
				continue
			}
			if pm.Min != nil && std.Min != nil && *pm.Min < *std.Min {
				add(pp+"/min", "below the capability's minimum %d", *std.Min)
			}
			if pm.Max != nil && std.Max != nil && *pm.Max > *std.Max {
				add(pp+"/max", "above the capability's maximum %d", *std.Max)
			}
			if pm.Min != nil && pm.Max != nil && *pm.Min > *pm.Max {
				add(pp, "min above max")
			}
		}
	}
}

// paramTypeMatches checks that a config property can hold a standard
// param's values.
func paramTypeMatches(t capability.ParamType, prop *core.SettingProperty) string {
	want := map[capability.ParamType][]string{
		capability.ParamString:     {"string"},
		capability.ParamInteger:    {"integer"},
		capability.ParamBoolean:    {"boolean"},
		capability.ParamStringList: {"array"},
		capability.ParamPortList:   {"string", "array"},
	}[t]
	if !slices.Contains(want, prop.Type) {
		return fmt.Sprintf("config key %q is %s; a %s param needs %s", prop.Name, prop.Type, t, strings.Join(want, " or "))
	}
	return ""
}

func (m Manifest) validateInput(add func(p, format string, args ...any)) {
	in := m.Input
	if in == nil {
		return
	}
	switch in.Batch {
	case "", BatchOne:
		if in.MaxTargets != 0 {
			add("/input/max_targets", "only for batch: list")
		}
	case BatchList:
		if in.MaxTargets < 0 || in.MaxTargets > 100000 {
			add("/input/max_targets", "must be between 0 and 100000")
		}
	default:
		add("/input/batch", "must be one or list")
	}
}

func (m Manifest) validateSafety(add func(p, format string, args ...any), schema *core.SettingsSchema) {
	if p := m.Permissions.Proxy; p != "" {
		switch {
		case p != ProxyHonors && p != ProxyIgnores:
			add("/permissions/proxy", "must be honors or ignores")
		case m.Permissions.Network == NetNone:
			add("/permissions/proxy", "a tool without network has no proxy behavior")
		case p == ProxyIgnores && m.Permissions.Network == NetEgressProxy:
			add("/permissions/proxy", "network egress-proxy needs a tool that honors the proxy")
		}
	}
	if m.Features != nil {
		if m.Features.Streaming {
			add("/features/streaming", "reserved: not part of adapter protocol v1")
		}
		if m.Features.Retest && m.Retest {
			add("/retest", "set features.retest only (retest is its older spelling)")
		}
		if m.Features.Retest && m.Class != TargetScan {
			add("/features/retest", "only target-scan tools retest")
		}
		if m.Features.Retest && m.Run != nil && m.Run.Profile == ProfileExec {
			add("/features/retest", "an exec-profile tool cannot retest (it has no verdict channel)")
		}
	}
	s := m.Safety
	if s == nil {
		return
	}
	if s.RateParam != "" {
		var prop *core.SettingProperty
		if schema != nil {
			prop = schema.Property(s.RateParam)
		}
		if prop == nil || prop.Type != "integer" || strings.Contains(s.RateParam, ".") {
			add("/safety/rate_param", "must name a top-level integer config key")
		}
	}
	checkList(add, "/safety/side_effects", s.SideEffects, func(v string) string {
		if !slices.Contains(sideEffects, v) {
			return "must be one of " + strings.Join(sideEffects, ", ")
		}
		return ""
	})
	if len(s.SideEffects) > 0 && m.Tier != T2 {
		add("/tier", "a tool with side effects is intrusive: declare T2")
	}
	if s.ExpandsTargets && m.Class != TargetScan && m.Class != Connector {
		add("/safety/expands_targets", "only target-scan tools and connectors discover targets")
	}
}

func (m Manifest) validatePresentation(add func(p, format string, args ...any)) {
	pr := m.Presentation
	if pr == nil {
		return
	}
	if msg := checkText(pr.DisplayName, 64); msg != "" {
		add("/presentation/display_name", "%s", msg)
	}
	if pr.Category != "" && !slices.Contains(presentationCategories, pr.Category) {
		add("/presentation/category", "must be one of %s", strings.Join(presentationCategories, ", "))
	}
	if pr.Icon != "" && !slices.Contains(presentationIcons, pr.Icon) {
		add("/presentation/icon", "must be one of %s", strings.Join(presentationIcons, ", "))
	}
	if pr.DocsURL != "" {
		u, err := url.Parse(pr.DocsURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(pr.DocsURL) > 512 {
			add("/presentation/docs_url", "must be an https URL of at most 512 bytes without credentials")
		}
	}
}

func (m Manifest) validateIdentityExtras(add func(p, format string, args ...any)) {
	if msg := checkText(m.Publisher, 64); msg != "" {
		add("/publisher", "%s", msg)
	}
	if m.License != "" && !spdxRE.MatchString(m.License) {
		add("/license", "must be an SPDX license expression")
	}
	if e := m.Engine; e != nil {
		if e.Name == "" || !nameRE.MatchString(e.Name) {
			add("/engine/name", "must match ^[a-z][a-z0-9-]{1,62}$")
		}
		if e.License != "" && !spdxRE.MatchString(e.License) {
			add("/engine/license", "must be an SPDX license expression")
		}
		if e.MinVersion != "" && !versionRE.MatchString(e.MinVersion) {
			add("/engine/min_version", "must be a semantic version")
		}
		if len(e.VersionProbe) > maxProbeArgv {
			add("/engine/version_probe", "more than %d entries", maxProbeArgv)
		}
		for i, a := range e.VersionProbe {
			ptr := fmt.Sprintf("/engine/version_probe/%d", i)
			if i == 0 && slices.Contains(refusedPrograms, strings.ToLower(lastPathElem(a))) {
				add(ptr, "a shell or launcher; run the engine directly")
			}
			if a == "" || len(a) > 256 || strings.ContainsAny(a, "\x00\n\r") || strings.Contains(a, "{{") {
				add(ptr, "must be 1 to 256 bytes, with no line break or placeholder")
			}
		}
	}
	if s := m.SDK; s != nil && s.Min != "" {
		if !versionRE.MatchString(s.Min) {
			add("/sdk/min", "must be a semantic version")
		} else if semverLess(sdk.Version, s.Min) {
			add("/sdk/min", "needs SDK %s; this is %s", s.Min, sdk.Version)
		}
	}
	if d := m.Deprecated; d != nil {
		if !versionRE.MatchString(d.Since) {
			add("/deprecated/since", "must be a semantic version")
		}
		if d.ReplacedBy != "" && !nameRE.MatchString(d.ReplacedBy) {
			add("/deprecated/replaced_by", "must be a tool name")
		}
		if msg := checkText(d.Message, 512); msg != "" {
			add("/deprecated/message", "%s", msg)
		}
	}
}

// checkText refuses control characters and over-long display text.
func checkText(s string, maxLen int) string {
	if len(s) > maxLen {
		return fmt.Sprintf("longer than %d bytes", maxLen)
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.Is(unicode.Bidi_Control, r) {
			return "contains a control character"
		}
	}
	return ""
}

func lastPathElem(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// semverLess reports whether a < b, comparing MAJOR.MINOR.PATCH and
// ignoring pre-release and build suffixes.
func semverLess(a, b string) bool {
	pa, pb := semverParts(a), semverParts(b)
	for i := range 3 {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func semverParts(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out [3]int
	for i, s := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(s)
	}
	return out
}

// autoMapParams fills the param mapping of implements entries that have
// none: a standard param maps to the config key of the same name when its
// type matches. Used by the builder, where parameters and capabilities are
// declared together; a manifest file states its mapping.
func autoMapParams(m Manifest) []Implementation {
	if len(m.Implements) == 0 {
		return m.Implements
	}
	schema, err := m.ConfigSchema()
	if err != nil || schema == nil {
		return m.Implements
	}
	out := slices.Clone(m.Implements)
	for i, im := range out {
		if im.Params != nil {
			continue
		}
		c, ok := capability.Lookup(im.Capability)
		if !ok {
			continue
		}
		for _, p := range c.Params {
			prop := schema.Property(p.Name)
			if prop == nil || paramTypeMatches(p.Type, prop) != "" {
				continue
			}
			if out[i].Params == nil {
				out[i].Params = map[string]ParamMapping{}
			}
			out[i].Params[p.Name] = ParamMapping{}
		}
	}
	return out
}
