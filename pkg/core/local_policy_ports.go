package core

// ports.allow (api RFC-040 §5.7): the sensor owner's list of destination
// ports, a limit the platform cannot widen. A job can name ports in more
// places than its config: the tenant's and the sensor's settings layers,
// the capability's standard params, and any key a tool's schema calls its
// port list. Admission (checkJobPorts) reads every one of them from the
// payload; the executor checks the settings the tool will really run with
// once more (CheckResolvedPorts), defaults included; the egress forwarder
// refuses a connection to any other port (AllowedPorts).
//
// Which settings name ports is declared by the tool where it can be: a
// tool's manifest maps the capability's port_list and top_n standard
// params onto its own config keys (PortSettingsProvider). The settings
// schema itself has no marker for a port setting, so for a setting nothing
// declares, the key's name decides (portKeyKind). A tool that calls its
// port list something else must declare the mapping in its manifest.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/openctemio/contract/capability"
)

// PortSettingKind says how a tool setting names ports.
type PortSettingKind int

const (
	// PortSettingNone: the setting does not name ports.
	PortSettingNone PortSettingKind = iota
	// PortSettingList: a port number or a list ("80,443,8000-8100", a
	// number, or a list of them) the tool scans.
	PortSettingList
	// PortSettingTopN: the tool scans its own N most common ports; the sdk
	// cannot know which ports those are.
	PortSettingTopN
)

// PortSettingsProvider is a Scanner that knows which of its settings name
// ports: the config keys its tool manifest maps the capability's port_list
// and top_n standard params onto, wherever they are named. A wrapper around
// such a scanner should forward it.
type PortSettingsProvider interface {
	PortSettings() map[string]PortSettingKind
}

// topPortKeys are the settings that make a tool scan its own "top N" port
// list instead of a list the job names (naabu "top_ports", the standard
// param "top_n").
var topPortKeys = []string{"top_ports", "top_n"}

// PortParamKind is how a capability's standard param named name, of type
// t, names ports: a port_list param is a list, top_n is a top-N count.
func PortParamKind(name string, t capability.ParamType) PortSettingKind {
	switch {
	case t == capability.ParamPortList:
		return PortSettingList
	case slices.Contains(topPortKeys, name):
		return PortSettingTopN
	}
	return PortSettingNone
}

// portExcludeTokens mark a list that narrows a scan, not one that names
// ports to scan: "exclude_ports" never asks for more than the job's ports.
var portExcludeTokens = []string{"exclude", "excluded", "skip", "ignore", "ignored", "deny", "denied", "except"}

// portKeyKind is how a setting nothing declares names ports, by its name
// (the last segment of a group's "group.key"): "ports", "port_range",
// "tcp_ports" and "port" are port lists, "top_ports" and "top_n" (and
// names with "top" and "ports") are top-N counts. A name that is only
// similar ("support", "proxy_port") is not.
func portKeyKind(key string) PortSettingKind {
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		key = key[i+1:]
	}
	tokens := portKeyTokens(key)
	key = strings.Join(tokens, "_")
	if slices.Contains(topPortKeys, key) {
		return PortSettingTopN
	}
	has := func(words ...string) bool {
		return slices.ContainsFunc(tokens, func(t string) bool { return slices.Contains(words, t) })
	}
	switch {
	case has(portExcludeTokens...):
		return PortSettingNone
	case has("top", "topports", "topport") && has("port", "ports", "topports", "topport"):
		return PortSettingTopN
	case key == "port", has("ports"), has(joinedPortLists...), has("port") && has("range", "ranges", "list", "spec"):
		return PortSettingList
	}
	return PortSettingNone
}

// joinedPortLists are port-list words written as one ("portrange",
// "tcpports"). Only these exact words: a word that merely ends in "ports"
// ("supports", "exports", "reports") is not a port list.
var joinedPortLists = []string{"portrange", "portranges", "portlist", "portspec", "tcpports", "udpports", "sctpports", "scanports"}

// portKeyTokens splits a setting name into lower-case words at '_', '-'
// and ' ', and where the case changes the way camelCase and PascalCase
// names are written: "topPorts" and "top_ports" are both [top ports],
// "TCPPorts" is [tcp ports].
func portKeyTokens(key string) []string {
	var tokens []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(key)
	for i, r := range runes {
		if r == '_' || r == '-' || r == ' ' {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(cur) > 0 {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			// fooBar | FOOBar (the last capital of a run starts a word)
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return tokens
}

// portSettingKind is the kind of the setting key: what the tool declared,
// else what its name says.
func portSettingKind(key string, declared map[string]PortSettingKind) PortSettingKind {
	if k, ok := declared[key]; ok && k != PortSettingNone {
		return k
	}
	return portKeyKind(key)
}

// maxPortConfigDepth bounds how deep a config or layer is searched for
// port settings; a schema's groups are one level deep.
const maxPortConfigDepth = 4

// offSwitch reports whether v is false: a setting that is switched off
// (a boolean "scan_ports") asks for no ports. A switch that is on is a
// request for the tool's own list, which cannot be checked.
func offSwitch(v any) bool {
	b, ok := v.(bool)
	return ok && !b
}

// shortValue is a platform-supplied value as a refusal quotes it.
func shortValue(v any) string {
	return truncateBytes(fmt.Sprint(v), 64)
}

// portSpecOf reads a setting value as a port list: a string, a number or a
// list of them (joined by commas).
func portSpecOf(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case []string:
		return strings.Join(x, ","), true
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if _, nested := e.([]any); nested {
				return "", false
			}
			s, ok := portSpecOf(e)
			if !ok {
				return "", false
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ","), true
	}
	return "", false
}

func (lp *LocalPolicy) checkPort(port int) error {
	if lp.ports == nil {
		return nil
	}
	for _, r := range lp.ports {
		if port >= r.lo && port <= r.hi {
			return nil
		}
	}
	return refuse("ports.allow", "port %d is not in %s", port, lp.portsText)
}

// checkPortValue checks a port list a job or a tool's settings carry: a port
// number or a list such as "80,443,8000-8100", every port of which
// ports.allow must allow. A value the policy cannot read ("top-100",
// "full") is refused. label names where the value is ("the job's ports
// setting").
func (lp *LocalPolicy) checkPortValue(label string, v any) error {
	spec, ok := portSpecOf(v)
	if !ok {
		return refuse("ports.allow", "%s %s cannot be checked against the policy", label, shortValue(v))
	}
	ranges, err := parseJobPorts(spec)
	if err != nil {
		return refuse("ports.allow", "%s %q cannot be checked against the policy", label, truncateBytes(spec, 64))
	}
	for _, r := range ranges {
		for p := r.lo; p <= r.hi; p++ {
			if err := lp.checkPort(p); err != nil {
				return refuse("ports.allow", "%s %q includes port %d, which is not in %s", label, truncateBytes(spec, 64), p, lp.portsText)
			}
		}
	}
	return nil
}

// parseJobPorts reads a port list a job names, more strictly than the
// policy file: every number is plain decimal digits without a sign or a
// leading zero, so the sdk and the tool read the same port ("0022" is 22
// here, but 18 to a tool that reads a leading zero as octal).
func parseJobPorts(spec string) ([]portRange, error) {
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		if !canonicalPort(strings.TrimSpace(lo)) || (isRange && !canonicalPort(strings.TrimSpace(hi))) {
			return nil, fmt.Errorf("%q is not a plain port number or range", part)
		}
	}
	return parsePorts(spec)
}

// canonicalPort reports whether s is a port number written plainly: ASCII
// digits, no sign, no leading zero.
func canonicalPort(s string) bool {
	if s == "" || s[0] == '0' {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// refuseTopN is the refusal of a request for a tool's own top-N port list:
// the sdk does not know a tool's list, so it cannot prove every port of it
// is allowed, and the list would otherwise run outside the operator's
// allow-list (fail closed). An operator who wants top-N scans lists those
// ports in ports.allow and the platform names them.
func (lp *LocalPolicy) refuseTopN(label string, v any) error {
	return refuse("ports.allow", "%s (%s) asks the tool to pick the ports, which cannot be checked against %s; name the ports in the job's ports setting",
		label, shortValue(v), lp.portsText)
}

// portSource is a config or settings layer of a job, and whose it is ("job's").
type portSource struct {
	what string
	cfg  map[string]any
}

// checkJobPorts applies ports.allow to everything a job's payload says
// about ports: its config, the older scanner_config, the tenant's and the
// sensor's settings layers (which reach the tool's settings like config
// does), and the capability's standard params. A port-scanning capability
// that names no ports is refused too: the tool would scan its default list.
func (lp *LocalPolicy) checkJobPorts(job *policyJob) error {
	sources := []portSource{{"job's", job.Config}, {"job's", job.ScannerConfig}}
	if l := job.SettingsLayers; l != nil {
		sources = append(sources, portSource{"tenant settings layer's", l.Tenant}, portSource{"sensor settings layer's", l.Sensor})
	}
	named := false
	for _, s := range sources {
		n, err := lp.checkPortConfig(s.what, "", s.cfg, 0)
		if err != nil {
			return err
		}
		named = named || n
	}
	n, err := lp.checkPortParams(job.Capability, job.Params)
	if err != nil {
		return err
	}
	if !named && !n && isPortScanCapability(job.Capability) {
		return lp.refuseUnnamedPorts(job.Capability)
	}
	return nil
}

// isPortScanCapability reports whether ref names the port-scan capability,
// whose tools scan their own default ports when the job names none.
func isPortScanCapability(ref string) bool {
	id, _, ok := capability.ParseRef(strings.TrimSpace(ref))
	return ok && id == "scan.ports"
}

// refuseUnnamedPorts is the refusal of a port scan that names no ports.
func (lp *LocalPolicy) refuseUnnamedPorts(ref string) error {
	return refuse("ports.allow", "%s scans ports but the job names none: name the ports in the job; the tool's default list cannot be checked against the local policy's ports.allow (%s)",
		truncateBytes(ref, 64), lp.portsText)
}

// checkPortConfig checks the port settings of one config or settings layer
// (what says whose it is; prefix is the group a nested map is in). It
// reports whether a port list was named and passed. A null value is no
// request, except for a list, which is not readable and so refused as it
// always was.
func (lp *LocalPolicy) checkPortConfig(what, prefix string, cfg map[string]any, depth int) (named bool, err error) {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, path := cfg[k], prefix+k
		if group, ok := v.(map[string]any); ok {
			if depth >= maxPortConfigDepth {
				return false, lp.refuseDeep(what)
			}
			n, err := lp.checkPortConfig(what, path+".", group, depth+1)
			if err != nil {
				return false, err
			}
			named = named || n
			continue
		}
		if list, ok := v.([]any); ok && portKeyKind(k) == PortSettingNone {
			// A list of objects (services: [{port: 22}]) names ports in
			// its elements.
			n, err := lp.checkPortArray(what, path, list, depth)
			if err != nil {
				return false, err
			}
			named = named || n
			continue
		}
		if offSwitch(v) {
			continue
		}
		label := "the " + what + " " + path + " setting"
		switch portKeyKind(k) {
		case PortSettingList:
			if err := lp.checkPortValue(label, v); err != nil {
				return false, err
			}
			named = true
		case PortSettingTopN:
			if v != nil {
				return false, lp.refuseTopN(label, v)
			}
		}
	}
	return named, nil
}

// refuseDeep is the refusal of settings nested past maxPortConfigDepth.
func (lp *LocalPolicy) refuseDeep(what string) error {
	return refuse("ports.allow", "the job's %s settings are nested deeper than %d levels and cannot be checked against the policy", what, maxPortConfigDepth)
}

// checkPortArray checks the objects (and lists of them) in the list a
// setting path holds, one level deeper than the setting, within the same
// depth bound as groups. Scalars in a list under a key that names no ports
// are not port requests.
func (lp *LocalPolicy) checkPortArray(what, path string, list []any, depth int) (named bool, err error) {
	for i, e := range list {
		var n bool
		switch x := e.(type) {
		case map[string]any:
			if depth >= maxPortConfigDepth {
				return false, lp.refuseDeep(what)
			}
			n, err = lp.checkPortConfig(what, fmt.Sprintf("%s[%d].", path, i), x, depth+1)
		case []any:
			if depth >= maxPortConfigDepth {
				return false, lp.refuseDeep(what)
			}
			n, err = lp.checkPortArray(what, fmt.Sprintf("%s[%d]", path, i), x, depth+1)
		}
		if err != nil {
			return false, err
		}
		named = named || n
	}
	return named, nil
}

// paramKind is how the param name of capability ref names ports. A param
// "ports" is a port list even for a capability the catalog does not know.
func paramKind(ref, name string) PortSettingKind {
	var t capability.ParamType
	if c, known := capability.Lookup(ref); known {
		if p, ok := c.Param(name); ok {
			t = p.Type
		}
	}
	if k := PortParamKind(name, t); k != PortSettingNone {
		return k
	}
	if name == "ports" {
		return PortSettingList
	}
	return PortSettingNone
}

// namesPortParam reports whether a capability job's standard params name a
// port list (a non-null value of a port_list param).
func namesPortParam(ref string, params map[string]json.RawMessage) bool {
	for name, raw := range params {
		if raw = bytes.TrimSpace(raw); len(raw) > 0 && string(raw) != "null" && paramKind(ref, name) == PortSettingList {
			return true
		}
	}
	return false
}

// checkPortParams applies ports.allow to the standard params of a
// capability job and reports whether a port list was named and passed. A
// param is a port list when the capability's catalog entry types it
// port_list (the manifest maps it onto the tool's ports key), or, for a
// capability the catalog does not know, when it is named "ports"; "top_n"
// and "top_ports" ask the tool to pick the ports and are refused. A null
// value is no request.
func (lp *LocalPolicy) checkPortParams(ref string, params map[string]json.RawMessage) (named bool, err error) {
	names := make([]string, 0, len(params))
	for n := range params {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := bytes.TrimSpace(params[name])
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		label := "the job's " + name + " param"
		switch paramKind(ref, name) {
		case PortSettingTopN:
			return false, refuse("ports.allow", "%s (%s) asks the tool to pick the ports, which cannot be checked against %s; name the ports in the job's ports param",
				label, truncateBytes(string(raw), 64), lp.portsText)
		case PortSettingList:
			var v any
			if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&v); err != nil {
				return false, refuse("ports.allow", "%s cannot be checked against the policy", label)
			}
			if err := lp.checkPortValue(label, v); err != nil {
				return false, err
			}
			named = true
		}
	}
	return named, nil
}

// CheckResolvedPorts applies ports.allow to the settings a tool is about to
// run with, every layer and the tool's defaults resolved (ts; nil when the
// tool has none). It is the executor's second line behind admission: a
// setting reaches the tool from a layer, a default or a manifest mapping
// admission cannot always read from the payload. A port list must lie
// inside ports.allow; a top-N count set by any layer is refused, and one
// that is only the tool's default is refused unless the job names a port
// list (paramsNamePorts, or a list among the settings), which the tool
// scans instead. A job of a port-scanning capability that names no list at
// all is refused. declared are the settings the tool says name ports
// (PortSettingsProvider); the others are told by their names.
func (lp *LocalPolicy) CheckResolvedPorts(ts *ToolSettings, declared map[string]PortSettingKind, capabilityRef string, paramsNamePorts bool) error {
	if !lp.Present() || lp.ports == nil {
		return nil
	}
	values := ts.Values()
	keys := ts.Keys()
	named := paramsNamePorts
	var defaultTopN string
	for _, k := range keys {
		v := values[k]
		if offSwitch(v) {
			continue
		}
		switch portSettingKind(k, declared) {
		case PortSettingList:
			if spec, ok := portSpecOf(v); v == nil || (ok && strings.TrimSpace(spec) == "") {
				continue // no list: an optional list the layers left empty
			}
			if err := lp.checkPortValue(fmt.Sprintf("the resolved %s setting (%s)", k, ts.Source(k)), v); err != nil {
				return err
			}
			named = true
		case PortSettingTopN:
			if v == nil {
				continue
			}
			if ts.Source(k) != SettingSourceDefault {
				return lp.refuseTopN(fmt.Sprintf("the resolved %s setting (%s)", k, ts.Source(k)), v)
			}
			defaultTopN = k
		}
	}
	if !named && defaultTopN != "" {
		return refuse("ports.allow", "the tool's default %s setting asks it to pick the ports, which cannot be checked against %s; name the ports in the job's ports setting",
			defaultTopN, lp.portsText)
	}
	if !named && isPortScanCapability(capabilityRef) {
		return lp.refuseUnnamedPorts(capabilityRef)
	}
	return nil
}

// checkResolvedJobPorts is CheckResolvedPorts for a scan command about to
// run scanner with the settings ts resolved under schema. A tool that
// resolved no settings still runs with its schema's defaults.
func checkResolvedJobPorts(lp *LocalPolicy, schema *SettingsSchema, ts *ToolSettings, scanner Scanner, p *ScanCommandPayload) error {
	if !lp.Present() || lp.ports == nil {
		return nil
	}
	if ts == nil && schema != nil {
		ts, _ = schema.Resolve()
	}
	var declared map[string]PortSettingKind
	if pp, ok := scanner.(PortSettingsProvider); ok {
		declared = pp.PortSettings()
	}
	ref := p.Capability
	if ps, ok := scanner.(PortScanImplementer); ok && ps.ImplementsPortScan() && !isPortScanCapability(ref) {
		// A port scanner scans its default ports whatever capability the
		// job names, or when it names none.
		ref = "scan.ports"
	}
	return lp.CheckResolvedPorts(ts, declared, ref, namesPortParam(p.Capability, p.Params))
}

// PortScanImplementer is a Scanner that says whether it is a port scanner:
// its tool manifest lists the scan.ports capability among the ones it
// implements. Under ports.allow such a tool's job must name its ports
// whatever capability the job names (or none): it would otherwise scan the
// tool's default list. A wrapper around such a scanner should forward it.
type PortScanImplementer interface {
	ImplementsPortScan() bool
}

// AllowedPorts returns the destination ports ports.allow allows, ascending,
// for the egress forwarder (egress.Scope.Ports); nil when every port is
// allowed (no ports.allow, or it names all of them).
func (lp *LocalPolicy) AllowedPorts() []int {
	if !lp.Present() || lp.ports == nil {
		return nil
	}
	var allowed [65536]bool
	n := 0
	for _, r := range lp.ports {
		for p := r.lo; p <= r.hi; p++ {
			if !allowed[p] {
				allowed[p] = true
				n++
			}
		}
	}
	if n >= 65535 {
		return nil
	}
	out := make([]int, 0, n)
	for p := 1; p <= 65535; p++ {
		if allowed[p] {
			out = append(out, p)
		}
	}
	return out
}
