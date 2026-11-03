// Package toolrt holds the rules every tool's output passes, shared by the
// tool side (pkg/tool/adapter, pkg/testkit) and the runtime side
// (pkg/sensorkit/toolhost): record validation against CTIS and the
// manifest's produces, sanitization, size and count caps, report assembly
// and provenance stamping. The runtime applies them on its side of the
// process boundary whatever the tool did on its own.
package toolrt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Bounds of one record.
const (
	// MaxString bounds any string in a record (longer ones are cut).
	MaxString = 256 << 10
	// MaxDepth bounds the nesting of a record.
	MaxDepth = 32
	// MaxNodes bounds the values in one record.
	MaxNodes = 100000
	// MaxInfoBytes bounds a report's tool, metadata and properties.
	MaxInfoBytes = 64 << 10
)

// Checker applies the output rules to one task's records. It is safe for
// concurrent use.
type Checker struct {
	m          tool.Manifest
	maxRecords int
	maxBytes   int64

	mu          sync.Mutex
	records     int
	bytes       int64
	capped      bool
	assetIDs    map[string]bool
	findingIDs  map[string]bool
	depIDs      map[string]bool
	endpointIDs map[string]bool
	quarantined map[string]int
	invalid     int
	targets     map[string]bool
	// targetHosts are the host names and addresses of the task's targets.
	targetHosts map[string]bool
	// rules maps the id of each accepted rule to its rule_id.
	rules map[string]string
	// nextAsset numbers the document-local ids the checker gives assets a
	// tool emitted without one.
	nextAsset int
}

// NewChecker returns a checker for m's limits and produces.
func NewChecker(m tool.Manifest) *Checker {
	_, _, maxBytes, maxRecords := m.Resources.Limits()
	return &Checker{m: m, maxRecords: maxRecords, maxBytes: maxBytes,
		assetIDs: map[string]bool{}, findingIDs: map[string]bool{}, depIDs: map[string]bool{}, endpointIDs: map[string]bool{},
		quarantined: map[string]int{}, targets: map[string]bool{}, targetHosts: map[string]bool{}, rules: map[string]string{}}
}

// AllowTarget lets an asset that is one of the task's targets (same type
// and value) through without being in produces: a converter that files
// findings on the scanned target emits it, and it is the task's input,
// not new output.
func (c *Checker) AllowTarget(typ, value string) {
	c.mu.Lock()
	a := ctis.Asset{Type: ctis.AssetType(typ), Value: value}
	a.Value = canonicalValue(a)
	c.targets[typ+"\x00"+a.Value] = true
	if h := assetHost(a); h != "" {
		c.targetHosts[h] = true
	}
	c.mu.Unlock()
}

// AllowTaskTargets allows every target of a task (AllowTarget), its type
// inferred from its value when the task names none.
func (c *Checker) AllowTaskTargets(targets []tool.Target) {
	for _, t := range targets {
		typ := t.Type
		if typ == "" {
			typ = string(tool.InferTargetType(t.Value))
		}
		if typ != "" {
			c.AllowTarget(typ, t.Value)
		}
	}
}

// Stats are what the checker refused.
type Stats struct {
	Records     int            `json:"records"`
	Bytes       int64          `json:"bytes"`
	Capped      bool           `json:"capped,omitempty"`
	Quarantined map[string]int `json:"quarantined,omitempty"`
	Invalid     int            `json:"invalid,omitempty"`
}

// Stats returns a copy of the counters.
func (c *Checker) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	q := make(map[string]int, len(c.quarantined))
	for k, v := range c.quarantined {
		q[k] = v
	}
	if len(q) == 0 {
		q = nil
	}
	return Stats{Records: c.records, Bytes: c.bytes, Capped: c.capped, Quarantined: q, Invalid: c.invalid}
}

// KnowAsset records an asset id the runtime itself added (a target's
// asset), so findings may reference it.
func (c *Checker) KnowAsset(id string) {
	c.mu.Lock()
	c.assetIDs[id] = true
	c.mu.Unlock()
}

// HasAsset reports whether id names an accepted asset.
func (c *Checker) HasAsset(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.assetIDs[id]
}

// AssetJSON checks an asset given as JSON (from an adapter) and returns it
// sanitized.
func (c *Checker) AssetJSON(raw []byte) (ctis.Asset, error) {
	var a ctis.Asset
	if err := Sanitize(raw, &a); err != nil {
		return a, c.reject(err)
	}
	return c.asset(a)
}

// Asset checks a typed asset and returns it sanitized.
func (c *Checker) Asset(a ctis.Asset) (ctis.Asset, error) {
	var out ctis.Asset
	if err := SanitizeValue(a, &out); err != nil {
		return out, c.reject(err)
	}
	return c.asset(out)
}

// TargetAsset checks the asset the runtime adds for a task target (to
// file findings on): it is the task's input, not the tool's output, so it
// need not be in produces; every other check applies.
func (c *Checker) TargetAsset(a ctis.Asset) (ctis.Asset, error) {
	var out ctis.Asset
	if err := SanitizeValue(a, &out); err != nil {
		return out, c.reject(err)
	}
	return c.checkAsset(out)
}

func (c *Checker) asset(a ctis.Asset) (ctis.Asset, error) {
	a.Value = canonicalValue(a)
	c.mu.Lock()
	isTarget := c.targets[string(a.Type)+"\x00"+a.Value]
	// The asset a finding is filed on may be another view of a target (a
	// scanner names the web origin or the service of the host it was
	// given): it is the task's input, not new output, when the tool
	// reports findings and the asset's host is one of the targets' hosts.
	if !isTarget && c.m.ProducesFindings() {
		if h := assetHost(a); h != "" && c.targetHosts[h] {
			isTarget = true
		}
	}
	c.mu.Unlock()
	if !isTarget && !c.m.Declares(tool.KindAsset, string(a.Type)) {
		return a, c.quarantine(tool.KindAsset + ":" + string(a.Type))
	}
	return c.checkAsset(a)
}

func (c *Checker) checkAsset(a ctis.Asset) (ctis.Asset, error) {
	// CTIS 2.0: the value is the canonical form of its type, and every
	// asset has a document-local id (never UUID-shaped; Validate refuses
	// one a tool sent).
	a.Value = canonicalValue(a)
	probe := a
	if probe.ID == "" {
		probe.ID = "probe"
	}
	if err := validate(&ctis.Report{Assets: []ctis.Asset{probe}}); err != nil {
		return a, c.reject(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.ID == "" {
		for {
			c.nextAsset++
			a.ID = "asset-" + strconv.Itoa(c.nextAsset)
			if !c.assetIDs[a.ID] {
				break
			}
		}
	}
	if a.ID != "" && c.assetIDs[a.ID] {
		c.invalid++
		return a, fmt.Errorf("%w: duplicate asset id %q", tool.ErrInvalidRecord, a.ID)
	}
	if err := c.account(a); err != nil {
		return a, err
	}
	c.assetIDs[a.ID] = true
	return a, nil
}

// FindingJSON checks a finding given as JSON.
func (c *Checker) FindingJSON(raw []byte) (ctis.Finding, error) {
	var f ctis.Finding
	if err := Sanitize(raw, &f); err != nil {
		return f, c.reject(err)
	}
	return c.finding(f)
}

// Finding checks a typed finding. Its asset_ref, when set, must name an
// asset accepted earlier (or one the runtime added).
func (c *Checker) Finding(f ctis.Finding) (ctis.Finding, error) {
	var out ctis.Finding
	if err := SanitizeValue(f, &out); err != nil {
		return out, c.reject(err)
	}
	return c.finding(out)
}

func (c *Checker) finding(f ctis.Finding) (ctis.Finding, error) {
	if !c.m.Declares(tool.KindFinding, string(f.Type)) {
		return f, c.quarantine(tool.KindFinding + ":" + string(f.Type))
	}
	// A secret finding whose snippet or masked value a tool left unmasked
	// has it masked here and wherever another field repeats it, so no tool
	// can put a raw credential in the report.
	ctis.RedactSecretFinding(&f)
	probe := f
	probe.AssetRef, probe.ID, probe.RuleRef = probeAsset.ID, "", ""
	if err := validate(&ctis.Report{Assets: []ctis.Asset{probeAsset}, Findings: []ctis.Finding{probe}}); err != nil {
		return f, c.reject(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.ID != "" && c.findingIDs[f.ID] {
		c.invalid++
		return f, fmt.Errorf("%w: duplicate finding id %q", tool.ErrInvalidRecord, f.ID)
	}
	if f.RuleRef != "" {
		ruleID, ok := c.rules[f.RuleRef]
		if !ok || (f.RuleID != "" && f.RuleID != ruleID) {
			c.invalid++
			return f, fmt.Errorf("%w: rule_ref %q names no rule emitted before it with rule_id %q", tool.ErrInvalidRecord, f.RuleRef, f.RuleID)
		}
		if f.RuleID == "" {
			f.RuleID = ruleID
		}
	}
	if f.AssetRef != "" && !c.assetIDs[f.AssetRef] {
		c.invalid++
		return f, fmt.Errorf("%w: asset_ref %q names no asset emitted before it", tool.ErrInvalidRecord, f.AssetRef)
	}
	if err := c.account(f); err != nil {
		return f, err
	}
	if f.ID != "" {
		c.findingIDs[f.ID] = true
	}
	return f, nil
}

// DependencyJSON checks a dependency given as JSON.
func (c *Checker) DependencyJSON(raw []byte) (ctis.Dependency, error) {
	var d ctis.Dependency
	if err := Sanitize(raw, &d); err != nil {
		return d, c.reject(err)
	}
	return c.dependency(d)
}

// Dependency checks a typed dependency.
func (c *Checker) Dependency(d ctis.Dependency) (ctis.Dependency, error) {
	var out ctis.Dependency
	if err := SanitizeValue(d, &out); err != nil {
		return out, c.reject(err)
	}
	return c.dependency(out)
}

func (c *Checker) dependency(d ctis.Dependency) (ctis.Dependency, error) {
	if !c.m.Declares(tool.KindDependency, "") {
		return d, c.quarantine(tool.KindDependency)
	}
	// The references name other records of the report: checked here
	// against the records accepted so far (asset_ref), and by form only
	// (depends_on), not inside the one-record report.
	probe := d
	probe.AssetRef, probe.DependsOn = "", nil
	if err := validate(&ctis.Report{Dependencies: []ctis.Dependency{probe}}); err != nil {
		return d, c.reject(err)
	}
	for _, ref := range d.DependsOn {
		if ref == "" || len(ref) > 1024 || ctis.IsUUIDShaped(ref) {
			return d, c.reject(fmt.Errorf("dependency depends_on %q is not a document reference", ref))
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if d.AssetRef != "" && !c.assetIDs[d.AssetRef] {
		c.invalid++
		return d, fmt.Errorf("%w: dependency asset_ref %q names no asset emitted before it", tool.ErrInvalidRecord, d.AssetRef)
	}
	if d.ID != "" && c.depIDs[d.ID] {
		c.invalid++
		return d, fmt.Errorf("%w: duplicate dependency id %q", tool.ErrInvalidRecord, d.ID)
	}
	if err := c.account(d); err != nil {
		return d, err
	}
	if d.ID != "" {
		c.depIDs[d.ID] = true
	}
	return d, nil
}

// EndpointJSON checks an endpoint given as JSON.
func (c *Checker) EndpointJSON(raw []byte) (ctis.Endpoint, error) {
	var e ctis.Endpoint
	if err := Sanitize(raw, &e); err != nil {
		return e, c.reject(err)
	}
	return c.endpoint(e)
}

// Endpoint checks a typed endpoint.
func (c *Checker) Endpoint(e ctis.Endpoint) (ctis.Endpoint, error) {
	var out ctis.Endpoint
	if err := SanitizeValue(e, &out); err != nil {
		return out, c.reject(err)
	}
	return c.endpoint(out)
}

func (c *Checker) endpoint(e ctis.Endpoint) (ctis.Endpoint, error) {
	if !c.m.Declares(tool.KindEndpoint, "") {
		return e, c.quarantine(tool.KindEndpoint)
	}
	if err := validate(&ctis.Report{Endpoints: []ctis.Endpoint{e}}); err != nil {
		return e, c.reject(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.ID != "" && c.endpointIDs[e.ID] {
		c.invalid++
		return e, fmt.Errorf("%w: duplicate endpoint id %q", tool.ErrInvalidRecord, e.ID)
	}
	if err := c.account(e); err != nil {
		return e, err
	}
	if e.ID != "" {
		c.endpointIDs[e.ID] = true
	}
	return e, nil
}

// RuleJSON checks a rule given as JSON.
func (c *Checker) RuleJSON(raw []byte) (ctis.Rule, error) {
	var r ctis.Rule
	if err := Sanitize(raw, &r); err != nil {
		return r, c.reject(err)
	}
	return c.rule(r)
}

// Rule checks a typed rule of the catalog (ids unique).
func (c *Checker) Rule(r ctis.Rule) (ctis.Rule, error) {
	var out ctis.Rule
	if err := SanitizeValue(r, &out); err != nil {
		return out, c.reject(err)
	}
	return c.rule(out)
}

func (c *Checker) rule(r ctis.Rule) (ctis.Rule, error) {
	if err := validate(&ctis.Report{Rules: []ctis.Rule{r}}); err != nil {
		return r, c.reject(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.rules[r.ID]; dup {
		c.invalid++
		return r, fmt.Errorf("%w: duplicate rule id %q", tool.ErrInvalidRecord, r.ID)
	}
	if err := c.account(r); err != nil {
		return r, err
	}
	c.rules[r.ID] = r.RuleID
	return r, nil
}

// RelationshipJSON checks a relationship given as JSON.
func (c *Checker) RelationshipJSON(raw []byte) (ctis.Relationship, error) {
	var r ctis.Relationship
	if err := Sanitize(raw, &r); err != nil {
		return r, c.reject(err)
	}
	return c.relationship(r)
}

// Relationship checks a typed relationship: a known type between two
// assets accepted before it.
func (c *Checker) Relationship(r ctis.Relationship) (ctis.Relationship, error) {
	var out ctis.Relationship
	if err := SanitizeValue(r, &out); err != nil {
		return out, c.reject(err)
	}
	return c.relationship(out)
}

func (c *Checker) relationship(r ctis.Relationship) (ctis.Relationship, error) {
	probe := r
	probe.FromRef, probe.ToRef = probeAsset.ID, probeAsset.ID+"-2"
	to := probeAsset
	to.ID, to.Value = probe.ToRef, probe.ToRef
	if err := validate(&ctis.Report{Assets: []ctis.Asset{probeAsset, to}, Relationships: []ctis.Relationship{probe}}); err != nil {
		return r, c.reject(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.assetIDs[r.FromRef] || !c.assetIDs[r.ToRef] || r.FromRef == r.ToRef {
		c.invalid++
		return r, fmt.Errorf("%w: relationship %s from %q to %q does not link two assets emitted before it",
			tool.ErrInvalidRecord, r.Type, r.FromRef, r.ToRef)
	}
	if err := c.account(r); err != nil {
		return r, err
	}
	return r, nil
}

// InfoJSON checks a report's tool, metadata and properties given as JSON.
func (c *Checker) InfoJSON(raw []byte) (*tool.ReportInfo, error) {
	if len(raw) > MaxInfoBytes {
		return nil, c.reject(fmt.Errorf("report info larger than %d bytes", MaxInfoBytes))
	}
	var info tool.ReportInfo
	if err := Sanitize(raw, &info); err != nil {
		return nil, c.reject(err)
	}
	return c.info(&info)
}

// Info checks a typed ReportInfo.
func (c *Checker) Info(in *tool.ReportInfo) (*tool.ReportInfo, error) {
	if in == nil {
		return nil, nil
	}
	var info tool.ReportInfo
	if err := SanitizeValue(in, &info); err != nil {
		return nil, c.reject(err)
	}
	return c.info(&info)
}

func (c *Checker) info(info *tool.ReportInfo) (*tool.ReportInfo, error) {
	b, err := json.Marshal(info)
	if err != nil || len(b) > MaxInfoBytes {
		return nil, c.reject(fmt.Errorf("report info larger than %d bytes", MaxInfoBytes))
	}
	if md := info.Metadata; md != nil {
		if md.CoverageType != "" && md.CoverageType != ctis.CoverageFull && md.CoverageType != ctis.CoverageIncremental && md.CoverageType != ctis.CoveragePartial {
			return nil, c.reject(fmt.Errorf("metadata.coverage_type %q is not full, incremental or partial", md.CoverageType))
		}
	}
	// The tool (its techniques and content releases) and the metadata a tool
	// may set pass the CTIS checks of a report that carries only them.
	probe := &ctis.Report{Tool: info.Tool, Properties: info.Properties}
	if probe.Tool != nil && probe.Tool.Name == "" {
		t := *probe.Tool
		t.Name = c.m.Name
		probe.Tool = &t
	}
	if md := info.Metadata; md != nil {
		probe.Metadata = ctis.ReportMetadata{DurationMs: md.DurationMs, Channel: md.Channel, SourceRefs: md.SourceRefs,
			CoverageType: md.CoverageType, Branch: md.Branch, Profiles: md.Profiles, StartedAt: md.StartedAt,
			EndedAt: md.EndedAt, Properties: md.Properties, Extensions: md.Extensions}
	}
	if err := validate(probe); err != nil {
		return nil, c.reject(err)
	}
	return info, nil
}

func (c *Checker) account(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		c.invalid++
		return fmt.Errorf("%w: %v", tool.ErrInvalidRecord, err)
	}
	if c.records+1 > c.maxRecords || c.bytes+int64(len(b)) > c.maxBytes {
		c.capped = true
		return fmt.Errorf("%w: %d records, %d bytes (limits %d records, %d bytes)",
			tool.ErrOutputLimit, c.records, c.bytes, c.maxRecords, c.maxBytes)
	}
	c.records++
	c.bytes += int64(len(b))
	return nil
}

func (c *Checker) quarantine(kind string) error {
	c.mu.Lock()
	c.quarantined[kind]++
	c.mu.Unlock()
	return fmt.Errorf("%w: %s is not in the manifest's produces", tool.ErrUndeclaredOutput, kind)
}

func (c *Checker) reject(err error) error {
	c.mu.Lock()
	c.invalid++
	c.mu.Unlock()
	if errors.Is(err, tool.ErrInvalidRecord) {
		return err
	}
	return fmt.Errorf("%w: %v", tool.ErrInvalidRecord, err)
}

var probeTime = time.Unix(1, 0).UTC()

// canonicalValue is the canonical form of an asset's value (CTIS 2.0): the
// module's canonical form of its type, with the transport of a service
// written as "host:port" taken from technical.service (tcp when unstated).
func canonicalValue(a ctis.Asset) string {
	v := strings.TrimSpace(a.Value)
	if a.Type == ctis.AssetTypeService && v != "" && !strings.Contains(v[strings.LastIndex(v, ":")+1:], "/") {
		tr := ctis.TransportTCP
		if a.Technical != nil && a.Technical.Service != nil && a.Technical.Service.Transport != "" {
			tr = a.Technical.Service.Transport
		}
		v += "/" + string(tr)
	}
	return ctis.NormalizeAssetName(a.Type, v)
}

// assetHost is the host name or address of a network asset in canonical
// form (domain_name, ip_address, host, service, web_origin), "" otherwise.
func assetHost(a ctis.Asset) string {
	v := a.Value
	switch a.Type {
	case ctis.AssetTypeDomainName, ctis.AssetTypeIPAddress, ctis.AssetTypeHost:
		return v
	case ctis.AssetTypeWebOrigin:
		if u, err := url.Parse(v); err == nil {
			return u.Hostname()
		}
	case ctis.AssetTypeService:
		if i := strings.LastIndex(v, "/"); i > 0 {
			if h, _, err := net.SplitHostPort(v[:i]); err == nil {
				return h
			}
		}
	}
	return ""
}

// probeReportID is the metadata.id of the one-record reports validate
// checks (a fixed UUIDv7; those reports never leave the runtime).
const probeReportID = "00000000-03e8-7000-8000-000000000000"

// probeAsset is the asset a finding is filed on while it is checked alone.
var probeAsset = ctis.Asset{ID: "probe", Type: ctis.AssetTypeUnclassified, Value: "probe"}

// validate runs the CTIS checks on a report holding one record.
func validate(r *ctis.Report) error {
	r.Version = ctis.SchemaVersion
	r.Metadata.ID = probeReportID
	r.Metadata.GeneratedAt = probeTime
	return r.Validate()
}

// SanitizeValue sanitizes a typed value into out (see Sanitize).
func SanitizeValue(v, out any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return Sanitize(raw, out)
}

// Sanitize decodes raw into out after cleaning it: invalid UTF-8 replaced,
// control characters (but tab, line feed and carriage return) and
// bidirectional-override characters removed from every string and key,
// strings cut to MaxString, nesting and size bounded. The final decode is
// strict: a member out does not know is an error (the platform decodes
// CTIS strictly too).
func Sanitize(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	if d.More() {
		return errors.New("trailing data after the JSON value")
	}
	nodes := 0
	clean, err := sanitizeNode(v, 0, &nodes)
	if err != nil {
		return err
	}
	b, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	sd := json.NewDecoder(bytes.NewReader(b))
	sd.DisallowUnknownFields()
	if err := sd.Decode(out); err != nil {
		return err
	}
	return nil
}

func sanitizeNode(v any, depth int, nodes *int) (any, error) {
	*nodes++
	if *nodes > MaxNodes {
		return nil, fmt.Errorf("more than %d values in one record", MaxNodes)
	}
	if depth > MaxDepth {
		return nil, fmt.Errorf("nested deeper than %d", MaxDepth)
	}
	switch x := v.(type) {
	case string:
		return CleanString(x), nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			c, err := sanitizeNode(e, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out[CleanString(k)] = c
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			c, err := sanitizeNode(e, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	}
	return v, nil
}

// CleanString removes control and bidirectional-override characters (it
// keeps tab, line feed and carriage return), replaces invalid UTF-8 and
// cuts the result to MaxString bytes on a rune boundary.
func CleanString(s string) string {
	if !needsCleaning(s) {
		return s
	}
	var b strings.Builder
	b.Grow(min(len(s), MaxString))
	for _, r := range strings.ToValidUTF8(s, "�") {
		if dropRune(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > MaxString {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func needsCleaning(s string) bool {
	if len(s) > MaxString || !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if dropRune(r) {
			return true
		}
	}
	return false
}

func dropRune(r rune) bool {
	switch r {
	case '\t', '\n', '\r':
		return false
	case '\u200e', '\u200f', '\u061c', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069':
		return true
	}
	return unicode.IsControl(r)
}
