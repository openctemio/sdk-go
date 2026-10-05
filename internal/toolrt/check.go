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
	quarantined map[string]int
	invalid     int
	targets     map[string]bool
}

// NewChecker returns a checker for m's limits and produces.
func NewChecker(m tool.Manifest) *Checker {
	_, _, maxBytes, maxRecords := m.Resources.Limits()
	return &Checker{m: m, maxRecords: maxRecords, maxBytes: maxBytes,
		assetIDs: map[string]bool{}, findingIDs: map[string]bool{}, depIDs: map[string]bool{},
		quarantined: map[string]int{}, targets: map[string]bool{}}
}

// AllowTarget lets an asset that is one of the task's targets (same type
// and value) through without being in produces: a converter that files
// findings on the scanned target emits it, and it is the task's input,
// not new output.
func (c *Checker) AllowTarget(typ, value string) {
	c.mu.Lock()
	c.targets[typ+"\x00"+value] = true
	c.mu.Unlock()
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
	c.mu.Lock()
	isTarget := c.targets[string(a.Type)+"\x00"+a.Value]
	c.mu.Unlock()
	if !isTarget && !c.m.Declares(tool.KindAsset, string(a.Type)) {
		return a, c.quarantine(tool.KindAsset + ":" + string(a.Type))
	}
	return c.checkAsset(a)
}

func (c *Checker) checkAsset(a ctis.Asset) (ctis.Asset, error) {
	if err := validate(&ctis.Report{Assets: []ctis.Asset{a}}); err != nil {
		return a, c.reject(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.ID != "" && c.assetIDs[a.ID] {
		c.invalid++
		return a, fmt.Errorf("%w: duplicate asset id %q", tool.ErrInvalidRecord, a.ID)
	}
	if err := c.account(a); err != nil {
		return a, err
	}
	if a.ID != "" {
		c.assetIDs[a.ID] = true
	}
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
	probe := f
	probe.AssetRef, probe.ID = "", ""
	if err := validate(&ctis.Report{Findings: []ctis.Finding{probe}}); err != nil {
		return f, c.reject(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.ID != "" && c.findingIDs[f.ID] {
		c.invalid++
		return f, fmt.Errorf("%w: duplicate finding id %q", tool.ErrInvalidRecord, f.ID)
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
	if err := validate(&ctis.Report{Dependencies: []ctis.Dependency{d}}); err != nil {
		return d, c.reject(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
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
		if md.CoverageType != "" && md.CoverageType != "full" && md.CoverageType != "incremental" && md.CoverageType != "partial" {
			return nil, c.reject(fmt.Errorf("metadata.coverage_type %q is not full, incremental or partial", md.CoverageType))
		}
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

// validate runs the CTIS checks on a report holding one record.
func validate(r *ctis.Report) error {
	r.Version = ctis.SchemaVersion
	r.Metadata.Timestamp = probeTime
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
