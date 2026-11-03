package toolrt

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// ProvenanceKey is the metadata property the runtime stamps (and
// overwrites whatever a tool put there).
const ProvenanceKey = "provenance"

// TargetResult is the outcome of one target.
type TargetResult struct {
	Target tool.Target      `json:"-"`
	State  tool.TargetState `json:"state"`
	Error  *tool.Error      `json:"-"`
}

// Assembler builds one task's CTIS report from checked records. It is safe
// for concurrent use.
type Assembler struct {
	m       tool.Manifest
	checker *Checker
	targets map[string]tool.Target
	order   []string

	mu           sync.Mutex
	report       ctis.Report
	targetAssets map[string]string
	results      map[string]*TargetResult
	info         *tool.ReportInfo

	// items are the items of a retest task by ref; verdicts what the tool
	// said about them.
	items     map[string]tool.RetestItem
	itemOrder []string
	verdicts  map[string]tool.RetestVerdict
}

// NewAssembler starts the report of task.
func NewAssembler(m tool.Manifest, task tool.Task, c *Checker) *Assembler {
	a := &Assembler{m: m, checker: c, targets: map[string]tool.Target{},
		targetAssets: map[string]string{}, results: map[string]*TargetResult{},
		items: map[string]tool.RetestItem{}, verdicts: map[string]tool.RetestVerdict{}}
	for _, it := range task.Retest {
		if _, dup := a.items[it.Ref]; !dup {
			a.itemOrder = append(a.itemOrder, it.Ref)
		}
		a.items[it.Ref] = it
	}
	c.AllowTaskTargets(task.Targets)
	for _, t := range task.Targets {
		if _, dup := a.targets[t.Ref]; !dup {
			a.order = append(a.order, t.Ref)
		}
		a.targets[t.Ref] = t
	}
	return a
}

// Checker is the assembler's checker.
func (a *Assembler) Checker() *Checker { return a.checker }

// LookupTarget returns the task's target with ref.
func (a *Assembler) LookupTarget(ref string) (tool.Target, bool) {
	t, ok := a.targets[ref]
	return t, ok
}

// Asset checks and adds an asset.
func (a *Assembler) Asset(as ctis.Asset) error {
	as, err := a.checker.Asset(as)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.report.Assets = append(a.report.Assets, as)
	a.mu.Unlock()
	return nil
}

// AddCheckedAsset adds an asset the checker already accepted.
func (a *Assembler) AddCheckedAsset(as ctis.Asset) {
	a.mu.Lock()
	a.report.Assets = append(a.report.Assets, as)
	a.mu.Unlock()
}

// Finding checks and adds a finding; one without an asset reference is
// filed on target ref's asset (added on first use) when ref names a
// target.
func (a *Assembler) Finding(ref string, f ctis.Finding) error {
	if f.AssetRef == "" && ref != "" {
		id, err := a.targetAsset(ref)
		if err != nil {
			return err
		}
		f.AssetRef = id
	}
	if f.AssetRef == "" {
		return errNoFindingAsset
	}
	f, err := a.checker.Finding(f)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.report.Findings = append(a.report.Findings, f)
	a.mu.Unlock()
	return nil
}

// AddCheckedFinding adds a finding the checker already accepted, filing it
// on target ref's asset when it has no asset reference.
func (a *Assembler) AddCheckedFinding(ref string, f ctis.Finding) error {
	if f.AssetRef == "" && ref != "" {
		id, err := a.targetAsset(ref)
		if err != nil {
			return err
		}
		f.AssetRef = id
	}
	if f.AssetRef == "" {
		return errNoFindingAsset
	}
	a.mu.Lock()
	a.report.Findings = append(a.report.Findings, f)
	a.mu.Unlock()
	return nil
}

// targetAssetPrefix starts the id of an asset the runtime adds for a task
// target (to file findings on).
const targetAssetPrefix = "target-"

// OutputOnly returns a copy of r without the assets the runtime added for
// the task's targets: they are the task's input, so a capability's output
// contract does not judge them.
func OutputOnly(r *ctis.Report) *ctis.Report {
	if r == nil {
		return nil
	}
	cp := *r
	cp.Assets = make([]ctis.Asset, 0, len(r.Assets))
	for _, a := range r.Assets {
		if !strings.HasPrefix(a.ID, targetAssetPrefix) {
			cp.Assets = append(cp.Assets, a)
		}
	}
	return &cp
}

// errNoFindingAsset refuses a finding that names no asset and no target
// (CTIS 2.0: every finding names an asset of the document).
var errNoFindingAsset = fmt.Errorf("%w: the finding names no asset (asset_ref) and no target", tool.ErrInvalidRecord)

// DefaultTargetRef is the ref a finding without an asset or target is filed
// on: the task's target when it has exactly one, else "".
func (a *Assembler) DefaultTargetRef() string {
	if len(a.order) == 1 {
		return a.order[0]
	}
	return ""
}

// Dependency checks and adds a dependency.
func (a *Assembler) Dependency(d ctis.Dependency) error {
	d, err := a.checker.Dependency(d)
	if err != nil {
		return err
	}
	a.AddCheckedDependency(d)
	return nil
}

// AddCheckedDependency adds a dependency the checker already accepted.
func (a *Assembler) AddCheckedDependency(d ctis.Dependency) {
	a.mu.Lock()
	a.report.Dependencies = append(a.report.Dependencies, d)
	a.mu.Unlock()
}

// Endpoint checks and adds an endpoint.
func (a *Assembler) Endpoint(e ctis.Endpoint) error {
	e, err := a.checker.Endpoint(e)
	if err != nil {
		return err
	}
	a.AddCheckedEndpoint(e)
	return nil
}

// AddCheckedEndpoint adds an endpoint the checker already accepted.
func (a *Assembler) AddCheckedEndpoint(e ctis.Endpoint) {
	a.mu.Lock()
	a.report.Endpoints = append(a.report.Endpoints, e)
	a.mu.Unlock()
}

// Rule checks and adds a rule of the catalog.
func (a *Assembler) Rule(r ctis.Rule) error {
	r, err := a.checker.Rule(r)
	if err != nil {
		return err
	}
	a.AddCheckedRule(r)
	return nil
}

// AddCheckedRule adds a rule the checker already accepted.
func (a *Assembler) AddCheckedRule(r ctis.Rule) {
	a.mu.Lock()
	a.report.Rules = append(a.report.Rules, r)
	a.mu.Unlock()
}

// Relationship checks and adds a relationship.
func (a *Assembler) Relationship(r ctis.Relationship) error {
	r, err := a.checker.Relationship(r)
	if err != nil {
		return err
	}
	a.AddCheckedRelationship(r)
	return nil
}

// AddCheckedRelationship adds a relationship the checker already accepted.
func (a *Assembler) AddCheckedRelationship(r ctis.Relationship) {
	a.mu.Lock()
	a.report.Relationships = append(a.report.Relationships, r)
	a.mu.Unlock()
}

// SetInfo merges a checked ReportInfo (later calls win per field).
func (a *Assembler) SetInfo(info *tool.ReportInfo) {
	if info == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.info == nil {
		a.info = &tool.ReportInfo{}
	}
	if info.Tool != nil {
		a.info.Tool = info.Tool
	}
	if info.Metadata != nil {
		a.info.Metadata = info.Metadata
	}
	if len(info.Properties) > 0 {
		if a.info.Properties == nil {
			a.info.Properties = ctis.Properties{}
		}
		maps.Copy(a.info.Properties, info.Properties)
	}
}

// targetAsset returns the id of target ref's asset, adding it on first use.
// The asset passes the same checks as any other (its type must be
// declared).
func (a *Assembler) targetAsset(ref string) (string, error) {
	t, ok := a.targets[ref]
	if !ok {
		return "", fmt.Errorf("%w: unknown target %q", tool.ErrInvalidRecord, ref)
	}
	a.mu.Lock()
	id, ok := a.targetAssets[ref]
	a.mu.Unlock()
	if ok {
		return id, nil
	}
	typ := ctis.AssetType(t.Type)
	if typ == "" {
		// A plain target of a scan command: its type from its form.
		typ = tool.InferTargetType(t.Value)
	}
	if !typ.IsValid() || t.Value == "" {
		// CTIS 2.0: every finding names an asset of the document.
		return "", fmt.Errorf("%w: target %q has no CTIS asset type and value to file a finding on", tool.ErrInvalidRecord, ref)
	}
	// The id is document-local and derived from the target's position, never
	// from the task's ref (which may be a receiver's identifier).
	id = targetAssetPrefix + strconv.Itoa(slices.Index(a.order, ref)+1)
	if _, cerr := ctis.CanonicalAssetValue(typ, canonicalValue(ctis.Asset{Type: typ, Value: t.Value})); cerr != nil {
		// A target value without the canonical form of its type (a local
		// checkout path given as a repository): the findings stay on an
		// unclassified asset of that value rather than being lost.
		typ = ctis.AssetTypeUnclassified
	}
	as, err := a.checker.TargetAsset(ctis.Asset{ID: id, Type: typ, Value: t.Value, Name: t.Value})
	if err != nil {
		return "", fmt.Errorf("asset of target %q: %w", ref, err)
	}
	a.mu.Lock()
	a.targetAssets[ref] = id
	a.report.Assets = append(a.report.Assets, as)
	a.mu.Unlock()
	return id, nil
}

// Target records target ref's outcome (the first terminal report wins;
// unknown refs are refused).
func (a *Assembler) Target(ref string, state tool.TargetState, err *tool.Error) error {
	t, ok := a.targets[ref]
	if !ok {
		return fmt.Errorf("unknown target %q", ref)
	}
	switch state {
	case tool.StateDone, tool.StateFailed, tool.StateSkipped:
	default:
		return fmt.Errorf("unknown target state %q", state)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, done := a.results[ref]; done {
		return nil
	}
	a.results[ref] = &TargetResult{Target: t, State: state, Error: err}
	return nil
}

// Results returns every target's outcome, in task order; a target never
// reported has no entry.
func (a *Assembler) Results() []TargetResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []TargetResult
	for _, ref := range a.order {
		if r, ok := a.results[ref]; ok {
			out = append(out, *r)
		}
	}
	return out
}

// Done counts the targets the tool settled as done.
func (a *Assembler) Done() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, r := range a.results {
		if r.State == tool.StateDone {
			n++
		}
	}
	return n
}

// Unfinished returns the task's targets the tool gave no outcome, in task
// order: the ones a run that stopped part-way never reached.
func (a *Assembler) Unfinished() []tool.Target {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []tool.Target
	for _, ref := range a.order {
		if _, ok := a.results[ref]; !ok {
			out = append(out, a.targets[ref])
		}
	}
	return out
}

// Status computes the task outcome from the run's error and what the
// checker and the targets say: a run error is failed (canceled for a
// cancel); otherwise partial when a target failed, was skipped or was
// never reported, or when output was capped, quarantined or invalid.
func (a *Assembler) Status(runErr *tool.Error) tool.Status {
	if runErr != nil {
		if runErr.Class == tool.Canceled {
			return tool.StatusCanceled
		}
		return tool.StatusFailed
	}
	st := a.checker.Stats()
	if st.Capped || len(st.Quarantined) > 0 || st.Invalid > 0 {
		return tool.StatusPartial
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ref := range a.order {
		r, ok := a.results[ref]
		if !ok || r.State != tool.StateDone {
			return tool.StatusPartial
		}
	}
	return tool.StatusOK
}

// Report returns the assembled report. The tool's name is the manifest's
// (a tool cannot claim to be another one); tool.version is what the tool
// reported (the engine it runs). The adapter's own version is in the
// provenance. metadata.id is a new producer UUIDv7 (ctis.NewReportID): the
// runtime never names the receiver's job in the document. Every target the
// tool did not complete is in metadata.targets as failed.
func (a *Assembler) Report(now time.Time) *ctis.Report {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.report
	r.Version = ctis.SchemaVersion
	r.Schema = ctis.SchemaURL
	r.Metadata = ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: now, Channel: ctis.ChannelScanner}
	if info := a.info; info != nil {
		if info.Tool != nil {
			t := *info.Tool
			r.Tool = &t
		}
		if md := info.Metadata; md != nil {
			if md.Channel != "" {
				r.Metadata.Channel = md.Channel
			}
			r.Metadata.DurationMs = max(md.DurationMs, 0)
			r.Metadata.SourceRefs = slices.Clone(md.SourceRefs)
			r.Metadata.CoverageType = md.CoverageType
			r.Metadata.Branch = md.Branch
			r.Metadata.Profiles = slices.Clone(md.Profiles)
			r.Metadata.StartedAt, r.Metadata.EndedAt = md.StartedAt, md.EndedAt
			r.Metadata.Properties = maps.Clone(md.Properties)
			r.Metadata.Extensions = maps.Clone(md.Extensions)
		}
		r.Properties = maps.Clone(info.Properties)
	}
	if r.Tool == nil {
		r.Tool = &ctis.Tool{}
	}
	r.Tool.Name = a.m.Name
	for _, ref := range a.order {
		if res, ok := a.results[ref]; ok && res.State == tool.StateFailed {
			var class tool.ErrorClass
			if res.Error != nil {
				class = res.Error.Class
			}
			if o, ok := TargetOutcomeOf(res.Target.Value, tool.StateFailed, class); ok {
				r.Metadata.Targets = append(r.Metadata.Targets, o)
			}
		}
	}
	return &r
}

// TargetOutcomeOf is the CTIS metadata.targets entry of a target that ended
// in state with error class (failed: its class; skipped: refused by policy
// or excluded). It reports false for a state that has no outcome.
func TargetOutcomeOf(value string, state tool.TargetState, class tool.ErrorClass) (ctis.TargetOutcome, bool) {
	o := ctis.TargetOutcome{Target: value}
	switch state {
	case tool.StateDone:
		o.State = ctis.TargetDone
	case tool.StateFailed:
		o.State, o.Class = ctis.TargetFailed, ctis.TargetClassToolError
		switch class {
		case tool.Timeout:
			o.Class = ctis.TargetClassTimeout
		case tool.TargetUnreachable, tool.NotFound:
			o.Class = ctis.TargetClassUnreachable
		case tool.EgressRefused:
			o.Class = ctis.TargetClassEgressRefused
		}
	case tool.StateSkipped:
		o.State, o.Class = ctis.TargetSkipped, ctis.TargetClassExcluded
		if class == tool.RefusedByPolicy {
			o.Class = ctis.TargetClassRefused
		}
	default:
		return o, false
	}
	return o, value != ""
}

// Provenance is what the runtime stamps on every report: which tool and
// manifest produced it, under which sandbox, and what the runtime refused.
// It is an opaque metadata property (receivers give properties no
// meaning) and never carries a receiver's identifier: the task the report
// answers is bound by the transport, not by the document.
type Provenance struct {
	Tool           string         `json:"tool"`
	ToolVersion    string         `json:"tool_version"`
	ManifestDigest string         `json:"manifest_digest"`
	Protocol       int            `json:"protocol,omitempty"`
	Execution      string         `json:"execution"`
	Sandbox        any            `json:"sandbox,omitempty"`
	Network        string         `json:"network,omitempty"`
	Sensor         string         `json:"sensor,omitempty"`
	Attempt        int            `json:"attempt,omitempty"`
	Status         tool.Status    `json:"status"`
	Records        int            `json:"records"`
	Quarantined    map[string]int `json:"quarantined,omitempty"`
	Invalid        int            `json:"invalid,omitempty"`
	Capped         bool           `json:"capped,omitempty"`
	// Capability is the capability the task ran ("scan.ports@1").
	Capability string `json:"capability,omitempty"`
	// ContractViolations counts records that miss its contract.
	ContractViolations int `json:"contract_violations,omitempty"`
}

// capabilityRefRE is the form of the capability claim of the io.openctem
// extension namespace (id@major).
var capabilityRefRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+@[1-9][0-9]{0,2}$`)

// Stamp writes p into r's metadata properties, replacing anything there,
// and states the capability the task ran in
// metadata.extensions["io.openctem"].capability (a hint to the receiver,
// which binds the report to its own command).
func Stamp(r *ctis.Report, p Provenance) {
	if r.Metadata.Properties == nil {
		r.Metadata.Properties = ctis.Properties{}
	}
	r.Metadata.Properties[ProvenanceKey] = p
	if len(p.Capability) <= 128 && capabilityRefRE.MatchString(p.Capability) {
		r.Metadata.Extensions.Set(ctis.OpenCTEMNamespace, "capability", p.Capability)
		return
	}
	// No valid capability for the task: nothing the tool put under the
	// OpenCTEM namespace of the metadata may reach the receiver as if the
	// runtime had stamped it.
	delete(r.Metadata.Extensions, ctis.OpenCTEMNamespace)
	if len(r.Metadata.Extensions) == 0 {
		r.Metadata.Extensions = nil
	}
}
