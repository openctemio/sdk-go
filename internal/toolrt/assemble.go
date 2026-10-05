package toolrt

import (
	"fmt"
	"maps"
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
}

// NewAssembler starts the report of task.
func NewAssembler(m tool.Manifest, task tool.Task, c *Checker) *Assembler {
	a := &Assembler{m: m, checker: c, targets: map[string]tool.Target{},
		targetAssets: map[string]string{}, results: map[string]*TargetResult{}}
	for _, t := range task.Targets {
		if _, dup := a.targets[t.Ref]; !dup {
			a.order = append(a.order, t.Ref)
		}
		a.targets[t.Ref] = t
		if t.Type != "" {
			c.AllowTarget(t.Type, t.Value)
		}
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
	a.mu.Lock()
	a.report.Findings = append(a.report.Findings, f)
	a.mu.Unlock()
	return nil
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
	if !ctis.AssetType(t.Type).IsValid() || t.Value == "" {
		// Nothing to file on: the finding stays without an asset (the
		// platform's ingest decides).
		return "", nil
	}
	id = "target-" + ref
	as, err := a.checker.TargetAsset(ctis.Asset{ID: id, Type: ctis.AssetType(t.Type), Value: t.Value, Name: t.Value})
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

// failedTarget is a target the tool did not complete, in the report's
// properties ("failed_targets").
type failedTarget struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// Report returns the assembled report. The tool's name is the manifest's
// (a tool cannot claim to be another one); tool.version is what the tool
// reported (the engine it runs). The adapter's own version is in the
// provenance.
func (a *Assembler) Report(now time.Time) *ctis.Report {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.report
	r.Version = ctis.SchemaVersion
	r.Schema = ctis.SchemaURL
	r.Metadata = ctis.ReportMetadata{Timestamp: now, SourceType: "scanner"}
	if info := a.info; info != nil {
		if info.Tool != nil {
			t := *info.Tool
			r.Tool = &t
		}
		if md := info.Metadata; md != nil {
			if md.SourceType != "" {
				r.Metadata.SourceType = md.SourceType
			}
			r.Metadata.ID, r.Metadata.DurationMs, r.Metadata.SourceRef = md.ID, max(md.DurationMs, 0), md.SourceRef
			r.Metadata.CoverageType = md.CoverageType
			r.Metadata.Branch = md.Branch
			r.Metadata.Scope = md.Scope
			r.Metadata.Properties = maps.Clone(md.Properties)
		}
		r.Properties = maps.Clone(info.Properties)
	}
	if r.Tool == nil {
		r.Tool = &ctis.Tool{}
	}
	r.Tool.Name = a.m.Name
	var failed []failedTarget
	for _, ref := range a.order {
		if res, ok := a.results[ref]; ok && res.State == tool.StateFailed {
			msg := ""
			if res.Error != nil {
				msg = res.Error.Detail
				if msg == "" {
					msg = string(res.Error.Class)
				}
			}
			failed = append(failed, failedTarget{Target: res.Target.Value, Error: msg})
		}
	}
	if len(failed) > 0 {
		if r.Properties == nil {
			r.Properties = ctis.Properties{}
		}
		r.Properties["failed_targets"] = failed
	}
	return &r
}

// Provenance is what the runtime stamps on every report: which tool and
// manifest produced it, under which sandbox, for which task, and what the
// runtime refused.
type Provenance struct {
	Tool           string         `json:"tool"`
	ToolVersion    string         `json:"tool_version"`
	ManifestDigest string         `json:"manifest_digest"`
	Protocol       int            `json:"protocol,omitempty"`
	Execution      string         `json:"execution"`
	Sandbox        any            `json:"sandbox,omitempty"`
	Network        string         `json:"network,omitempty"`
	Sensor         string         `json:"sensor,omitempty"`
	TaskID         string         `json:"task_id,omitempty"`
	Attempt        int            `json:"attempt,omitempty"`
	Status         tool.Status    `json:"status"`
	Records        int            `json:"records"`
	Quarantined    map[string]int `json:"quarantined,omitempty"`
	Invalid        int            `json:"invalid,omitempty"`
	Capped         bool           `json:"capped,omitempty"`
}

// Stamp writes p into r's metadata properties, replacing anything there.
func Stamp(r *ctis.Report, p Provenance) {
	if r.Metadata.Properties == nil {
		r.Metadata.Properties = ctis.Properties{}
	}
	r.Metadata.Properties[ProvenanceKey] = p
}
