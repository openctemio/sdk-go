package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
)

// Tier is how much a tool touches the target: passive (T0, no traffic beyond
// normal reads), safe (T1, active but non-destructive) or intrusive (T2).
// A grant's ceiling is passive or safe; intrusive never runs inside a run, it
// becomes a request a person approves.
type Tier string

// Tiers, ordered.
const (
	TierPassive   Tier = "passive"
	TierSafe      Tier = "safe"
	TierIntrusive Tier = "intrusive"
)

func (t Tier) rank() int {
	switch t {
	case TierPassive:
		return 0
	case TierSafe:
		return 1
	case TierIntrusive:
		return 2
	}
	return 3 // unknown is above everything: fail closed
}

// Class is where a tool runs.
type Class string

// Classes.
const (
	// ClassPlatformRead reads platform data through the job-scoped token of
	// the AI service account (the same read paths a person uses).
	ClassPlatformRead Class = "platform_read"
	// ClassSensorJob runs a tool-pack tool as a signed sensor task: in this
	// worker's own sandbox (interactive lane, self-affinity) or on the scan
	// fleet when the platform places it there.
	ClassSensorJob Class = "sensor_job"
	// ClassMCP calls a tool of an MCP server the organization approved,
	// pinned by definition digest.
	ClassMCP Class = "mcp"
)

// ToolDef is a tool's fixed description. Targets lists the argument names
// that carry a target placeholder; the policy accepts only placeholders bound
// in the grant there.
type ToolDef struct {
	Spec    ToolSpec
	Class   Class
	Tier    Tier
	Targets []string
}

// Tool is one callable tool. Call receives arguments the policy and the
// input schema already accepted and returns raw output text; the harness
// truncates, redacts and fences it.
type Tool interface {
	Def() ToolDef
	Call(ctx context.Context, args json.RawMessage) (string, error)
}

// TargetBinding binds a placeholder the model sees to the subject's real
// target. Only the egress forwarder at the tool boundary resolves it; the
// harness checks only that a placeholder is bound.
type TargetBinding struct {
	Token string `json:"token"`
	Value string `json:"value"`
}

// Grant is the investigation grant from the signed job statement: what this
// run may use. Nothing the model writes can widen it.
type Grant struct {
	Tools       []string        `json:"tools"`
	Targets     []TargetBinding `json:"targets"`
	TierCeiling Tier            `json:"tier_ceiling"`
	Budgets     Budgets         `json:"budgets"`
}

func (g Grant) bound(token string) bool {
	for _, b := range g.Targets {
		if b.Token == token {
			return true
		}
	}
	return false
}

var toolName = regexp.MustCompile(`^[a-z0-9_.@-]{1,64}$`)

// Registry is the set of tools one run may offer the model: the tools the
// worker has, intersected with the grant and the playbook, capped at the
// grant's tier ceiling.
type Registry struct {
	tools map[string]Tool
	names []string
	// Withheld lists tools the grant named that this worker cannot offer
	// (not installed, or above the ceiling), for the run record.
	Withheld []string
}

// NewRegistry builds the run's registry. allow (the playbook's tool list)
// may only narrow the grant; nil means the grant as is.
func NewRegistry(g Grant, allow []string, available ...Tool) (*Registry, error) {
	have := make(map[string]Tool, len(available))
	for _, t := range available {
		d := t.Def()
		if !toolName.MatchString(d.Spec.Name) {
			return nil, fmt.Errorf("harness: invalid tool name %q", d.Spec.Name)
		}
		if _, dup := have[d.Spec.Name]; dup {
			return nil, fmt.Errorf("harness: tool %q registered twice", d.Spec.Name)
		}
		have[d.Spec.Name] = t
	}
	r := &Registry{tools: map[string]Tool{}}
	for _, name := range g.Tools {
		if allow != nil && !slices.Contains(allow, name) {
			continue
		}
		t, ok := have[name]
		if !ok || t.Def().Tier.rank() > g.TierCeiling.rank() || g.TierCeiling.rank() > TierSafe.rank() {
			r.Withheld = append(r.Withheld, name)
			continue
		}
		r.tools[name] = t
		r.names = append(r.names, name)
	}
	sort.Strings(r.names)
	return r, nil
}

// Specs lists the tools for the model, in a stable order (so a cached prompt
// prefix stays identical across runs of one playbook).
func (r *Registry) Specs() []ToolSpec {
	out := make([]ToolSpec, 0, len(r.names))
	for _, n := range r.names {
		out = append(out, r.tools[n].Def().Spec)
	}
	return out
}

// Lookup returns a tool the run may call.
func (r *Registry) Lookup(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// Len is the number of tools offered.
func (r *Registry) Len() int { return len(r.names) }
