package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Refusal codes returned to the model and written to the run record. They
// are fixed strings, never text from a tool, a target or a model.
const (
	CodeOutsideGrant     = "outside_grant"
	CodeInvalidArgs      = "invalid_args"
	CodeTargetNotBound   = "target_not_bound"
	CodeTierAboveCeiling = "tier_above_ceiling"
	CodeNeedsApproval    = "needs_approval"
	CodeBudgetExhausted  = "budget_exhausted"
	CodeDeniedByHook     = "denied_by_hook"
	CodeToolFailed       = "tool_failed"
)

// Decision is the verdict on one tool call. A deny from any check wins.
type Decision struct {
	Allow bool
	Code  string
}

// Allowed is the decision of a check with no objection.
var Allowed = Decision{Allow: true}

// Deny returns a denial with a fixed code.
func Deny(code string) Decision { return Decision{Code: code} }

// PreToolHook is a deterministic guard run before a tool call, after the
// grant policy. It can only deny (a hook never widens the grant). A hook that
// panics denies.
type PreToolHook func(ctx context.Context, call ToolCall, def ToolDef) Decision

// PostToolHook transforms a tool's output before the model sees it
// (redaction, truncation, neutralizing markup). It cannot add a tool call.
type PostToolHook func(ctx context.Context, call ToolCall, def ToolDef, output string) string

// Policy decides every tool call before it runs.
type Policy interface {
	Decide(ctx context.Context, call ToolCall, def ToolDef) Decision
}

// GrantPolicy is the policy built from the signed grant: the tool must be in
// the run's registry, the arguments must satisfy the tool's input schema, a
// target argument must be a placeholder bound in the grant, and the tier must
// be within the ceiling (intrusive tools are never run, they need a person).
type GrantPolicy struct {
	grant Grant

	mu       sync.Mutex
	compiled map[string]*jsonschema.Schema
}

// NewGrantPolicy builds the policy of one run.
func NewGrantPolicy(g Grant) *GrantPolicy {
	return &GrantPolicy{grant: g, compiled: map[string]*jsonschema.Schema{}}
}

// Decide implements Policy.
func (p *GrantPolicy) Decide(_ context.Context, call ToolCall, def ToolDef) Decision {
	if def.Spec.Name == "" || def.Spec.Name != call.Name {
		return Deny(CodeOutsideGrant)
	}
	granted := false
	for _, n := range p.grant.Tools {
		if n == call.Name {
			granted = true
			break
		}
	}
	if !granted {
		return Deny(CodeOutsideGrant)
	}
	if def.Tier == TierIntrusive {
		return Deny(CodeNeedsApproval)
	}
	if def.Tier.rank() > p.grant.TierCeiling.rank() || p.grant.TierCeiling.rank() > TierSafe.rank() {
		return Deny(CodeTierAboveCeiling)
	}
	args, ok := decodeObject(call.Args)
	if !ok {
		return Deny(CodeInvalidArgs)
	}
	if err := p.validateArgs(def, call.Args); err != nil {
		return Deny(CodeInvalidArgs)
	}
	for _, field := range def.Targets {
		v, present := args[field]
		if !present {
			continue
		}
		if !p.allBound(v) {
			return Deny(CodeTargetNotBound)
		}
	}
	return Allowed
}

func (p *GrantPolicy) allBound(v any) bool {
	switch x := v.(type) {
	case string:
		return p.grant.bound(x)
	case []any:
		if len(x) == 0 {
			return false
		}
		for _, e := range x {
			s, ok := e.(string)
			if !ok || !p.grant.bound(s) {
				return false
			}
		}
		return true
	}
	return false
}

func decodeObject(raw json.RawMessage) (map[string]any, bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, true
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// validateArgs checks the arguments against the tool's input schema. A tool
// without a schema accepts only an empty object (closed by default).
func (p *GrantPolicy) validateArgs(def ToolDef, raw json.RawMessage) error {
	if len(bytes.TrimSpace(def.Spec.InputSchema)) == 0 {
		m, _ := decodeObject(raw)
		if len(m) != 0 {
			return fmt.Errorf("tool takes no arguments")
		}
		return nil
	}
	s, err := p.schema(def)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage(`{}`)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return s.Validate(v)
}

func (p *GrantPolicy) schema(def ToolDef) (*jsonschema.Schema, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.compiled[def.Spec.Name]; ok {
		return s, nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(def.Spec.InputSchema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	url := "urn:openctem:tool:" + def.Spec.Name
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, err
	}
	p.compiled[def.Spec.Name] = s
	return s, nil
}

// runPreHooks runs the hooks in order; the first denial wins. A panicking
// hook denies.
func runPreHooks(ctx context.Context, hooks []PreToolHook, call ToolCall, def ToolDef) (d Decision) {
	defer func() {
		if recover() != nil {
			d = Deny(CodeDeniedByHook)
		}
	}()
	for _, h := range hooks {
		if r := h(ctx, call, def); !r.Allow {
			if r.Code == "" {
				r.Code = CodeDeniedByHook
			}
			return r
		}
	}
	return Allowed
}
