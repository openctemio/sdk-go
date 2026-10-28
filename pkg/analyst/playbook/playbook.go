// Package playbook is the analyst playbook format (openctem.io/playbook/v1):
// a versioned, reviewable file that tells the harness how to work one kind
// of job (for example triage of a web finding): its instructions, the steps
// and evidence it needs, the tools it may use (a subset of the grant) and
// its budgets (never above the grant). The same file runs on the platform's
// analyst pool and on an organization's own worker; the platform pins it by
// digest in the job.
//
// Design: openctem api/docs/rfcs/RFC-133-ai-analyst-harness.md.
//
// Stability: Experimental (docs/STABILITY.md).
package playbook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/sdk-go/pkg/analyst"
	"github.com/openctemio/sdk-go/pkg/analyst/contract"
)

// APIVersion of this format.
const APIVersion = "openctem.io/playbook/v1"

// MaxBytes bounds a playbook file.
const MaxBytes = 64 << 10

// Step is one stage of the work, in order. Tools narrows the playbook's
// tools for the stage (shown to the model as guidance; the run-level list is
// the enforced one).
type Step struct {
	ID    string   `yaml:"id"`
	Goal  string   `yaml:"goal"`
	Tools []string `yaml:"tools,omitempty"`
}

// Match says which subjects a playbook is for. Empty fields match anything.
type Match struct {
	Sources    []string `yaml:"sources,omitempty"`
	Categories []string `yaml:"categories,omitempty"`
}

// Budgets in the file (seconds as an integer, like the contract).
type Budgets struct {
	Steps        int   `yaml:"steps,omitempty"`
	ToolCalls    int   `yaml:"tool_calls,omitempty"`
	Tokens       int   `yaml:"tokens,omitempty"`
	Seconds      int   `yaml:"seconds,omitempty"`
	CostMicroUSD int64 `yaml:"cost_micro_usd,omitempty"`
}

// Playbook is one parsed, validated playbook.
type Playbook struct {
	APIVersion       string   `yaml:"apiVersion"`
	Name             string   `yaml:"name"`
	Version          string   `yaml:"version"`
	Title            string   `yaml:"title"`
	Kind             string   `yaml:"kind"`
	Output           string   `yaml:"output"`
	ModelTier        string   `yaml:"model_tier"`
	Match            Match    `yaml:"match,omitempty"`
	Tools            []string `yaml:"tools,omitempty"`
	RequiredEvidence []string `yaml:"required_evidence,omitempty"`
	Budgets          Budgets  `yaml:"budgets,omitempty"`
	Steps            []Step   `yaml:"steps"`
	Rules            []string `yaml:"rules,omitempty"`
	Instructions     string   `yaml:"instructions"`

	digest string
}

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	semverRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	kindRe   = regexp.MustCompile(`^[a-z_]{1,32}\.v[0-9]{1,3}$`)
	toolRe   = regexp.MustCompile(`^[a-z0-9_.@-]{1,64}$`)
	stepRe   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	fieldRe  = regexp.MustCompile(`^bundle:[a-z0-9_]{1,48}(\.[a-z0-9_]{1,48}){0,3}$`)
)

// ErrInvalid matches every validation failure (errors.Is).
var ErrInvalid = errors.New("playbook_invalid")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
}

// Parse reads and validates a playbook. Unknown keys are refused, so a
// typo never silently drops a rule.
func Parse(b []byte) (*Playbook, error) {
	if len(b) > MaxBytes {
		return nil, invalid("larger than %d bytes", MaxBytes)
	}
	var p Playbook
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, invalid("%v", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	p.digest = "sha256:" + hex.EncodeToString(sum[:])
	return &p, nil
}

// Load reads a playbook file.
func Load(path string) (*Playbook, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func (p *Playbook) validate() error {
	switch {
	case p.APIVersion != APIVersion:
		return invalid("apiVersion must be %s", APIVersion)
	case !nameRe.MatchString(p.Name):
		return invalid("name %q", p.Name)
	case !semverRe.MatchString(p.Version):
		return invalid("version %q is not semver", p.Version)
	case !kindRe.MatchString(p.Kind):
		return invalid("kind %q", p.Kind)
	case strings.TrimSpace(p.Title) == "":
		return invalid("title is required")
	case strings.TrimSpace(p.Instructions) == "":
		return invalid("instructions are required")
	case len(p.Steps) == 0:
		return invalid("at least one step is required")
	}
	if _, ok := contract.OutputSchemaID(p.Output); !ok {
		return invalid("output %q is not a known output schema", p.Output)
	}
	switch analyst.ModelTier(p.ModelTier) {
	case analyst.TierSmall, analyst.TierLarge:
	default:
		return invalid("model_tier must be small or large")
	}
	for _, t := range p.Tools {
		if !toolRe.MatchString(t) {
			return invalid("tool %q", t)
		}
	}
	seen := map[string]bool{}
	for _, s := range p.Steps {
		if !stepRe.MatchString(s.ID) || seen[s.ID] {
			return invalid("step id %q is invalid or repeated", s.ID)
		}
		seen[s.ID] = true
		if strings.TrimSpace(s.Goal) == "" {
			return invalid("step %s has no goal", s.ID)
		}
		for _, t := range s.Tools {
			if !slices.Contains(p.Tools, t) {
				return invalid("step %s uses tool %s that the playbook does not list", s.ID, t)
			}
		}
	}
	for _, f := range p.RequiredEvidence {
		if !fieldRe.MatchString(f) {
			return invalid("required_evidence %q must be bundle:<field>", f)
		}
	}
	return p.Budgets.validate()
}

func (b Budgets) validate() error {
	switch {
	case b.Steps < 0 || b.Steps > 64, b.ToolCalls < 0 || b.ToolCalls > 64,
		b.Tokens < 0 || b.Tokens > 2000000, b.Seconds < 0 || b.Seconds > 3600, b.CostMicroUSD < 0:
		return invalid("budgets out of range")
	}
	return nil
}

// ID is name@version, the template id a result reports.
func (p *Playbook) ID() string { return p.Name + "@" + p.Version }

// Digest is the sha256 of the exact file bytes.
func (p *Playbook) Digest() string { return p.digest }

// Render turns the playbook into the instructions of one run.
func (p *Playbook) Render() analyst.Instructions {
	var b strings.Builder
	b.WriteString(p.Title)
	b.WriteString("\n\n")
	b.WriteString(strings.TrimSpace(p.Instructions))
	b.WriteString("\n\nSteps:\n")
	for i, s := range p.Steps {
		fmt.Fprintf(&b, "%d. %s: %s", i+1, s.ID, strings.TrimSpace(s.Goal))
		if len(s.Tools) > 0 {
			fmt.Fprintf(&b, " (tools: %s)", strings.Join(s.Tools, ", "))
		}
		b.WriteString("\n")
	}
	if len(p.RequiredEvidence) > 0 {
		b.WriteString("\nAlways read and cite: ")
		b.WriteString(strings.Join(p.RequiredEvidence, ", "))
		b.WriteString("\n")
	}
	if len(p.Rules) > 0 {
		b.WriteString("\nRules:\n")
		for _, r := range p.Rules {
			b.WriteString("- ")
			b.WriteString(strings.TrimSpace(r))
			b.WriteString("\n")
		}
	}
	tools := p.Tools
	if tools == nil {
		tools = []string{}
	}
	return analyst.Instructions{
		ID: p.ID(), Digest: p.digest, Text: b.String(), Tools: tools,
		Budgets: analyst.Budgets{Steps: p.Budgets.Steps, ToolCalls: p.Budgets.ToolCalls, Tokens: p.Budgets.Tokens,
			Seconds: p.Budgets.Seconds, CostMicroUSD: p.Budgets.CostMicroUSD},
	}
}

// Matches reports whether the playbook is for a subject with this source and
// category.
func (p *Playbook) Matches(source, category string) bool {
	return (len(p.Match.Sources) == 0 || slices.Contains(p.Match.Sources, source)) &&
		(len(p.Match.Categories) == 0 || slices.Contains(p.Match.Categories, category))
}

// RequireEvidence returns a verifier that refuses an answer whose verdict
// does not cite every required bundle field.
func (p *Playbook) RequireEvidence() analyst.Verifier {
	required := slices.Clone(p.RequiredEvidence)
	return requireEvidence(required)
}
