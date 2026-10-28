package harness

import (
	"fmt"
	"sync"
	"time"
)

// Budgets bound one run. Zero means "use the default"; the effective budget
// is the smaller of the grant's and the playbook's, never larger than either.
type Budgets struct {
	Steps        int   `json:"steps,omitempty"`
	ToolCalls    int   `json:"tool_calls,omitempty"`
	Tokens       int   `json:"tokens,omitempty"`
	Seconds      int   `json:"seconds,omitempty"`
	CostMicroUSD int64 `json:"cost_micro_usd,omitempty"`
}

// Default budgets when neither the grant nor the playbook sets one.
var DefaultBudgets = Budgets{Steps: 12, ToolCalls: 8, Tokens: 60000, Seconds: 300}

// Narrow returns the tighter of b and o, field by field (zero = unset).
func (b Budgets) Narrow(o Budgets) Budgets {
	return Budgets{
		Steps:        minSet(b.Steps, o.Steps),
		ToolCalls:    minSet(b.ToolCalls, o.ToolCalls),
		Tokens:       minSet(b.Tokens, o.Tokens),
		Seconds:      minSet(b.Seconds, o.Seconds),
		CostMicroUSD: minSet(b.CostMicroUSD, o.CostMicroUSD),
	}
}

// withDefaults fills unset fields from DefaultBudgets (cost stays unset:
// cost is capped only when someone set a cap).
func (b Budgets) withDefaults() Budgets {
	if b.Steps == 0 {
		b.Steps = DefaultBudgets.Steps
	}
	if b.ToolCalls == 0 {
		b.ToolCalls = DefaultBudgets.ToolCalls
	}
	if b.Tokens == 0 {
		b.Tokens = DefaultBudgets.Tokens
	}
	if b.Seconds == 0 {
		b.Seconds = DefaultBudgets.Seconds
	}
	return b
}

func minSet[T int | int64](a, b T) T {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	}
	return b
}

// BudgetError says which budget a run hit. Which is a fixed code.
type BudgetError struct{ Which string }

func (e *BudgetError) Error() string { return "harness: budget exhausted: " + e.Which }

// Meter counts what a run used against its budgets. Safe for concurrent use
// (parallel tool calls).
type Meter struct {
	mu        sync.Mutex
	limit     Budgets
	steps     int
	toolCalls int
	tokensIn  int
	tokensOut int
	cost      int64
	started   time.Time
	finalUsed bool
}

// NewMeter starts a meter with the given (already narrowed) budgets.
func NewMeter(b Budgets, now time.Time) *Meter {
	return &Meter{limit: b.withDefaults(), started: now}
}

// Limit returns the effective budgets.
func (m *Meter) Limit() Budgets { return m.limit }

// Step reserves one model call.
func (m *Meter) Step() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.steps >= m.limit.Steps {
		return &BudgetError{Which: "steps"}
	}
	m.steps++
	return nil
}

// finalStep reserves the one extra model call a run gets after a budget
// stop, to answer with what it has. A second one is refused.
func (m *Meter) finalStep() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.finalUsed {
		return &BudgetError{Which: "steps"}
	}
	m.finalUsed = true
	m.steps++
	return nil
}

// ToolCall reserves one tool call.
func (m *Meter) ToolCall() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.toolCalls >= m.limit.ToolCalls {
		return &BudgetError{Which: "tool_calls"}
	}
	m.toolCalls++
	return nil
}

// Add records a call's usage and returns a BudgetError once tokens or cost
// are over the limit (the call already happened; the next one is refused).
func (m *Meter) Add(u Usage, costMicroUSD int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokensIn += u.InputTokens
	m.tokensOut += u.OutputTokens
	m.cost += costMicroUSD
	if m.tokensIn+m.tokensOut >= m.limit.Tokens {
		return &BudgetError{Which: "tokens"}
	}
	if m.limit.CostMicroUSD > 0 && m.cost >= m.limit.CostMicroUSD {
		return &BudgetError{Which: "cost"}
	}
	return nil
}

// Snapshot is the usage so far.
type Snapshot struct {
	Steps, ToolCalls, TokensIn, TokensOut int
	CostMicroUSD                          int64
}

// Snapshot returns the usage so far.
func (m *Meter) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{Steps: m.steps, ToolCalls: m.toolCalls, TokensIn: m.tokensIn, TokensOut: m.tokensOut, CostMicroUSD: m.cost}
}

// Wall is the wall-clock budget.
func (m *Meter) Wall() time.Duration { return time.Duration(m.limit.Seconds) * time.Second }

func (s Snapshot) String() string {
	return fmt.Sprintf("steps=%d tool_calls=%d tokens=%d/%d cost=%d", s.Steps, s.ToolCalls, s.TokensIn, s.TokensOut, s.CostMicroUSD)
}
