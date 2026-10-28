package harness

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
)

// Role of a message in a conversation with a model.
type Role string

// Roles. The system prompt is Request.System, never a message, so text from
// a bundle or a tool can never be placed in the system role.
const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// ToolCall is one tool request from the model. Args is the raw JSON the
// model wrote; it is untrusted until the policy and the tool's schema accept it.
type ToolCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// ToolResult is what the harness returns to the model for one call: the
// fenced tool output, or a typed refusal (Code) when the call was denied.
type ToolResult struct {
	CallID  string `json:"call_id"`
	Name    string `json:"name"`
	Content string `json:"content"`
	IsError bool   `json:"is_error,omitempty"`
	Code    string `json:"code,omitempty"`
}

// Message is one turn. An assistant message may carry tool calls; a tool
// message carries their results, in the same order.
type Message struct {
	Role        Role         `json:"role"`
	Text        string       `json:"text,omitempty"`
	ToolCalls   []ToolCall   `json:"tool_calls,omitempty"`
	ToolResults []ToolResult `json:"tool_results,omitempty"`
}

// ToolSpec is how a tool is described to the model.
type ToolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Request is one model call. OutputSchema, when set, asks providers that
// support it for structured output; the harness validates the answer
// whatever the provider does.
type Request struct {
	Model        string          `json:"model"`
	System       string          `json:"system"`
	Messages     []Message       `json:"messages"`
	Tools        []ToolSpec      `json:"tools,omitempty"`
	MaxTokens    int             `json:"max_tokens,omitempty"`
	Temperature  float64         `json:"temperature"`
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`
	// CacheKey groups requests that share a prefix (the system prompt and
	// the playbook) so a provider adapter can mark it cacheable. It never
	// spans organizations: the harness derives it from the tenant.
	CacheKey string `json:"cache_key,omitempty"`
}

// StopReason says why a model turn ended.
type StopReason string

// Stop reasons, normalized across providers.
const (
	StopEnd       StopReason = "end"
	StopToolUse   StopReason = "tool_use"
	StopMaxTokens StopReason = "max_tokens"
	StopRefusal   StopReason = "refusal"
)

// Usage is the token usage of one call.
type Usage struct {
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	CacheReadTokens  int `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens int `json:"cache_write_tokens,omitempty"`
}

// Response is one model answer.
type Response struct {
	Message Message    `json:"message"`
	Stop    StopReason `json:"stop"`
	Usage   Usage      `json:"usage"`
	Model   string     `json:"model"`
}

// Provider is one model API behind one interface (anthropic, openai, gemini,
// openai_compatible for local and self-hosted models). An adapter only
// translates; it never executes a tool, retries a tool or widens a request.
// Credentials stay in the adapter or in the egress forwarder that adds the
// auth header, never in a message.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// Pricer prices one call in micro USD. The platform recomputes cost from its
// own price table; the worker's figure only enforces the run budget.
type Pricer interface {
	CostMicroUSD(model string, u Usage) int64
}

// ErrReplayExhausted is returned by Replay when the script has no more turns.
var ErrReplayExhausted = errors.New("harness: replay script exhausted")

// Replay is a Provider that answers from a recorded script, in order. It is
// how a run is replayed from its record, how the eval harness runs a golden
// set offline, and how tests play a hostile model. It records every request
// it receives.
type Replay struct {
	ProviderName string
	Turns        []Response

	mu       sync.Mutex
	next     int
	requests []Request
}

// Name implements Provider.
func (r *Replay) Name() string {
	if r.ProviderName == "" {
		return "replay"
	}
	return r.ProviderName
}

// Complete implements Provider.
func (r *Replay) Complete(ctx context.Context, req Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	if r.next >= len(r.Turns) {
		return Response{}, ErrReplayExhausted
	}
	resp := r.Turns[r.next]
	r.next++
	return resp, nil
}

// Requests returns the requests received so far.
func (r *Replay) Requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Request(nil), r.requests...)
}
