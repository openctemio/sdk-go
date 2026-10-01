package core

import "context"

type AgentState string

const (
	AgentStateRunning AgentState = "running"
	AgentStateStopped AgentState = "stopped"
)

type AgentStatus struct {
	Name   string
	Status AgentState
}

type Agent interface {
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Status() *AgentStatus
}

type Pusher interface{}

type BaseAgentConfig struct {
	Name    string
	Version string
}

type BaseAgent struct{ name string }

func NewBaseAgent(cfg *BaseAgentConfig, pusher Pusher) *BaseAgent { return &BaseAgent{name: cfg.Name} }

func (a *BaseAgent) Name() string                    { return a.name }
func (a *BaseAgent) Start(ctx context.Context) error { return nil }
func (a *BaseAgent) Stop(ctx context.Context) error  { return nil }
func (a *BaseAgent) Status() *AgentStatus            { return &AgentStatus{Name: a.name} }

func ValidateBaseAgentConfig(cfg *BaseAgentConfig) error { return nil }
