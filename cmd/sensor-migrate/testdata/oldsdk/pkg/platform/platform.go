package platform

import (
	"context"
	"errors"
)

var ErrAgentAlreadyExists = errors.New("agent with this name already exists")

type AgentCredentials struct {
	AgentID   string `json:"agent_id"`
	APIKey    string `json:"api_key"`
	APIPrefix string `json:"api_prefix"`
}

type EnsureRegisteredConfig struct {
	BaseURL         string
	BootstrapToken  string
	CredentialsFile string
}

func EnsureRegistered(ctx context.Context, cfg *EnsureRegisteredConfig) (*AgentCredentials, error) {
	return &AgentCredentials{}, nil
}

type AgentBuilder struct{}

func NewAgentBuilder() *AgentBuilder { return &AgentBuilder{} }

func (b *AgentBuilder) WithCredentials(baseURL, apiKey, agentID string) *AgentBuilder { return b }

type PlatformAgent struct{}

func (b *AgentBuilder) Build() (*PlatformAgent, error) { return &PlatformAgent{}, nil }
