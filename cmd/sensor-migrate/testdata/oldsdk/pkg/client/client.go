package client

import "time"

type Config struct {
	BaseURL string
	APIKey  string
	AgentID string
	Timeout time.Duration
}

type Client struct{ agentID string }

type Option func(*Client)

func WithAgentID(id string) Option { return func(c *Client) { c.agentID = id } }

func NewWithOptions(opts ...Option) *Client {
	c := &Client{}
	for _, o := range opts {
		o(c)
	}
	return c
}

func New(cfg *Config) *Client { return &Client{agentID: cfg.AgentID} }
