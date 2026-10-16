// Command fixture is a sensor written against the pre-sensor SDK API.
package main

import (
	"fmt"
	"os"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
)

// AgentPool is the caller's own type: it must keep its name.
type AgentPool struct {
	agents []core.Agent // caller's field: kept
}

// myAgent embeds the SDK base type; the embedded field is renamed with it.
type myAgent struct {
	*core.BaseAgent
	agentNote string // caller's field: kept
}

func newClient(agentID string) *client.Client {
	cfg := &client.Config{BaseURL: "https://api.example.com", APIKey: os.Getenv("API_KEY"), AgentID: agentID}
	_ = cfg.AgentID
	return client.New(cfg)
}

func main() {
	agent := "a local variable called agent" // never touched
	fmt.Println(agent)

	cfg := &core.BaseAgentConfig{Name: "fixture", Version: "1.0.0"}
	if err := core.ValidateBaseAgentConfig(cfg); err != nil {
		panic(err)
	}
	m := &myAgent{BaseAgent: core.NewBaseAgent(cfg, nil), agentNote: "n"}
	var s core.Agent = m
	_ = m.BaseAgent.Name()
	st := s.Status()
	if st.Status == core.AgentStateRunning {
		fmt.Println("running")
	}
	var state core.AgentState = core.AgentStateStopped
	_ = state

	pool := AgentPool{agents: []core.Agent{s}}
	_ = pool

	_ = newClient(os.Getenv("AGENT_ID")) // string literal: never touched
	_ = client.NewWithOptions(client.WithAgentID("s-1"))
}
