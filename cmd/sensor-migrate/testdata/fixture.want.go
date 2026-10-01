// Command fixture is a sensor written against the pre-sensor SDK API.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/platform"
)

// AgentPool is the caller's own type: it must keep its name.
type AgentPool struct {
	agents []core.Sensor // caller's field: kept
}

// myAgent embeds the SDK base type; the embedded field is renamed with it.
type myAgent struct {
	*core.BaseSensor
	agentNote string // caller's field: kept
}

func newClient(agentID string) *client.Client {
	cfg := &client.Config{BaseURL: "https://api.example.com", APIKey: os.Getenv("API_KEY"), SensorID: agentID}
	_ = cfg.SensorID
	return client.New(cfg)
}

func main() {
	ctx := context.Background()
	agent := "a local variable called agent" // never touched
	fmt.Println(agent)

	cfg := &core.BaseSensorConfig{Name: "fixture", Version: "1.0.0"}
	if err := core.ValidateBaseSensorConfig(cfg); err != nil {
		panic(err)
	}
	m := &myAgent{BaseSensor: core.NewBaseSensor(cfg, nil), agentNote: "n"}
	var s core.Sensor = m
	_ = m.BaseSensor.Name()
	st := s.Status()
	if st.Status == core.SensorStateRunning {
		fmt.Println("running")
	}
	var state core.SensorState = core.SensorStateStopped
	_ = state

	pool := AgentPool{agents: []core.Sensor{s}}
	_ = pool

	_ = newClient(os.Getenv("AGENT_ID")) // string literal: never touched
	_ = client.NewWithOptions(client.WithSensorID("s-1"))

	creds, err := platform.EnsureRegistered(ctx, &platform.EnsureRegisteredConfig{BaseURL: "https://api.example.com"})
	if errors.Is(err, platform.ErrSensorAlreadyExists) {
		return
	}
	var stored *platform.SensorCredentials = creds
	fmt.Println(stored.SensorID)

	b := platform.NewSensorBuilder().WithCredentials("https://api.example.com", stored.APIKey, stored.SensorID)
	var pa *platform.PlatformSensor
	pa, _ = b.Build()
	_ = pa
}
