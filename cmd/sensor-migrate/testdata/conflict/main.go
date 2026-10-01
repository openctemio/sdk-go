package main

import "github.com/openctemio/sdk-go/pkg/client"

// wrapped embeds client.Config and declares its own SensorID: renaming
// w.AgentID to w.SensorID would silently read the caller's field instead.
type wrapped struct {
	client.Config
	SensorID string
}

func main() {
	w := wrapped{SensorID: "mine"}
	w.AgentID = "sdk"
	_ = w
}
