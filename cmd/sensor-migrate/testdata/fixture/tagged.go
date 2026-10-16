//go:build extra

package main

import "github.com/openctemio/sdk-go/pkg/client"

// extraSensorID only builds with -tags extra: the codemod must see it
// when run with -tags extra, in the same pass as the default build.
func extraSensorID(c *client.Config) string { return c.AgentID }
