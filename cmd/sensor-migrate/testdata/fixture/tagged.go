//go:build extra

package main

import "github.com/openctemio/sdk-go/pkg/platform"

// extraCredentials only builds with -tags extra: the codemod must see it
// when run with -tags extra, in the same pass as the default build.
func extraCredentials(c *platform.AgentCredentials) string { return c.AgentID }
