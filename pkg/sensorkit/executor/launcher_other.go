//go:build !linux

package executor

import (
	"errors"
	"os/exec"
)

var errNoSandbox = errors.New("the task sandbox is available on Linux only")

func confine(launchSpec) (Status, error) { return Status{Backend: "process"}, errNoSandbox }

func execTool(string, []string, []string) error { return errNoSandbox }

func makeUndumpable() {}

func confineAttrs(*exec.Cmd) {}

func setupNetwork(launchSpec) error { return errNoSandbox }

func superviseTool(string, []string, []string) int { return launcherExit }

func runConfined(launchSpec, []string) int { return launcherExit }
