//go:build !linux

package executor

import "errors"

var errNoSandbox = errors.New("the task sandbox is available on Linux only")

func confine(launchSpec) (Status, error) { return Status{Backend: "process"}, errNoSandbox }

func execTool(string, []string, []string) error { return errNoSandbox }

func makeUndumpable() {}
