//go:build !unix

package core

import "os/exec"

func configureProcessGroup(*exec.Cmd) {}

func killProcessGroup(int) {}
