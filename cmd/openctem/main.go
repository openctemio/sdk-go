// Command openctem is the OpenCTEM developer CLI. Its tool commands
// scaffold, check and run a tool the way a sensor runs it:
//
//	openctem tool init --kind exec-sarif --capability sast.code@1 ./acme-lint
//	openctem tool validate ./acme-lint
//	openctem tool run ./acme-lint --target ./src@repository
//	openctem tool test ./acme-lint --capability --scope --fuzz 30s
//	openctem tool diff old/tool.yaml new/tool.yaml
//	openctem tool describe --json ./acme-lint
//
// Every task runs through the sensor runtime's host and sandbox
// (pkg/sensorkit/toolhost); nothing talks to a platform. Exit status: 0 ok,
// 1 a check failed, 2 a usage error.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/openctemio/sdk-go/internal/toolcli"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

func main() {
	executor.RunLauncherIfRequested()
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "tool" {
		_, _ = fmt.Fprintln(stderr, "usage: openctem tool <init|validate|run|test|diff|describe> ... (openctem tool help)")
		return toolcli.ExitUsage
	}
	return toolcli.Main(args[1:], stdout, stderr)
}
