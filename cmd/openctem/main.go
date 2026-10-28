// Command openctem is the OpenCTEM developer CLI. Its tool commands
// scaffold, check and run a tool the way a sensor runs it:
//
//	openctem tool init --kind exec-sarif --capability sast.code@1 ./acme-lint
//	openctem tool validate ./acme-lint
//	openctem tool run ./acme-lint --target ./src@repository
//	openctem tool test ./acme-lint --capability --scope --fuzz 30s
//	openctem tool diff old/tool.yaml new/tool.yaml
//	openctem tool describe --json ./acme-lint
//	openctem version
//
// Its agent commands scaffold an analyst playbook and run its golden set
// offline, as the platform's eval gate does:
//
//	openctem agent init --kind triage.v1 ./my-triage
//	openctem agent test ./my-triage
//
// Every task runs through the sensor runtime's host and sandbox
// (pkg/sensorkit/toolhost); nothing talks to a platform. Exit status: 0 ok,
// 1 a check failed, 2 a usage error.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/openctemio/sdk-go/internal/agentcli"
	"github.com/openctemio/sdk-go/internal/toolcli"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

func main() {
	executor.RunLauncherIfRequested()
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		return printVersion(stdout)
	}
	if len(args) == 2 && args[0] == "tool" && args[1] == "version" {
		return printVersion(stdout)
	}
	if len(args) > 0 && args[0] == "agent" {
		return agentcli.Main(args[1:], stdout, stderr)
	}
	if len(args) == 0 || args[0] != "tool" {
		_, _ = fmt.Fprintln(stderr, "usage: openctem <version | tool <init|validate|run|test|diff|describe|version> ... | agent <init|test> ...> (openctem tool help, openctem agent help)")
		return toolcli.ExitUsage
	}
	return toolcli.Main(args[1:], stdout, stderr)
}

// printVersion prints the CLI's version: the release it was built from (a
// "go install ...@vX.Y.Z" or a release binary), or "<sdk version>-devel" for a
// build from a checkout. useragent.SDKVersion holds that logic.
func printVersion(stdout io.Writer) int {
	_, _ = fmt.Fprintln(stdout, "openctem "+useragent.SDKVersion())
	return toolcli.ExitOK
}
