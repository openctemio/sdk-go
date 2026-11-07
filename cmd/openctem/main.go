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
// Its playbook commands scaffold an AI playbook and run its golden set
// offline, as the platform's eval gate does:
//
//	openctem playbook init --kind triage.v1 ./my-triage
//	openctem playbook test ./my-triage
//
// Its import command converts the output of a tool a person ran into CTIS
// and imports it into an organization with an API key (internal/importcli):
//
//	nmap -sV -oX - 192.0.2.0/24 | openctem import --format nmap --dry-run
//	gau example.com | openctem import --format lines --as url --tool gau
//
// targets export lists the organization's in-scope assets of one kind for
// such a tool, and run exports them, runs the person's command on them and
// imports its output:
//
//	openctem targets export --type domain > names.txt
//	openctem run --type ip --format nmap -- nmap -sV -iL {targets_file} -oX {output_file}
//
// Every tool and playbook task runs through the sensor runtime's host and
// sandbox (pkg/sensorkit/toolhost); only import, targets and run talk to a platform. Exit
// status: 0 ok, 1 a check failed, 2 a usage error (import adds 3: the upload
// is still queued).
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/openctemio/sdk-go/internal/importcli"
	"github.com/openctemio/sdk-go/internal/playbookcli"
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
	if len(args) > 0 && args[0] == "playbook" {
		return playbookcli.Main(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "import" {
		return importcli.Main(args[1:], os.Stdin, stdout, stderr, os.Getenv)
	}
	if len(args) > 0 && args[0] == "targets" {
		return importcli.TargetsMain(args[1:], stdout, stderr, os.Getenv)
	}
	if len(args) > 0 && args[0] == "run" {
		return importcli.RunMain(args[1:], stdout, stderr, os.Getenv)
	}
	if len(args) == 0 || args[0] != "tool" {
		_, _ = fmt.Fprintln(stderr, "usage: openctem <version | tool <init|validate|run|test|diff|describe|version> ... | playbook <init|test> ... | import [flags] [file ...] | targets export ... | run ... -- <command>> (openctem tool help, openctem playbook help, openctem import -h)")
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
