// Command openctem-conformance checks a tool written in any language
// against adapter protocol v1 and its contract, the way a sensor will run it.
// It is the older name of "openctem tool test" (cmd/openctem) and is kept
// as an alias for one minor release:
//
//	openctem-conformance tool path/to/tool.yaml
//	openctem-conformance tool -update path/to/tool.yaml   # rewrite fixture expectations
//
// It exits 0 when every check passes, 1 when one fails, 2 on a usage error.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/openctemio/sdk-go/internal/toolcli"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

func main() {
	executor.RunLauncherIfRequested()
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "tool" {
		_, _ = fmt.Fprintln(stderr, "usage: openctem-conformance tool [-update] [-timeout 30s] <tool.yaml>  (now: openctem tool test)")
		return toolcli.ExitUsage
	}
	fs := flag.NewFlagSet("tool", flag.ContinueOnError)
	fs.SetOutput(stderr)
	update := fs.Bool("update", false, "rewrite each fixture's expect file with what the tool produced")
	timeout := fs.Duration("timeout", 30*time.Second, "bound of each check")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: openctem-conformance tool [-update] [-timeout 30s] <tool.yaml>  (now: openctem tool test)")
		return toolcli.ExitUsage
	}
	return toolcli.Test(fs.Arg(0), conformance.ContractOptions{Timeout: *timeout}, *update, stdout)
}
