// Command openctem-conformance checks a tool written in any language
// against adapter protocol v1, the way a sensor will run it (see
// conformance.RunToolSuite and docs/adapter-protocol.md):
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

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

func main() {
	executor.RunLauncherIfRequested()
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "tool" {
		_, _ = fmt.Fprintln(stderr, "usage: openctem-conformance tool [-update] [-timeout 30s] <tool.yaml>")
		return 2
	}
	fs := flag.NewFlagSet("tool", flag.ContinueOnError)
	fs.SetOutput(stderr)
	update := fs.Bool("update", false, "rewrite each fixture's expect file with what the tool produced")
	timeout := fs.Duration("timeout", 30*time.Second, "bound of each check")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: openctem-conformance tool [-update] [-timeout 30s] <tool.yaml>")
		return 2
	}
	r := &reporter{out: stdout}
	func() {
		defer func() {
			if v := recover(); v != nil && v != errFatal {
				panic(v)
			}
		}()
		conformance.RunToolSuite(r, fs.Arg(0), conformance.ToolSuiteOptions{Timeout: *timeout, Update: *update})
	}()
	if r.failed {
		_, _ = fmt.Fprintln(stdout, "FAIL")
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "PASS")
	return 0
}

// errFatal stops the suite at a Fatalf, as testing.T does.
var errFatal = fmt.Errorf("fatal")

type reporter struct {
	out    io.Writer
	failed bool
}

func (r *reporter) Helper() {}

func (r *reporter) Logf(format string, args ...any) {
	_, _ = fmt.Fprintf(r.out, "  note: "+format+"\n", args...)
}

func (r *reporter) Errorf(format string, args ...any) {
	r.failed = true
	_, _ = fmt.Fprintf(r.out, "  FAIL: "+format+"\n", args...)
}

func (r *reporter) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	panic(errFatal)
}
