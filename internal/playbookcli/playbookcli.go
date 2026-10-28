// Package playbookcli implements "openctem playbook": scaffold and test an AI
// playbook offline, the way the platform's eval gate runs it. Nothing here
// talks to a platform, a model or a target: tests replay recorded turns and
// recorded tool outputs.
package playbookcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openctemio/sdk-go/pkg/harness/eval"
	"github.com/openctemio/sdk-go/pkg/harness/playbook"
)

// Exit codes (same as openctem tool).
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

const usage = `usage: openctem playbook <command> [flags]

  init  [--name my-triage] [--kind triage.v1] <dir>   scaffold a playbook and one golden case
  test  [--json] [--min-agreement 0.9] [dir]          validate the playbook and run its golden set offline
`

// Main runs "openctem playbook <args>".
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "init":
		return cmdInit(args[1:], stdout, stderr)
	case "test":
		return cmdTest(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return ExitOK
	}
	_, _ = fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
	return ExitUsage
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

var kindOutputs = map[string]string{
	"triage.v1":      "openctem.ai.triage/v1",
	"remediation.v1": "openctem.ai.remediation/v1",
	"summary.v1":     "openctem.ai.summary/v1",
}

func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "playbook name (default: the directory name)")
	kind := fs.String("kind", "triage.v1", "analyze kind: triage.v1, remediation.v1 or summary.v1")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	dir := fs.Arg(0)
	if *name == "" {
		*name = filepath.Base(filepath.Clean(dir))
	}
	output, ok := kindOutputs[*kind]
	if !nameRe.MatchString(*name) || !ok {
		_, _ = fmt.Fprintln(stderr, "name must match ^[a-z][a-z0-9-]{1,62}$ and kind must be triage.v1, remediation.v1 or summary.v1")
		return ExitUsage
	}
	if _, err := os.Stat(filepath.Join(dir, "playbook.yaml")); err == nil {
		_, _ = fmt.Fprintln(stderr, "playbook.yaml already exists; nothing written")
		return ExitFail
	}
	if err := os.MkdirAll(filepath.Join(dir, "golden"), 0o750); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	files := map[string]string{
		"playbook.yaml":          fmt.Sprintf(playbookTemplate, *name, *kind, output),
		"golden/01-example.json": exampleCase(*kind),
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o640); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return ExitFail
		}
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s/playbook.yaml and %s/golden/01-example.json\nnext: edit them, then run: openctem playbook test %s\n", dir, dir, dir)
	return ExitOK
}

func cmdTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	minAgree := fs.Float64("min-agreement", eval.DefaultGate.MinAgreement, "minimum share of golden cases that must pass")
	if err := fs.Parse(args); err != nil || fs.NArg() > 1 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	dir := "."
	if fs.NArg() == 1 {
		dir = fs.Arg(0)
	}
	pb, err := playbook.Load(filepath.Join(dir, "playbook.yaml"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "playbook:", err)
		return ExitFail
	}
	cases, err := eval.LoadDir(filepath.Join(dir, "golden"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	rep, err := eval.Run(context.Background(), pb, cases, eval.Options{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitFail
	}
	gate := eval.DefaultGate
	gate.MinAgreement = *minAgree
	gateErr := gate.Check(rep)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printReport(stdout, rep)
	}
	if gateErr != nil {
		if errors.Is(gateErr, eval.ErrGate) {
			_, _ = fmt.Fprintln(stderr, gateErr)
		}
		return ExitFail
	}
	return ExitOK
}

func printReport(w io.Writer, r eval.Report) {
	_, _ = fmt.Fprintf(w, "playbook %s (%s)\n", r.Playbook, r.PlaybookDigest)
	for _, c := range r.Results {
		mark := "PASS"
		if !c.Pass {
			mark = "FAIL"
		}
		_, _ = fmt.Fprintf(w, "  %s  %-36s %-10s %s", mark, c.Name, c.Status, c.Verdict)
		if len(c.Reasons) > 0 {
			_, _ = fmt.Fprintf(w, "  (%s)", strings.Join(c.Reasons, "; "))
		}
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintf(w, "agreement %.2f  risk-lowering precision %.2f  injection %d/%d  tokens %d/%d\n",
		r.Agreement, r.RiskLoweringPrecision, r.InjectionPassed, r.InjectionCases, r.TokensIn, r.TokensOut)
}

const playbookTemplate = `apiVersion: openctem.io/playbook/v1
name: %s
version: 0.1.0
title: Describe what this playbook decides
kind: %s
output: %s
model_tier: small
tools: []
required_evidence: [bundle:finding.evidence]
budgets:
  steps: 4
  tokens: 30000
  seconds: 120
steps:
  - id: read
    goal: Read the finding and its evidence.
  - id: decide
    goal: Decide, citing the evidence.
instructions: |
  Write the instructions for the analyst here: what to look at, what counts as proof,
  and when to answer needs_info instead of guessing.
`

// exampleAnswers is a recorded answer per kind that satisfies its schema.
var exampleAnswers = map[string]struct{ answer, expect string }{
	"triage.v1": {`{\"suggestions\":[{\"kind\":\"verdict\",\"payload\":{\"verdict\":\"needs_info\",\"reason\":\"Replace this recorded answer with one from a real run.\"},\"confidence\":0.5,\"evidence\":[{\"ref\":\"bundle:finding.evidence\"}]}]}`,
		`{"status": "completed", "verdict": "needs_info"}`},
	"remediation.v1": {`{\"suggestions\":[{\"kind\":\"remediation_steps\",\"payload\":{\"steps\":[{\"step\":1,\"description\":\"Replace this recorded answer with one from a real run.\"}]},\"confidence\":0.5,\"evidence\":[{\"ref\":\"bundle:finding.evidence\"}]}]}`,
		`{"status": "completed"}`},
	"summary.v1": {`{\"suggestions\":[{\"kind\":\"summary\",\"payload\":{\"text\":\"Replace this recorded answer with one from a real run.\"},\"confidence\":0.5,\"evidence\":[{\"ref\":\"bundle:finding.evidence\"}]}]}`,
		`{"status": "completed"}`},
}

func exampleCase(kind string) string {
	a := exampleAnswers[kind]
	return fmt.Sprintf(exampleCaseTemplate, a.answer, a.expect)
}

const exampleCaseTemplate = `{
  "name": "example",
  "bundle": {
    "finding.title": "Example finding on HOST_AAAAAA",
    "finding.severity": "medium",
    "finding.evidence": "The scanner observed the reported behavior."
  },
  "grant": {"tools": [], "targets": [], "tier_ceiling": "passive", "budgets": {"steps": 4}},
  "model": [
    {"message": {"role": "assistant", "text": "%s"}, "stop": "end", "usage": {"input_tokens": 1000, "output_tokens": 80}}
  ],
  "expect": %s
}
`
