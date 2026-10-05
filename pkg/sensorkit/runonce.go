package sensorkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/openctemio/ctis"

	"github.com/openctemio/sdk-go/pkg/core"
)

// RunOnceOptions configure a one-shot run of the kit's scanners.
type RunOnceOptions struct {
	// Targets are the directories to scan (default ".").
	Targets []string
	// Out receives progress and the verdict (default io.Discard).
	Out io.Writer
}

// RunOnceResult is the outcome of RunOnce.
type RunOnceResult struct {
	// Reports pushed to the run.
	Reports int
	// ScanFailures counts scanners that failed to run or whose output could
	// not be parsed.
	ScanFailures int
	// Verdict is the platform's gate verdict.
	Verdict *CIVerdict
}

// RunOnce is runner mode: it runs every scanner added to the kit once on the
// targets, pushes each report to the CI run and asks the platform's gate for
// the verdict (api RFC-051). The run authenticates with the CI job's OIDC
// token (NewCIRun); the kit's API key is not used. A scanner that is not
// installed is skipped; one that fails, or whose output no parser reads,
// counts as a scan failure, which fails the gate.
func (k *Kit) RunOnce(ctx context.Context, run *CIRun, opts RunOnceOptions) (*RunOnceResult, error) {
	if run == nil {
		return nil, errors.New("RunOnce needs a CI run (NewCIRun)")
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	targets := opts.Targets
	if len(targets) == 0 {
		targets = []string{"."}
	}
	parsers := core.NewParserRegistry()
	for _, p := range k.parsers {
		parsers.Register(p)
	}
	res := &RunOnceResult{}
	for _, e := range k.scanners {
		name := e.s.Name()
		if ok, _, err := e.s.IsInstalled(ctx); err != nil || !ok {
			_, _ = fmt.Fprintf(out, "[%s] skipped: not installed\n", name)
			continue
		}
		for _, target := range targets {
			report, err := scanOnce(ctx, e.s, parsers, target)
			if err != nil {
				res.ScanFailures++
				_, _ = fmt.Fprintf(out, "[%s] %s: %v\n", name, target, err)
				continue
			}
			if report == nil {
				continue
			}
			if _, err := run.PushFindings(ctx, report); err != nil {
				return res, err
			}
			res.Reports++
			_, _ = fmt.Fprintf(out, "[%s] %s: %d finding(s) sent\n", name, target, len(report.Findings))
		}
	}
	v, err := run.Evaluate(ctx, res.ScanFailures)
	if err != nil {
		return res, err
	}
	res.Verdict = v
	WriteVerdict(out, v)
	return res, nil
}

// scanOnce runs one scanner on one target and parses its output; nil, nil
// when it found nothing.
func scanOnce(ctx context.Context, s core.Scanner, parsers *core.ParserRegistry, target string) (*ctis.Report, error) {
	result, err := s.Scan(ctx, target, &core.ScanOptions{TargetDir: target})
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	if result == nil || len(bytes.TrimSpace(result.RawOutput)) == 0 {
		return nil, nil
	}
	p, err := parsers.ForScanner(s.Name(), result.RawOutput)
	if err != nil {
		return nil, err
	}
	report, err := p.Parse(ctx, result.RawOutput, &core.ParseOptions{ToolName: s.Name(), BasePath: target})
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return report, nil
}
