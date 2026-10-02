// Package recon runs the ProjectDiscovery recon tools (subfinder, dnsx,
// naabu, httpx, katana) as ordinary scanners.
//
// Each tool's package implements core.ReconScanner, which returns typed
// results (subdomains, DNS records, open ports, live hosts, URLs). A sensor's
// command executor runs core.Scanner and reads its raw output with a parser.
// Scanner bridges the two: it runs the recon tool on every target, converts
// the results with ctis.ConvertReconToCTIS (the one recon-to-CTIS converter)
// and returns the CTIS report as its raw output, which the generic CTIS JSON
// parser reads. Discovered hosts, IPs, services and URLs then reach the
// platform as assets through normal ingest.
package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/scanners/recon/dnsx"
	"github.com/openctemio/sdk-go/pkg/scanners/recon/httpx"
	"github.com/openctemio/sdk-go/pkg/scanners/recon/katana"
	"github.com/openctemio/sdk-go/pkg/scanners/recon/naabu"
	"github.com/openctemio/sdk-go/pkg/scanners/recon/subfinder"
)

// Tools are the recon tools this package runs, in pipeline order.
var Tools = []string{"subfinder", "dnsx", "naabu", "httpx", "katana"}

// capabilities are the capability names the platform's tool catalog gives
// each recon tool. A sensor advertises them, and the platform offers a job
// whose required capabilities they cover.
var capabilities = map[string][]string{
	"subfinder": {"recon", "subdomain"},
	"dnsx":      {"recon", "dns"},
	"naabu":     {"recon", "portscan"},
	"httpx":     {"recon", "http", "tech_detect"},
	"katana":    {"recon", "crawler", "url_discovery"},
}

// Capabilities returns the platform capability names of a recon tool, or
// nil for a name that is not one.
func Capabilities(tool string) []string {
	caps := capabilities[tool]
	if caps == nil {
		return nil
	}
	return append([]string(nil), caps...)
}

// IsTool reports whether name is a recon tool this package runs.
func IsTool(name string) bool {
	_, ok := capabilities[name]
	return ok
}

// New returns the recon tool name as a core.Scanner, with the tool's
// defaults (naabu: connect scan of the top 100 ports, no root needed). An
// unknown name is an error.
func New(name string) (*Scanner, error) {
	var rs core.ReconScanner
	switch name {
	case "subfinder":
		rs = subfinder.NewScanner()
	case "dnsx":
		rs = dnsx.NewScanner()
	case "naabu":
		rs = naabu.NewScanner()
	case "httpx":
		rs = httpx.NewScanner()
	case "katana":
		rs = katana.NewScanner()
	default:
		return nil, fmt.Errorf("unknown recon tool: %s", name)
	}
	return NewScanner(rs), nil
}

// Scanner runs a core.ReconScanner as a core.Scanner whose raw output is a
// CTIS report. It is a core.MultiTargetScanner: a job with several targets
// runs the tool on each in turn and returns one report.
type Scanner struct {
	recon core.ReconScanner
	caps  []string
	// Options are passed to every recon run (threads, rate limit,
	// resolvers). The job's extra arguments and environment are added.
	Options core.ReconOptions
}

// NewScanner wraps rs. It advertises the platform capabilities of rs's
// tool, or rs's recon type for a tool the catalog does not know.
func NewScanner(rs core.ReconScanner) *Scanner {
	caps := Capabilities(rs.Name())
	if caps == nil {
		caps = []string{"recon", string(rs.Type())}
	}
	return &Scanner{recon: rs, caps: caps}
}

// Recon returns the wrapped recon scanner (to adjust its settings).
func (s *Scanner) Recon() core.ReconScanner { return s.recon }

// Name returns the tool name.
func (s *Scanner) Name() string { return s.recon.Name() }

// Version returns the tool version (known after IsInstalled).
func (s *Scanner) Version() string { return s.recon.Version() }

// Capabilities returns the platform capabilities of the tool.
func (s *Scanner) Capabilities() []string { return append([]string(nil), s.caps...) }

// IsInstalled reports whether the tool's binary answers its version flag.
// A binary that is on PATH but does not run is not installed: the sensor
// must not advertise a tool it cannot run.
func (s *Scanner) IsInstalled(ctx context.Context) (bool, string, error) {
	return s.recon.IsInstalled(ctx)
}

// Scan runs the tool on one target.
func (s *Scanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	return s.ScanTargets(ctx, []string{target}, opts)
}

// ErrToolFailed reports a recon run that did not complete. Its results are
// not reported: a failed run must fail its job, not complete with 0 assets.
var ErrToolFailed = errors.New("recon tool failed")

// ScanTargets runs the tool on each target and returns one CTIS report with
// everything found. A run that fails on any target fails the whole job.
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, opts *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()
	name := s.recon.Name()
	in := &ctis.ReconToCTISInput{
		ScannerName: name,
		ReconType:   string(s.recon.Type()),
		Target:      strings.Join(targets, ","),
		StartedAt:   start.Unix(),
	}
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ro := s.Options
		ro.Target = t
		if opts != nil {
			ro.ExtraArgs = append(append([]string(nil), ro.ExtraArgs...), opts.ExtraArgs...)
			if len(opts.Env) > 0 {
				ro.Env = mergeEnv(ro.Env, opts.Env)
			}
			ro.Verbose = ro.Verbose || opts.Verbose
		}
		res, err := s.recon.Scan(ctx, t, &ro)
		if err != nil {
			return nil, fmt.Errorf("%w: %s on %s: %w", ErrToolFailed, name, t, err)
		}
		if res == nil {
			return nil, fmt.Errorf("%w: %s on %s returned no result", ErrToolFailed, name, t)
		}
		if res.Error != "" {
			return nil, fmt.Errorf("%w: %s on %s: %s", ErrToolFailed, name, t, res.Error)
		}
		// The ProjectDiscovery tools exit 0 when they finish, results or
		// not; any other exit (an unknown flag exits 2, a missing input 1)
		// means the run did not happen.
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("%w: %s on %s exited with status %d", ErrToolFailed, name, t, res.ExitCode)
		}
		if in.ScannerVersion == "" {
			in.ScannerVersion = res.ScannerVersion
		}
		appendResult(in, res)
	}
	finished := time.Now()
	in.FinishedAt = finished.Unix()
	in.DurationMs = finished.Sub(start).Milliseconds()
	if in.ScannerVersion == "" {
		in.ScannerVersion = s.recon.Version()
	}

	convOpts := ctis.DefaultReconConverterOptions()
	convOpts.DiscoveryTool = name
	report, err := ctis.ConvertReconToCTIS(in, convOpts)
	if err != nil {
		return nil, fmt.Errorf("convert %s results: %w", name, err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode %s report: %w", name, err)
	}
	return &core.ScanResult{
		ScannerName:    name,
		ScannerVersion: in.ScannerVersion,
		StartedAt:      in.StartedAt,
		FinishedAt:     in.FinishedAt,
		DurationMs:     in.DurationMs,
		RawOutput:      raw,
	}, nil
}

// appendResult adds one run's results to the converter input.
func appendResult(in *ctis.ReconToCTISInput, r *core.ReconResult) {
	for _, s := range r.Subdomains {
		in.Subdomains = append(in.Subdomains, ctis.SubdomainInput{Host: s.Host, Domain: s.Domain, Source: s.Source, IPs: s.IPs})
	}
	for _, d := range r.DNSRecords {
		in.DNSRecords = append(in.DNSRecords, ctis.DNSRecordInput{
			Host: d.Host, RecordType: d.RecordType, Values: d.Values, TTL: d.TTL, Resolver: d.Resolver, StatusCode: d.StatusCode,
		})
	}
	for _, p := range r.OpenPorts {
		in.OpenPorts = append(in.OpenPorts, ctis.OpenPortInput{
			Host: p.Host, IP: p.IP, Port: p.Port, Protocol: p.Protocol, Service: p.Service, Version: p.Version, Banner: p.Banner,
		})
	}
	for _, h := range r.LiveHosts {
		in.LiveHosts = append(in.LiveHosts, ctis.LiveHostInput{
			URL: h.URL, Host: h.Host, IP: h.IP, Port: h.Port, Scheme: h.Scheme, StatusCode: h.StatusCode,
			ContentLength: h.ContentLength, Title: h.Title, WebServer: h.WebServer, ContentType: h.ContentType,
			Technologies: h.Technologies, CDN: h.CDN, TLSVersion: h.TLSVersion, Redirect: h.Redirect, ResponseTime: h.ResponseTime,
		})
	}
	for _, u := range r.URLs {
		in.URLs = append(in.URLs, ctis.DiscoveredURLInput{
			URL: u.URL, Method: u.Method, Source: u.Source, StatusCode: u.StatusCode, Depth: u.Depth,
			Parent: u.Parent, Type: u.Type, Extension: u.Extension,
		})
	}
	for _, t := range r.Technologies {
		in.Technologies = append(in.Technologies, ctis.TechnologyInput{
			Name: t.Name, Version: t.Version, Categories: t.Categories, Confidence: t.Confidence, Website: t.Website,
		})
	}
}

func mergeEnv(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

var _ core.MultiTargetScanner = (*Scanner)(nil)
