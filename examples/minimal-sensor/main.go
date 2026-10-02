// Example: a complete OpenCTEM sensor in one file.
//
// The sensor implements one tool (an in-process scanner that reports .env
// files left in a directory); pkg/sensorkit does everything else: settings,
// platform connection, heartbeat with the tool inventory, doorbell, command
// queue, outbox, key renewal and graceful shutdown.
//
//	go build -o minimal-sensor ./examples/minimal-sensor
//	API_URL=https://openctem.example.com API_KEY=<sensor key> \
//	SENSOR_SCAN_ROOTS=/srv/code ./minimal-sensor
//
// Dispatch a scan with tool "dotenv-check" from the platform, or run with
// -target <dir> to also scan a directory every hour.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	target := flag.String("target", "", "Directory to scan every hour (optional)")
	flag.Parse()

	opts := sensorkit.Options{
		Name: "minimal-sensor", Version: version,
		// Findings belong to an asset: here, the scanned directory.
		AssetResolver: func(_, target string) (ctis.AssetType, string) {
			abs, _ := filepath.Abs(target)
			return ctis.AssetTypeRepository, abs
		},
	}
	if *target != "" {
		opts.Targets = []string{*target}
	}
	kit, err := sensorkit.New(opts) // reads API_URL, API_KEY, SENSOR_* ...
	sensorkit.Exit(err)
	kit.AddScanner(dotenvScanner{})
	sensorkit.Exit(kit.Run(context.Background())) // blocks until SIGINT/SIGTERM
}

// dotenvScanner is the sensor's only tool. A tool that runs a binary embeds
// core.BaseScanner instead (core.NewBaseScanner) and gets IsInstalled and Scan.
type dotenvScanner struct{}

func (dotenvScanner) Name() string           { return "dotenv-check" }
func (dotenvScanner) Version() string        { return "1.0.0" }
func (dotenvScanner) Capabilities() []string { return []string{"secrets"} }

// IsInstalled: an in-process tool is always available.
func (dotenvScanner) IsInstalled(context.Context) (bool, string, error) { return true, "1.0.0", nil }

// Scan reports every .env file under target as SARIF, which the SDK parses
// and delivers (through the outbox) by itself.
func (s dotenvScanner) Scan(ctx context.Context, target string, _ *core.ScanOptions) (*core.ScanResult, error) {
	start := time.Now()
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string            `json:"ruleId"`
		Level     string            `json:"level"`
		Message   map[string]string `json:"message"`
		Locations []location        `json:"locations"`
	}
	results := []result{}
	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() && (d.Name() == ".env" || strings.HasPrefix(d.Name(), ".env.")) {
			var loc location
			loc.PhysicalLocation.ArtifactLocation.URI, _ = filepath.Rel(target, path)
			results = append(results, result{
				RuleID: "dotenv-file", Level: "warning", Locations: []location{loc},
				Message: map[string]string{"text": "Environment file with possible secrets in the source tree"},
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sarif := map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": s.Name(), "version": s.Version()}},
			"results": results,
		}},
	}
	out, _ := json.Marshal(sarif)
	return &core.ScanResult{
		ScannerName: s.Name(), ScannerVersion: s.Version(), RawOutput: out,
		StartedAt: start.Unix(), FinishedAt: time.Now().Unix(), DurationMs: time.Since(start).Milliseconds(),
	}, nil
}

// Keep the example honest: it must stay a core.Scanner.
var _ core.Scanner = dotenvScanner{}
