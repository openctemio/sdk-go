package core_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/mocks"
)

// One nuclei result: a single JSON object, the case that used to decode as an
// empty SARIF log (no "runs") and be reported as 0 findings.
const oneNucleiLine = `{"template-id":"git-config","info":{"name":"Git Config","severity":"medium"},"type":"http","host":"http://203.0.113.10","matched-at":"http://203.0.113.10/.git/config","ip":"203.0.113.10","timestamp":"2026-10-01T00:00:00Z"}`

type rawScanner struct {
	name string
	out  string
}

func (s *rawScanner) Name() string                                      { return s.name }
func (s *rawScanner) Version() string                                   { return "test" }
func (s *rawScanner) Capabilities() []string                            { return nil }
func (s *rawScanner) IsInstalled(context.Context) (bool, string, error) { return true, "test", nil }
func (s *rawScanner) Scan(context.Context, string, *core.ScanOptions) (*core.ScanResult, error) {
	return &core.ScanResult{ScannerName: s.name, RawOutput: []byte(s.out)}, nil
}

func scanCommand(t *testing.T, scanner, target string) *core.Command {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"scanner": scanner, "target": target})
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: "cmd-1", Type: "scan", Payload: payload}
}

func TestSARIFParserRejectsNonSARIF(t *testing.T) {
	p := &core.SARIFParser{}
	for name, data := range map[string]string{
		"one nuclei line":   oneNucleiLine,
		"two nuclei lines":  oneNucleiLine + "\n" + oneNucleiLine,
		"json without runs": `{"version":"2.1.0"}`,
		"runs not an array": `{"version":"2.1.0","runs":{}}`,
		"plain text":        "nothing to see",
	} {
		if p.CanParse([]byte(data)) {
			t.Errorf("%s: CanParse = true", name)
		}
		if _, err := p.Parse(context.Background(), []byte(data), nil); err == nil {
			t.Errorf("%s: Parse succeeded; non-SARIF data must be an error, not an empty report", name)
		}
	}
	if !p.CanParse([]byte(`{"version":"2.1.0","runs":[]}`)) {
		t.Error("an empty SARIF log must still parse")
	}
}

func TestForScannerNeverDefaultsToEmpty(t *testing.T) {
	r := core.NewParserRegistry()
	if _, err := r.ForScanner("nuclei", []byte(oneNucleiLine)); err == nil {
		t.Fatal("output no parser recognizes must be an error")
	}
	var nilRegistry *core.ParserRegistry
	if _, err := nilRegistry.ForScanner("nuclei", []byte(oneNucleiLine)); err == nil {
		t.Fatal("without a registry, non-SARIF output must be an error")
	}
	p, err := nilRegistry.ForScanner("x", []byte(`{"version":"2.1.0","runs":[]}`))
	if err != nil || p.Name() != "sarif" {
		t.Fatalf("without a registry SARIF output uses the SARIF parser, got %v, %v", p, err)
	}
}

// A scan whose output no parser can read fails the command; it must not
// complete with 0 findings while the scanner matched.
func TestExecuteScanFailsOnUnreadableOutput(t *testing.T) {
	pusher := &mocks.MockPusher{}
	exec := core.NewDefaultCommandExecutor(pusher)
	exec.SetParserRegistry(core.NewParserRegistry())
	exec.AddScanner(&rawScanner{name: "nuclei", out: oneNucleiLine})

	_, err := exec.Execute(context.Background(), scanCommand(t, "nuclei", "http://203.0.113.10"))
	if err == nil || !strings.Contains(err.Error(), "no parser recognizes") {
		t.Fatalf("want a parse failure, got %v", err)
	}
	if len(pusher.PushFindingsCalls) != 0 {
		t.Fatal("nothing may be pushed for unreadable output")
	}
}

func TestExecuteScanEmptyOutputIsZeroFindings(t *testing.T) {
	pusher := &mocks.MockPusher{}
	exec := core.NewDefaultCommandExecutor(pusher)
	exec.AddScanner(&rawScanner{name: "nuclei", out: "\n  \n"})

	res, err := exec.Execute(context.Background(), scanCommand(t, "nuclei", "http://203.0.113.10"))
	if err != nil {
		t.Fatalf("a scan with no output found nothing; got %v", err)
	}
	if res.FindingsCount != 0 || len(pusher.PushFindingsCalls) != 0 {
		t.Fatalf("want 0 findings and no push, got %d / %d", res.FindingsCount, len(pusher.PushFindingsCalls))
	}
}

func TestFindParserIsDeterministic(t *testing.T) {
	r := core.NewParserRegistry()
	r.Register(&acceptAll{name: "first"})
	r.Register(&acceptAll{name: "second"})
	for range 50 {
		if got := r.FindParser([]byte("anything")).Name(); got != "first" {
			t.Fatalf("FindParser picked %q; parsers must be probed in registration order", got)
		}
	}
}

type acceptAll struct {
	core.BaseParser
	name string
}

func (a *acceptAll) Name() string           { return a.name }
func (a *acceptAll) CanParse(_ []byte) bool { return true }

type recordingParser struct {
	core.BaseParser
	opts *core.ParseOptions
}

func (p *recordingParser) Name() string           { return "codescan" }
func (p *recordingParser) CanParse(_ []byte) bool { return true }
func (p *recordingParser) Parse(_ context.Context, _ []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	p.opts = opts
	r := ctis.NewReport()
	r.Tool = &ctis.Tool{Name: "codescan"}
	return r, nil
}

// A filesystem scan names its asset through the executor's resolver, and the
// parser gets repo-relative paths (BasePath = the validated target).
func TestExecuteScanAssetResolver(t *testing.T) {
	dir := t.TempDir()
	parser := &recordingParser{}
	reg := core.NewParserRegistry()
	reg.Register(parser)

	exec := core.NewDefaultCommandExecutor(&mocks.MockPusher{})
	exec.SetParserRegistry(reg)
	policy := core.DefaultScanTargetPolicy()
	policy.AllowedRoots = []string{dir}
	exec.SetScanTargetPolicy(policy)
	exec.AddScanner(&rawScanner{name: "codescan", out: `{"anything":true}`})

	var gotScanner, gotTarget string
	exec.SetAssetResolver(func(scanner, target string) (ctis.AssetType, string) {
		gotScanner, gotTarget = scanner, target
		return ctis.AssetTypeRepository, "github.com/acme/app"
	})

	if _, err := exec.Execute(context.Background(), scanCommand(t, "codescan", dir)); err != nil {
		t.Fatal(err)
	}
	if gotScanner != "codescan" || gotTarget == "" {
		t.Fatalf("resolver called with (%q, %q)", gotScanner, gotTarget)
	}
	if parser.opts == nil || parser.opts.AssetValue != "github.com/acme/app" ||
		parser.opts.AssetType != ctis.AssetTypeRepository || parser.opts.BasePath != gotTarget {
		t.Fatalf("parse options = %+v", parser.opts)
	}
}
