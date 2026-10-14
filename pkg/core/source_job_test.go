package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ctissource "github.com/openctemio/ctis/source"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/source"
)

type recordingPusher struct{ reports []*ctis.Report }

func (p *recordingPusher) PushFindings(_ context.Context, r *ctis.Report) (*PushResult, error) {
	p.reports = append(p.reports, r)
	return &PushResult{}, nil
}
func (p *recordingPusher) PushAssets(context.Context, *ctis.Report) (*PushResult, error) {
	return &PushResult{}, nil
}
func (p *recordingPusher) SendHeartbeat(context.Context, *SensorStatus) error { return nil }
func (p *recordingPusher) TestConnection(context.Context) error               { return nil }

// pathScanner records the target it scanned and returns SARIF output (or
// nothing).
type pathScanner struct {
	target string
	output []byte
}

func (s *pathScanner) Name() string           { return "semgrep" }
func (s *pathScanner) Version() string        { return "test" }
func (s *pathScanner) Capabilities() []string { return nil }
func (s *pathScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "test", nil
}
func (s *pathScanner) Scan(_ context.Context, target string, _ *ScanOptions) (*ScanResult, error) {
	s.target = target
	return &ScanResult{ScannerName: "semgrep", RawOutput: s.output}, nil
}

type fakeFetcher struct {
	root  string
	got   ctissource.Repository
	cred  *source.Credential
	calls int
}

func (f *fakeFetcher) Fetch(_ context.Context, repo ctissource.Repository, cred *source.Credential) (*source.Checkout, error) {
	f.calls++
	f.got, f.cred = repo, cred
	dir := filepath.Join(f.root, "src-x", "repo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &source.Checkout{Dir: dir, Commit: repo.Commit}, nil
}

type fakeCreds struct{ asked []string }

func (c *fakeCreds) SourceCredential(_ context.Context, cmdID string) (*source.Credential, error) {
	c.asked = append(c.asked, cmdID)
	return &source.Credential{Username: "x-access-token", Password: "ghs_short_lived"}, nil
}

var sourceCommit = strings.Repeat("ab", 20)

func sourceCommand(t *testing.T, credential string) *Command {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"scanner": "semgrep", "target": "github.com/acme/api",
		"source": map[string]any{"kind": "github", "clone_url": "https://github.com/acme/api.git", "branch": "main",
			"commit": sourceCommit, "credential": credential, "capabilities": []string{"sast.code@1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Command{ID: "cmd-code-scan", Type: "scan", Payload: payload}
}

func sourceExecutor(t *testing.T, scanner Scanner, roots bool) (*DefaultCommandExecutor, *recordingPusher, *fakeFetcher) {
	t.Helper()
	root := t.TempDir()
	ff := &fakeFetcher{root: root}
	prev := newSourceFetcher
	newSourceFetcher = func(string, bool) sourceFetcher { return ff }
	t.Cleanup(func() { newSourceFetcher = prev })
	p := &recordingPusher{}
	e := NewDefaultCommandExecutor(p)
	e.AddScanner(scanner)
	policy := DefaultScanTargetPolicy()
	if roots {
		policy.AllowedRoots = []string{root}
	}
	e.SetScanTargetPolicy(policy)
	return e, p, ff
}

const sarifOneFinding = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[{"id":"r1"}]}},
"results":[{"ruleId":"r1","level":"error","message":{"text":"bad"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":3}}}]}]}]}`

// A code-scan job fetches its source with the credential asked for this
// command, scans the checkout, and reports on the named repository as the
// full scan of the source's branch and commit.
func TestCodeScanJobScansTheCheckout(t *testing.T) {
	sc := &pathScanner{output: []byte(sarifOneFinding)}
	e, p, ff := sourceExecutor(t, sc, true)
	creds := &fakeCreds{}
	e.SetSourceCredentials(creds)
	if _, err := e.Execute(context.Background(), sourceCommand(t, "scm")); err != nil {
		t.Fatal(err)
	}
	if ff.calls != 1 || ff.cred == nil || ff.cred.Password != "ghs_short_lived" || len(creds.asked) != 1 || creds.asked[0] != "cmd-code-scan" {
		t.Fatalf("fetch: calls %d cred %v asked %v", ff.calls, ff.cred, creds.asked)
	}
	if !strings.HasSuffix(sc.target, filepath.Join("src-x", "repo")) {
		t.Fatalf("scanned %q, not the checkout", sc.target)
	}
	if len(p.reports) != 1 {
		t.Fatalf("%d reports", len(p.reports))
	}
	r := p.reports[0]
	if r.Metadata.CoverageType != "full" || r.Metadata.Branch == nil || r.Metadata.Branch.Name != "main" || r.Metadata.Branch.CommitSHA != sourceCommit {
		t.Fatalf("metadata: %+v %+v", r.Metadata, r.Metadata.Branch)
	}
	if len(r.Assets) == 0 || r.Assets[0].Type != ctis.AssetTypeRepository || r.Assets[0].Value != "github.com/acme/api" {
		t.Fatalf("assets: %+v", r.Assets)
	}
	if b, _ := json.Marshal(r); strings.Contains(string(b), "ghs_short_lived") {
		t.Fatal("the credential reached the report")
	}
}

// A full scan that found nothing still reports, so the platform can mark
// what the tool no longer sees on the branch as fixed.
func TestCodeScanJobReportsAnEmptyFullScan(t *testing.T) {
	e, p, _ := sourceExecutor(t, &pathScanner{}, true)
	if _, err := e.Execute(context.Background(), sourceCommand(t, "")); err != nil {
		t.Fatal(err)
	}
	if len(p.reports) != 1 || len(p.reports[0].Findings) != 0 || p.reports[0].Metadata.CoverageType != "full" ||
		p.reports[0].Metadata.Branch.CommitSHA != sourceCommit || p.reports[0].Tool.Name != "semgrep" {
		t.Fatalf("empty full scan: %+v", p.reports)
	}
}

func TestCodeScanJobRefusals(t *testing.T) {
	// No scan roots: no fetch.
	e, _, ff := sourceExecutor(t, &pathScanner{}, false)
	if _, err := e.Execute(context.Background(), sourceCommand(t, "")); err == nil || ff.calls != 0 {
		t.Fatalf("without scan roots: %v (fetches %d)", err, ff.calls)
	}
	// A credential is named but this sensor cannot ask for one.
	e, _, ff = sourceExecutor(t, &pathScanner{}, true)
	if _, err := e.Execute(context.Background(), sourceCommand(t, "scm")); err == nil || ff.calls != 0 {
		t.Fatalf("credential without a broker: %v (fetches %d)", err, ff.calls)
	}
	// An invalid source.
	e, _, ff = sourceExecutor(t, &pathScanner{}, true)
	cmd := sourceCommand(t, "")
	cmd.Payload = []byte(strings.Replace(string(cmd.Payload), "https://github.com/acme/api.git", "ext::sh -c id", 1))
	if _, err := e.Execute(context.Background(), cmd); err == nil || ff.calls != 0 {
		t.Fatalf("invalid source: %v (fetches %d)", err, ff.calls)
	}
}
