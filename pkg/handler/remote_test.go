package handler

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/gitenv"
	"github.com/openctemio/sdk-go/pkg/strategy"
)

// fakeGitEnv records CreateMRComment calls and returns a preset set of existing
// finding markers (to exercise idempotency). In an MR context (MergeRequestID
// non-empty) so createMRComments runs.
type fakeGitEnv struct {
	existing map[string]bool
	posted   []gitenv.MRCommentOption
}

func (f *fakeGitEnv) Provider() string          { return "fake" }
func (f *fakeGitEnv) IsActive() bool            { return true }
func (f *fakeGitEnv) ProjectID() string         { return "1" }
func (f *fakeGitEnv) ProjectName() string       { return "owner/repo" }
func (f *fakeGitEnv) ProjectURL() string        { return "https://example.test/owner/repo" }
func (f *fakeGitEnv) BlobURL() string           { return "" }
func (f *fakeGitEnv) CanonicalRepoName() string { return "owner/repo" }
func (f *fakeGitEnv) CommitSha() string         { return "abc123" }
func (f *fakeGitEnv) CommitBranch() string      { return "feature/x" }
func (f *fakeGitEnv) CommitTitle() string       { return "" }
func (f *fakeGitEnv) CommitTag() string         { return "" }
func (f *fakeGitEnv) DefaultBranch() string     { return "main" }
func (f *fakeGitEnv) MergeRequestID() string    { return "42" }
func (f *fakeGitEnv) MergeRequestTitle() string { return "PR" }
func (f *fakeGitEnv) SourceBranch() string      { return "feature/x" }
func (f *fakeGitEnv) TargetBranch() string      { return "main" }
func (f *fakeGitEnv) TargetBranchSha() string   { return "def456" }
func (f *fakeGitEnv) JobURL() string            { return "" }

func (f *fakeGitEnv) CreateMRComment(option gitenv.MRCommentOption) error {
	f.posted = append(f.posted, option)
	return nil
}
func (f *fakeGitEnv) ExistingFindingMarkers() (map[string]bool, error) {
	if f.existing == nil {
		return map[string]bool{}, nil
	}
	return f.existing, nil
}

func findingAt(rule, path string, line int) ctis.Finding {
	return ctis.Finding{
		Title: rule, RuleID: rule, Severity: ctis.SeverityHigh,
		Location: &ctis.FindingLocation{Path: path, StartLine: line, EndLine: line},
	}
}

func newTestRemoteHandler() *RemoteHandler {
	return NewRemoteHandler(&RemoteHandlerConfig{CreateComments: true, MaxComments: 10})
}

func TestCreateMRComments_SkipsAlreadyCommented(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{existing: map[string]bool{"sqli:app.go:5": true}}

	h.createMRComments(HandleFindingsParams{
		Report: &ctis.Report{Findings: []ctis.Finding{
			findingAt("sqli", "app.go", 5), // already commented -> skip
			findingAt("xss", "view.go", 9), // new -> post
		}},
		Strategy: strategy.AllFiles,
		GitEnv:   f,
	})

	if len(f.posted) != 1 {
		t.Fatalf("expected 1 comment (the new finding), got %d", len(f.posted))
	}
	if f.posted[0].Path != "view.go" {
		t.Fatalf("posted the wrong finding: %+v", f.posted[0])
	}
	// The posted comment must carry a marker so a future run can dedupe it.
	if !containsMarker(f.posted[0].Body, "xss:view.go:9") {
		t.Fatalf("posted comment missing idempotency marker: %q", f.posted[0].Body)
	}
}

func TestCreateMRComments_DedupesWithinRun(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}
	dup := findingAt("sqli", "app.go", 5)

	h.createMRComments(HandleFindingsParams{
		Report:   &ctis.Report{Findings: []ctis.Finding{dup, dup}},
		Strategy: strategy.AllFiles,
		GitEnv:   f,
	})

	if len(f.posted) != 1 {
		t.Fatalf("duplicate findings in one run must post once, got %d", len(f.posted))
	}
}

func TestCreateMRComments_ChangedFileOnly(t *testing.T) {
	h := newTestRemoteHandler()
	f := &fakeGitEnv{}

	h.createMRComments(HandleFindingsParams{
		Report: &ctis.Report{Findings: []ctis.Finding{
			findingAt("a", "changed.go", 1),
			findingAt("b", "untouched.go", 2),
		}},
		Strategy:     strategy.ChangedFileOnly,
		ChangedFiles: []strategy.ChangedFile{{Path: "changed.go"}},
		GitEnv:       f,
	})

	if len(f.posted) != 1 || f.posted[0].Path != "changed.go" {
		t.Fatalf("ChangedFileOnly must comment only on changed files, got %+v", f.posted)
	}
}

func containsMarker(body, key string) bool {
	return len(gitenv.ExtractMarkers([]string{body})) == 1 && gitenv.ExtractMarkers([]string{body})[key]
}
