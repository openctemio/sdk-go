// Package gitenv provides auto-detection and abstraction for CI/CD environments.
// It detects GitHub Actions, GitLab CI, and other CI systems from environment variables
// and provides a unified interface for accessing repository and commit information.
package gitenv

const (
	ProviderGitHub    = "github"
	ProviderGitLab    = "gitlab"
	ProviderBitbucket = "bitbucket"
	ProviderManual    = "manual"
)

// GitEnv provides a unified interface for CI/CD environment information.
// Implementations detect and read from CI-specific environment variables.
type GitEnv interface {
	// Provider returns the provider name (github, gitlab, bitbucket, etc.)
	Provider() string

	// IsActive returns true if this CI environment is detected
	IsActive() bool

	// Repository info
	ProjectID() string
	ProjectName() string
	ProjectURL() string
	BlobURL() string

	// CanonicalRepoName returns the full canonical repository name including the provider domain.
	// Format: {domain}/{owner}/{repo}
	// Examples:
	//   - github.com/openctemio/api
	//   - gitlab.com/myorg/myrepo
	// This ensures unique asset identification across different Git providers.
	CanonicalRepoName() string

	// Commit info
	CommitSha() string
	CommitBranch() string
	CommitTitle() string
	CommitTag() string
	DefaultBranch() string

	// MR/PR info
	MergeRequestID() string
	MergeRequestTitle() string
	SourceBranch() string
	TargetBranch() string
	TargetBranchSha() string

	// CI info
	JobURL() string

	// Actions
	CreateMRComment(option MRCommentOption) error
}

// MRCommentOption configures a merge request / pull request comment.
type MRCommentOption struct {
	Title     string
	Body      string
	Path      string
	StartLine int
	EndLine   int
}

// ManualEnv is a manual/local environment when no CI is detected.
type ManualEnv struct {
	repoURL   string
	branch    string
	commitSha string
	projectID string
}

// NewManualEnv creates a manual environment with optional override values.
func NewManualEnv(repoURL, branch, commitSha string) *ManualEnv {
	return &ManualEnv{
		repoURL:   repoURL,
		branch:    branch,
		commitSha: commitSha,
	}
}

func (m *ManualEnv) Provider() string    { return ProviderManual }
func (m *ManualEnv) IsActive() bool      { return true }
func (m *ManualEnv) ProjectID() string   { return m.projectID }
func (m *ManualEnv) ProjectName() string { return m.repoURL }
func (m *ManualEnv) ProjectURL() string  { return m.repoURL }
func (m *ManualEnv) BlobURL() string     { return "" }

// CanonicalRepoName returns the repo URL as-is for manual environments.
func (m *ManualEnv) CanonicalRepoName() string               { return m.repoURL }
func (m *ManualEnv) CommitSha() string                       { return m.commitSha }
func (m *ManualEnv) CommitBranch() string                    { return m.branch }
func (m *ManualEnv) CommitTitle() string                     { return "" }
func (m *ManualEnv) CommitTag() string                       { return "" }
func (m *ManualEnv) DefaultBranch() string                   { return "main" }
func (m *ManualEnv) MergeRequestID() string                  { return "" }
func (m *ManualEnv) MergeRequestTitle() string               { return "" }
func (m *ManualEnv) SourceBranch() string                    { return "" }
func (m *ManualEnv) TargetBranch() string                    { return "" }
func (m *ManualEnv) TargetBranchSha() string                 { return "" }
func (m *ManualEnv) JobURL() string                          { return "" }
func (m *ManualEnv) CreateMRComment(_ MRCommentOption) error { return nil }
