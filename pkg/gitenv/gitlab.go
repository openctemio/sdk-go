package gitenv

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// GitLabEnv provides GitLab CI environment information.
type GitLabEnv struct {
	accessToken string
	serverURL   string
	client      *gitlab.Client
	verbose     bool
}

// NewGitLab creates a new GitLab CI environment.
func NewGitLab() (*GitLabEnv, error) {
	accessToken := os.Getenv("GITLAB_TOKEN")
	serverURL := os.Getenv("CI_SERVER_URL")

	var client *gitlab.Client
	var err error
	if accessToken != "" && serverURL != "" {
		client, err = gitlab.NewClient(accessToken, gitlab.WithBaseURL(serverURL))
		if err != nil {
			return nil, fmt.Errorf("failed to create GitLab client: %w", err)
		}
	}

	return &GitLabEnv{
		accessToken: accessToken,
		serverURL:   serverURL,
		client:      client,
	}, nil
}

// SetVerbose enables verbose logging.
func (g *GitLabEnv) SetVerbose(v bool) {
	g.verbose = v
}

// IsActive returns true if running in GitLab CI.
func (g *GitLabEnv) IsActive() bool {
	isActive := os.Getenv("GITLAB_CI") == "true"
	if isActive {
		if g.verbose {
			fmt.Println("[gitenv] GitLab CI environment detected")
		}
		if g.accessToken == "" {
			if g.verbose {
				fmt.Println("[gitenv] Warning: GITLAB_TOKEN is not set. MR comments will not work.")
			}
		}
	}
	return isActive
}

// Provider returns "gitlab".
func (g *GitLabEnv) Provider() string {
	return ProviderGitLab
}

// ProjectID returns the GitLab project ID.
func (g *GitLabEnv) ProjectID() string {
	return os.Getenv("CI_PROJECT_ID")
}

// ProjectName returns the project name.
func (g *GitLabEnv) ProjectName() string {
	return os.Getenv("CI_PROJECT_NAME")
}

// CanonicalRepoName returns the full canonical repository name including domain.
// Format: {domain}/{namespace}/{project}
// Examples:
//   - gitlab.com/myorg/myrepo
//   - gitlab.mycompany.com/team/project
//
// This ensures unique asset identification across different Git providers.
func (g *GitLabEnv) CanonicalRepoName() string {
	// CI_PROJECT_PATH is namespace/project (e.g., "myorg/myrepo")
	projectPath := os.Getenv("CI_PROJECT_PATH")
	if projectPath == "" {
		return ""
	}

	// CI_SERVER_HOST is the GitLab server domain (e.g., "gitlab.com" or "gitlab.mycompany.com")
	serverHost := os.Getenv("CI_SERVER_HOST")
	if serverHost == "" {
		serverHost = "gitlab.com"
	}

	return fmt.Sprintf("%s/%s", serverHost, projectPath)
}

// ProjectURL returns the project URL.
func (g *GitLabEnv) ProjectURL() string {
	return os.Getenv("CI_PROJECT_URL")
}

// BlobURL returns the URL for viewing files.
func (g *GitLabEnv) BlobURL() string {
	return fmt.Sprintf("%s/-/blob", g.ProjectURL())
}

// CommitSha returns the current commit SHA.
func (g *GitLabEnv) CommitSha() string {
	return os.Getenv("CI_COMMIT_SHA")
}

// CommitBranch returns the current branch name.
func (g *GitLabEnv) CommitBranch() string {
	return os.Getenv("CI_COMMIT_BRANCH")
}

// CommitTitle returns the commit message.
func (g *GitLabEnv) CommitTitle() string {
	return os.Getenv("CI_COMMIT_TITLE")
}

// CommitTag returns the tag name if this is a tag pipeline.
func (g *GitLabEnv) CommitTag() string {
	return os.Getenv("CI_COMMIT_TAG")
}

// DefaultBranch returns the default branch name.
func (g *GitLabEnv) DefaultBranch() string {
	return os.Getenv("CI_DEFAULT_BRANCH")
}

// MergeRequestID returns the MR IID.
func (g *GitLabEnv) MergeRequestID() string {
	return os.Getenv("CI_MERGE_REQUEST_IID")
}

// MergeRequestTitle returns the MR title.
func (g *GitLabEnv) MergeRequestTitle() string {
	return os.Getenv("CI_MERGE_REQUEST_TITLE")
}

// SourceBranch returns the source branch for MRs.
func (g *GitLabEnv) SourceBranch() string {
	return os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
}

// TargetBranch returns the target branch for MRs.
func (g *GitLabEnv) TargetBranch() string {
	return os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
}

// TargetBranchSha returns the base commit SHA for MRs.
func (g *GitLabEnv) TargetBranchSha() string {
	return os.Getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
}

// JobURL returns the URL for the current job.
func (g *GitLabEnv) JobURL() string {
	return os.Getenv("CI_JOB_URL")
}

// CreateMRComment creates a discussion on a merge request.
func (g *GitLabEnv) CreateMRComment(option MRCommentOption) error {
	if g.client == nil {
		return errors.New("GitLab client not initialized, GITLAB_TOKEN may not be set")
	}

	mrIDStr := g.MergeRequestID()
	if mrIDStr == "" {
		return errors.New("not in a merge request context")
	}

	mrIDInt, err := strconv.Atoi(mrIDStr)
	if err != nil {
		return fmt.Errorf("invalid MR ID: %w", err)
	}
	mrID := int64(mrIDInt)

	projectID := g.ProjectID()
	if projectID == "" {
		return errors.New("CI_PROJECT_ID not set")
	}

	// Get MR diff refs for position
	mr, _, err := g.client.MergeRequests.GetMergeRequest(projectID, mrID, nil)
	if err != nil {
		return fmt.Errorf("failed to get MR: %w", err)
	}

	startLine := int64(option.StartLine)
	position := gitlab.PositionOptions{
		BaseSHA:      &mr.DiffRefs.BaseSha,
		StartSHA:     &mr.DiffRefs.StartSha,
		HeadSHA:      &mr.DiffRefs.HeadSha,
		OldPath:      &option.Path,
		NewPath:      &option.Path,
		PositionType: gitlab.Ptr("text"),
		NewLine:      &startLine,
		OldLine:      &startLine,
	}

	_, res, err := g.client.Discussions.CreateMergeRequestDiscussion(
		projectID,
		mrID,
		&gitlab.CreateMergeRequestDiscussionOptions{
			Body:     &option.Body,
			Position: &position,
		},
	)

	// If first attempt fails (400), retry without OldLine
	if err != nil || (res != nil && res.StatusCode == 400) {
		position.OldLine = nil
		_, _, err = g.client.Discussions.CreateMergeRequestDiscussion(
			projectID,
			mrID,
			&gitlab.CreateMergeRequestDiscussionOptions{
				Body:     &option.Body,
				Position: &position,
			},
		)
		if err != nil {
			if g.verbose {
				fmt.Printf("[gitenv] Failed to create MR discussion: %v\n", err)
			}
			return fmt.Errorf("failed to create MR discussion: %w", err)
		}
	}

	if g.verbose {
		fmt.Printf("[gitenv] Created MR discussion: %s\n", option.Title)
	}
	return nil
}

// ExistingFindingMarkers lists the MR's discussion notes and extracts the
// finding markers already posted, so a re-run can skip them (idempotency).
// Best-effort: errors return an empty set rather than failing the scan.
func (g *GitLabEnv) ExistingFindingMarkers() (map[string]bool, error) {
	empty := map[string]bool{}
	if g.client == nil {
		return empty, nil
	}
	mrIDStr := g.MergeRequestID()
	projectID := g.ProjectID()
	if mrIDStr == "" || projectID == "" {
		return empty, nil
	}
	mrIDInt, err := strconv.Atoi(mrIDStr)
	if err != nil {
		return empty, nil
	}
	mrID := int64(mrIDInt)

	bodies := make([]string, 0, 64)
	opts := &gitlab.ListMergeRequestDiscussionsOptions{ListOptions: gitlab.ListOptions{PerPage: 100}}
	for {
		discussions, resp, err := g.client.Discussions.ListMergeRequestDiscussions(projectID, mrID, opts)
		if err != nil {
			return empty, fmt.Errorf("list MR discussions: %w", err)
		}
		for _, d := range discussions {
			for _, n := range d.Notes {
				bodies = append(bodies, n.Body)
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return ExtractMarkers(bodies), nil
}
