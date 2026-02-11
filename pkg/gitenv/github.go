package gitenv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/v74/github"
	"golang.org/x/oauth2"
)

// GitHubEnv provides GitHub Actions CI environment information.
type GitHubEnv struct {
	accessToken  string
	client       *github.Client
	ctx          context.Context
	eventPayload githubEventPayload
	verbose      bool
}

// NewGitHub creates a new GitHub Actions environment.
func NewGitHub() (*GitHubEnv, error) {
	accessToken := os.Getenv("GITHUB_TOKEN")
	ctx := context.Background()

	var client *github.Client
	if accessToken != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: accessToken},
		)
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	} else {
		client = github.NewClient(nil)
	}

	return &GitHubEnv{
		accessToken: accessToken,
		client:      client,
		ctx:         ctx,
	}, nil
}

// SetVerbose enables verbose logging.
func (g *GitHubEnv) SetVerbose(v bool) {
	g.verbose = v
}

// IsActive returns true if running in GitHub Actions.
func (g *GitHubEnv) IsActive() bool {
	isActive := os.Getenv("GITHUB_ACTIONS") == "true"
	if isActive {
		if g.verbose {
			fmt.Println("[gitenv] GitHub Actions environment detected")
		}
		if g.accessToken == "" {
			if g.verbose {
				fmt.Println("[gitenv] Warning: GITHUB_TOKEN is not set. PR comments will not work.")
			}
		}
		g.loadEventPayload()
	}
	return isActive
}

func (g *GitHubEnv) loadEventPayload() {
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return
	}

	data, err := os.ReadFile(eventPath)
	if err != nil {
		if g.verbose {
			fmt.Printf("[gitenv] Warning: Could not read GITHUB_EVENT_PATH: %v\n", err)
		}
		return
	}

	if err := json.Unmarshal(data, &g.eventPayload); err != nil {
		if g.verbose {
			fmt.Printf("[gitenv] Warning: Could not parse event payload: %v\n", err)
		}
	}
}

// Provider returns "github".
func (g *GitHubEnv) Provider() string {
	return ProviderGitHub
}

// ProjectID returns the GitHub repository ID.
func (g *GitHubEnv) ProjectID() string {
	return os.Getenv("GITHUB_REPOSITORY_ID")
}

// ProjectName returns owner/repo format.
func (g *GitHubEnv) ProjectName() string {
	return os.Getenv("GITHUB_REPOSITORY")
}

// CanonicalRepoName returns the full canonical repository name including domain.
// Format: github.com/{owner}/{repo} (or custom domain for GitHub Enterprise)
// This ensures unique asset identification across different Git providers.
func (g *GitHubEnv) CanonicalRepoName() string {
	serverURL := os.Getenv("GITHUB_SERVER_URL")
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		return ""
	}

	// Extract domain from server URL
	domain := "github.com"
	if serverURL != "" {
		// Remove protocol prefix
		domain = strings.TrimPrefix(serverURL, "https://")
		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.TrimSuffix(domain, "/")
	}

	return fmt.Sprintf("%s/%s", domain, repo)
}

// ProjectURL returns the repository URL.
func (g *GitHubEnv) ProjectURL() string {
	serverURL := os.Getenv("GITHUB_SERVER_URL")
	repo := os.Getenv("GITHUB_REPOSITORY")
	if serverURL == "" {
		serverURL = "https://github.com"
	}
	return fmt.Sprintf("%s/%s", serverURL, repo)
}

// BlobURL returns the URL for viewing files.
func (g *GitHubEnv) BlobURL() string {
	return fmt.Sprintf("%s/blob", g.ProjectURL())
}

// CommitSha returns the current commit SHA.
func (g *GitHubEnv) CommitSha() string {
	return os.Getenv("GITHUB_SHA")
}

// CommitBranch returns the current branch name.
func (g *GitHubEnv) CommitBranch() string {
	// In PR context, use head ref
	if g.MergeRequestID() != "" && g.eventPayload.PullRequest != nil {
		return g.eventPayload.PullRequest.Head.Ref
	}

	// Regular branch
	if os.Getenv("GITHUB_REF_TYPE") == "branch" {
		return os.Getenv("GITHUB_REF_NAME")
	}

	return ""
}

// CommitTitle returns the commit message.
func (g *GitHubEnv) CommitTitle() string {
	if title := os.Getenv("GITHUB_COMMIT_TITLE"); title != "" {
		return title
	}
	if g.eventPayload.HeadCommit != nil {
		return g.eventPayload.HeadCommit.Message
	}
	return ""
}

// CommitTag returns the tag name if this is a tag push.
func (g *GitHubEnv) CommitTag() string {
	if os.Getenv("GITHUB_REF_TYPE") == "tag" {
		return os.Getenv("GITHUB_REF_NAME")
	}
	return ""
}

// DefaultBranch returns the default branch name.
func (g *GitHubEnv) DefaultBranch() string {
	if branch := os.Getenv("GITHUB_DEFAULT_BRANCH"); branch != "" {
		return branch
	}
	if g.eventPayload.Repository != nil && g.eventPayload.Repository.DefaultBranch != "" {
		return g.eventPayload.Repository.DefaultBranch
	}
	return "main"
}

// MergeRequestID returns the PR number.
func (g *GitHubEnv) MergeRequestID() string {
	if prNum := os.Getenv("GITHUB_PR_NUMBER"); prNum != "" {
		return prNum
	}
	if g.eventPayload.PullRequest != nil {
		return strconv.Itoa(g.eventPayload.PullRequest.Number)
	}
	return ""
}

// MergeRequestTitle returns the PR title.
func (g *GitHubEnv) MergeRequestTitle() string {
	if title := os.Getenv("GITHUB_PR_TITLE"); title != "" {
		return title
	}
	if g.eventPayload.PullRequest != nil {
		return g.eventPayload.PullRequest.Title
	}
	return ""
}

// SourceBranch returns the source branch for PRs.
func (g *GitHubEnv) SourceBranch() string {
	return os.Getenv("GITHUB_HEAD_REF")
}

// TargetBranch returns the target branch for PRs.
func (g *GitHubEnv) TargetBranch() string {
	return os.Getenv("GITHUB_BASE_REF")
}

// TargetBranchSha returns the base commit SHA for PRs.
func (g *GitHubEnv) TargetBranchSha() string {
	if sha := os.Getenv("GITHUB_BASE_REF_SHA"); sha != "" {
		return sha
	}
	if g.eventPayload.PullRequest != nil {
		return g.eventPayload.PullRequest.Base.Sha
	}
	return ""
}

// JobURL returns the URL for the current job.
func (g *GitHubEnv) JobURL() string {
	serverURL := os.Getenv("GITHUB_SERVER_URL")
	repo := os.Getenv("GITHUB_REPOSITORY")
	runID := os.Getenv("GITHUB_RUN_ID")
	if serverURL == "" || repo == "" || runID == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s/actions/runs/%s", serverURL, repo, runID)
}

// CreateMRComment creates a review comment on a pull request.
func (g *GitHubEnv) CreateMRComment(option MRCommentOption) error {
	if g.accessToken == "" {
		return fmt.Errorf("GITHUB_TOKEN not set, cannot create PR comment")
	}

	prNumberStr := g.MergeRequestID()
	if prNumberStr == "" {
		return fmt.Errorf("not in a pull request context")
	}

	prNumber, err := strconv.Atoi(prNumberStr)
	if err != nil {
		return fmt.Errorf("invalid PR number: %w", err)
	}

	ownerRepo := os.Getenv("GITHUB_REPOSITORY")
	parts := strings.Split(ownerRepo, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid GITHUB_REPOSITORY format: %s", ownerRepo)
	}
	owner, repo := parts[0], parts[1]

	comment := github.DraftReviewComment{
		Path: github.Ptr(option.Path),
		Body: github.Ptr(option.Body),
	}

	if option.StartLine == option.EndLine || option.EndLine == 0 {
		comment.Line = github.Ptr(option.StartLine)
	} else {
		comment.StartLine = github.Ptr(option.StartLine)
		comment.Line = github.Ptr(option.EndLine)
	}

	review := &github.PullRequestReviewRequest{
		Body:  github.Ptr(option.Title),
		Event: github.Ptr("COMMENT"),
		Comments: []*github.DraftReviewComment{
			&comment,
		},
	}

	_, _, err = g.client.PullRequests.CreateReview(g.ctx, owner, repo, prNumber, review)
	if err != nil {
		if g.verbose {
			fmt.Printf("[gitenv] Failed to create PR comment: %v\n", err)
		}
		return fmt.Errorf("failed to create PR comment: %w", err)
	}

	if g.verbose {
		fmt.Printf("[gitenv] Created PR comment: %s\n", option.Title)
	}
	return nil
}

// GitHub event payload structures
type githubEventPayload struct {
	PullRequest *githubPullRequest `json:"pull_request"`
	Repository  *githubRepository  `json:"repository"`
	HeadCommit  *githubHeadCommit  `json:"head_commit"`
}

type githubPullRequest struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Base   struct {
		Ref string `json:"ref"`
		Sha string `json:"sha"`
	} `json:"base"`
	Head struct {
		Ref string `json:"ref"`
		Sha string `json:"sha"`
	} `json:"head"`
}

type githubHeadCommit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type githubRepository struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
}
