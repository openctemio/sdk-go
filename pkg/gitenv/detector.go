package gitenv

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Detect auto-detects the CI environment and returns the appropriate GitEnv.
// Returns nil if no CI environment is detected.
func Detect() GitEnv {
	return DetectWithVerbose(false)
}

// DetectWithVerbose auto-detects the CI environment with optional verbose logging.
func DetectWithVerbose(verbose bool) GitEnv {
	// Try GitHub Actions first
	github, err := NewGitHub()
	if err == nil {
		github.SetVerbose(verbose)
		if github.IsActive() {
			return github
		}
	}

	// Try GitLab CI
	gitlab, err := NewGitLab()
	if err == nil {
		gitlab.SetVerbose(verbose)
		if gitlab.IsActive() {
			return gitlab
		}
	}

	// No CI environment detected
	if verbose {
		fmt.Println("[gitenv] No CI environment detected, running in manual mode")
	}
	return nil
}

// DetectFromDirectory detects git information from a local directory.
// Useful when running locally without CI environment.
func DetectFromDirectory(dir string, verbose bool) GitEnv {
	// First check for CI environment
	if env := DetectWithVerbose(verbose); env != nil {
		return env
	}

	// Fall back to reading from .git directory
	absPath, err := filepath.Abs(dir)
	if err != nil {
		absPath = dir
	}

	repoURL := readGitRemoteURL(filepath.Join(absPath, ".git", "config"))
	branch := readGitBranch(filepath.Join(absPath, ".git", "HEAD"))
	commitSha := readGitCommitSha(absPath)

	if verbose {
		if repoURL != "" {
			fmt.Printf("[gitenv] Detected repo: %s\n", repoURL)
		}
		if branch != "" {
			fmt.Printf("[gitenv] Detected branch: %s\n", branch)
		}
		if commitSha != "" {
			fmt.Printf("[gitenv] Detected commit: %s\n", commitSha)
		}
	}

	return NewManualEnv(normalizeGitURL(repoURL), branch, commitSha)
}

// readGitRemoteURL reads the origin remote URL from a git config file.
func readGitRemoteURL(configPath string) string {
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inRemoteOrigin := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[remote \"origin\"]" {
			inRemoteOrigin = true
			continue
		}

		if inRemoteOrigin {
			if strings.HasPrefix(line, "[") {
				break
			}
			if strings.HasPrefix(line, "url = ") {
				return strings.TrimPrefix(line, "url = ")
			}
		}
	}

	return ""
}

// readGitBranch reads the current branch from .git/HEAD.
func readGitBranch(headPath string) string {
	content, err := os.ReadFile(headPath)
	if err != nil {
		return ""
	}

	headContent := strings.TrimSpace(string(content))

	// HEAD file contains either:
	// 1. "ref: refs/heads/branch-name" (normal branch)
	// 2. A commit hash (detached HEAD)
	if strings.HasPrefix(headContent, "ref: refs/heads/") {
		return strings.TrimPrefix(headContent, "ref: refs/heads/")
	}

	// Detached HEAD - return short commit hash
	if len(headContent) >= 7 {
		return headContent[:7]
	}

	return ""
}

// readGitCommitSha reads the current commit SHA.
func readGitCommitSha(repoPath string) string {
	headPath := filepath.Join(repoPath, ".git", "HEAD")
	content, err := os.ReadFile(headPath)
	if err != nil {
		return ""
	}

	headContent := strings.TrimSpace(string(content))

	// If HEAD points to a ref, read the ref file
	if strings.HasPrefix(headContent, "ref: ") {
		refPath := strings.TrimPrefix(headContent, "ref: ")
		refFilePath := filepath.Join(repoPath, ".git", refPath)
		refContent, err := os.ReadFile(refFilePath)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(refContent))
	}

	// Direct commit hash
	return headContent
}

// normalizeGitURL normalizes a git URL to a standard format.
func normalizeGitURL(url string) string {
	if url == "" {
		return ""
	}

	// Convert SSH URLs to HTTPS-like format
	// git@github.com:org/repo.git -> github.com/org/repo
	if strings.HasPrefix(url, "git@") {
		url = strings.TrimPrefix(url, "git@")
		url = strings.Replace(url, ":", "/", 1)
	}

	// Remove https:// or http://
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Remove .git suffix
	url = strings.TrimSuffix(url, ".git")

	// Remove trailing slash
	url = strings.TrimSuffix(url, "/")

	return url
}
