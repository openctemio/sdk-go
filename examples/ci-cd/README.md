# CI/CD Integration Examples

Ready-to-use examples for integrating OpenCTEM Agent into your CI/CD pipelines.

## Supported Platforms

| Platform | Directory | Quick Start |
|----------|-----------|-------------|
| GitHub Actions | [github-actions/](./github-actions/) | Copy `minimal.yml` to `.github/workflows/` |
| GitLab CI | [gitlab-ci/](./gitlab-ci/) | Copy `minimal.gitlab-ci.yml` to root as `.gitlab-ci.yml` |

## Features Overview

| Feature | GitHub Actions | GitLab CI |
|---------|---------------|-----------|
| Auto CI detection | Yes | Yes |
| Diff-based scanning (MR/PR) | Yes | Yes |
| Inline comments | Yes | Yes |
| SARIF reports | Yes | Yes |
| Security dashboard | GitHub Security tab | GitLab Security Dashboard |
| Container scanning | Yes | Yes |
| Scheduled scans | Yes | Yes |

## Quick Comparison

### GitHub Actions (minimal)

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker://openctemio/agent:ci
        with:
          args: -tools semgrep,gitleaks,trivy -target . -auto-ci
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### GitLab CI (minimal)

```yaml
# .gitlab-ci.yml
stages:
  - security

security-scan:
  stage: security
  image: openctemio/agent:ci
  script:
    - agent -tools semgrep,gitleaks,trivy -target . -auto-ci
```

## Scanner Options

| Option | Description |
|--------|-------------|
| `-tools semgrep,gitleaks,trivy` | Scanners to run (comma-separated) |
| `-target .` | Directory to scan |
| `-auto-ci` | Auto-detect CI environment |
| `-comments` | Post inline comments on MR/PR |
| `-verbose` | Verbose output |
| `-json` | JSON output format |
| `-output file.json` | Output file path |
| `-sarif` | Generate SARIF report |
| `-sarif-output file.sarif` | SARIF output path |
| `-push` | Push results to OpenCTEM platform |

## Available Scanners

| Scanner | Type | Description |
|---------|------|-------------|
| `semgrep` | SAST | Static analysis with dataflow/taint tracking |
| `gitleaks` | Secret | Secret and credential detection |
| `trivy` | SCA | Dependency vulnerability scanning |
| `trivy-config` | IaC | Infrastructure as Code scanning |
| `trivy-image` | Container | Container image scanning |
| `trivy-full` | All | Combined vuln + misconfig + secret |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `API_URL` | Platform API URL |
| `API_KEY` | Platform API key |
| `GITHUB_TOKEN` | GitHub token (auto-provided in Actions) |
| `GITLAB_TOKEN` / `CI_JOB_TOKEN` | GitLab token (auto-provided in CI) |
