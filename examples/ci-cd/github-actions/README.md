# GitHub Actions Examples

Examples for integrating OpenCTEM Agent into GitHub Actions workflows.

## Quick Start

Copy `minimal.yml` to `.github/workflows/security.yml` in your repository:

```bash
mkdir -p .github/workflows
cp minimal.yml .github/workflows/security.yml
```

## Available Examples

| File | Description | Use Case |
|------|-------------|----------|
| `minimal.yml` | Simplest setup | Quick start, basic scanning |
| `security-scan.yml` | Full-featured workflow | Production use with all features |
| `pr-scan.yml` | PR-focused scanning | Code review with inline comments |

## Features

### Auto CI Detection
The agent automatically detects GitHub Actions environment and:
- Extracts PR/commit information
- Determines scan strategy (all files vs changed files only)
- Posts inline comments on PR diffs

### Inline PR Comments
When running in a PR context, findings are posted as inline comments on the changed lines:

```yaml
- name: Run scan
  uses: docker://openctemio/agent:ci
  with:
    args: -tools semgrep -target . -auto-ci -comments
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### SARIF Upload to Security Tab
Upload results to GitHub's Security tab:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Push to Platform
Send results to platform for tracking:

```yaml
env:
  API_URL: ${{ secrets.API_URL }}
  API_KEY: ${{ secrets.API_KEY }}
```

## Required Permissions

```yaml
permissions:
  contents: read           # Read repository
  security-events: write   # Upload SARIF
  pull-requests: write     # Post PR comments
```

## Secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `GITHUB_TOKEN` | Auto | Provided by GitHub, used for PR comments |
| `API_URL` | Optional | Platform API URL |
| `API_KEY` | Optional | Platform API key |

## Scanner Options

```yaml
args: >-
  -tools semgrep,gitleaks,trivy    # Scanners to run
  -target .                         # Directory to scan
  -auto-ci                          # Auto-detect CI environment
  -comments                         # Post inline comments
  -verbose                          # Verbose output
  -json                             # JSON output
  -output results.json              # Output file
  -sarif                            # Generate SARIF
  -sarif-output results.sarif       # SARIF output file
  -push                             # Push to OpenCTEM platform
```

## Fail on Critical Findings

```yaml
- name: Check findings
  run: |
    CRITICAL=$(cat results.json | jq '[.findings[] | select(.severity == "critical")] | length')
    if [ "$CRITICAL" -gt 0 ]; then
      exit 1
    fi
```
