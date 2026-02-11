# OpenCTEM SDK - Architecture Best Practices

Tài liệu này tổng hợp các best practices từ việc nghiên cứu:
- code-secure-analyzer (framework core)
- code-secure-semgrep (SAST scanner)
- code-secure-gitleaks (Secret scanner)
- code-secure-trivy (SCA scanner)

---

## 1. Kiến Trúc Tổng Quan

### 1.1 Plugin Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         OpenCTEM Agent                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Semgrep  │  │ Gitleaks │  │  Trivy   │  │ Custom   │        │
│  │ Scanner  │  │ Scanner  │  │ Scanner  │  │ Scanner  │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │               │
│       └──────────┬──┴──────┬──────┴─────────────┘               │
│                  │         │                                     │
│           ┌──────▼─────────▼──────┐                             │
│           │   Scanner Interface   │                             │
│           │  - SastScanner        │                             │
│           │  - ScaScanner         │                             │
│           │  - SecretScanner      │                             │
│           └──────────┬────────────┘                             │
│                      │                                          │
│           ┌──────────▼────────────┐                             │
│           │   Handler Interface   │                             │
│           │  - OnStart()          │                             │
│           │  - HandleFindings()   │                             │
│           │  - OnCompleted()      │                             │
│           │  - OnError()          │                             │
│           └──────────┬────────────┘                             │
│                      │                                          │
│    ┌─────────────────┼─────────────────┐                        │
│    ▼                 ▼                 ▼                        │
│ ┌──────────┐   ┌──────────┐   ┌──────────┐                     │
│ │ Console  │   │  Remote  │   │  Custom  │                     │
│ │ Handler  │   │  Handler │   │  Handler │                     │
│ └──────────┘   └────┬─────┘   └──────────┘                     │
│                     │                                           │
│              ┌──────▼──────┐                                    │
│              │ OpenCTEM API │                                    │
│              └─────────────┘                                    │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Scanner Types

```go
// SAST Scanner - Static Application Security Testing
type SastScanner interface {
    Name() string
    Type() ScannerType  // ScannerTypeSAST
    Scan(option ScanOption) (*SastResult, error)
}

// SCA Scanner - Software Composition Analysis
type ScaScanner interface {
    Name() string
    Type() ScannerType  // ScannerTypeDependency
    Scan() (*ScaResult, error)
}

// Secret Scanner - Secret Detection
type SecretScanner interface {
    Name() string
    Type() ScannerType  // ScannerTypeSecretDetection
    Scan(option ScanOption) (*SastResult, error)
}
```

---

## 2. CI/CD Environment Detection

### 2.1 GitEnv Interface

```go
type GitEnv interface {
    // Identification
    Provider() string           // "github", "gitlab", "bitbucket"
    IsActive() bool             // Check if this CI is active

    // Repository Info
    ProjectID() string
    ProjectName() string        // owner/repo format
    ProjectURL() string
    BlobURL() string            // URL for viewing files

    // Commit Info
    CommitSha() string
    CommitBranch() string
    CommitTitle() string
    CommitTag() string
    DefaultBranch() string

    // MR/PR Info
    MergeRequestID() string
    MergeRequestTitle() string
    SourceBranch() string
    TargetBranch() string
    TargetBranchSha() string    // Baseline for diff

    // CI Info
    JobURL() string

    // Actions
    CreateMRComment(option MRCommentOption) error
}
```

### 2.2 Environment Variables

**GitHub Actions:**
```bash
GITHUB_ACTIONS=true           # Detection flag
GITHUB_TOKEN                  # API access
GITHUB_SHA                    # Current commit
GITHUB_REF_NAME               # Branch/tag name
GITHUB_REPOSITORY             # owner/repo
GITHUB_HEAD_REF               # Source branch (PR)
GITHUB_BASE_REF               # Target branch (PR)
GITHUB_EVENT_PATH             # JSON event payload
GITHUB_PR_NUMBER              # PR number (optional)
```

**GitLab CI:**
```bash
GITLAB_CI=true                # Detection flag
GITLAB_TOKEN                  # API access
CI_COMMIT_SHA                 # Current commit
CI_COMMIT_BRANCH              # Branch name
CI_PROJECT_ID                 # Project ID
CI_PROJECT_URL                # Project URL
CI_MERGE_REQUEST_IID          # MR ID
CI_MERGE_REQUEST_DIFF_BASE_SHA # Baseline commit
CI_DEFAULT_BRANCH             # Default branch
```

### 2.3 Auto-Detection Logic

```go
func Detect() GitEnv {
    // Priority order
    if os.Getenv("GITHUB_ACTIONS") == "true" {
        return NewGitHub()
    }
    if os.Getenv("GITLAB_CI") == "true" {
        return NewGitLab()
    }
    if os.Getenv("BITBUCKET_PIPELINES") == "true" {
        return NewBitbucket()
    }
    return nil // Local/manual mode
}
```

---

## 3. Scan Strategy

### 3.1 Strategy Types

```go
type ScanStrategy int

const (
    AllFiles ScanStrategy = iota      // Full repository scan
    ChangedFileOnly                   // Delta scan for MR/PR
)
```

### 3.2 Strategy Selection Logic

```go
func DetermineStrategy(ctx *ScanContext) (ScanStrategy, []ChangedFile) {
    // 1. No CI environment → AllFiles
    if ctx.GitEnv == nil {
        return AllFiles, nil
    }

    // 2. Determine baseline commit
    baselineSha := ""
    if ctx.GitEnv.MergeRequestID() != "" {
        // MR/PR context: use target branch
        baselineSha = ctx.GitEnv.TargetBranchSha()
    } else if ctx.LastScanCommit != "" {
        // Regular push: use last scan commit
        baselineSha = ctx.LastScanCommit
    }

    // 3. No baseline → AllFiles
    if baselineSha == "" {
        return AllFiles, nil
    }

    // 4. Get changed files
    changedFiles := git.DiffCommit(ctx.CurrentSha, baselineSha)

    // 5. Too many changes → AllFiles
    if len(changedFiles) >= ctx.MaxChangedFiles {
        return AllFiles, nil
    }

    return ChangedFileOnly, changedFiles
}
```

### 3.3 MAX_CHANGED_FILES Threshold

```go
const DefaultMaxChangedFiles = 512

// Configurable via environment
maxFiles := os.Getenv("MAX_CHANGED_FILES")
```

**Rationale:**
- Too many changed files = full scan is more efficient
- Prevents extremely long diff operations
- Default 512 is reasonable for most repos

---

## 4. Handler Pattern

### 4.1 Handler Interface

```go
type ScanHandler interface {
    // Lifecycle
    OnStart(gitEnv GitEnv, scannerName, scannerType string) (*ScanInfo, error)
    OnCompleted() error
    OnError(err error) error

    // Result handling
    HandleSastFindings(params HandleSastParams) error
    HandleScaFindings(params HandleScaParams) error
    HandleSecretFindings(params HandleSecretParams) error
}

type ScanInfo struct {
    ScanID        string    // Scan session ID
    LastCommitSha string    // For baseline comparison
    ScanURL       string    // Link to scan results
}
```

### 4.2 Handler Selection

```go
func GetHandler() Handler {
    token := os.Getenv("API_KEY")
    url := os.Getenv("API_URL")

    if token != "" && url != "" {
        client := NewAPIClient(url, token)
        if client.TestConnection() {
            return NewRemoteHandler(client)
        }
    }
    return NewConsoleHandler()  // Fallback
}
```

### 4.3 RemoteHandler Features

1. **OnStart**: Register scan with server, get baseline
2. **HandleFindings**:
   - Upload findings to API
   - Create PR/MR inline comments
   - Categorize findings (new, confirmed, fixed)
3. **OnCompleted**: Update scan status
4. **OnError**: Mark scan as failed

### 4.4 MR/PR Comment Format

```go
func formatComment(finding Finding) string {
    return fmt.Sprintf(`**%s %s**

### %s

%s

**Rule:** `+"`%s`"+`
**Category:** %s

%s

---
*Detected by OpenCTEM Security Scanner*`,
        getSeverityEmoji(finding.Severity),
        finding.Severity,
        finding.Title,
        finding.Description,
        finding.RuleID,
        finding.Category,
        formatRemediation(finding.Remediation),
    )
}
```

---

## 5. Scanner Execution Pattern

### 5.1 Process Execution

```go
func ExecuteScanner(binary string, args []string) ([]byte, error) {
    cmd := exec.Command(binary, args...)

    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()

    if err := cmd.Start(); err != nil {
        return nil, err
    }

    // Non-blocking output streaming
    go streamOutput(stdout, logger.Info)
    go streamOutput(stderr, logger.Error)

    if err := cmd.Wait(); err != nil {
        return nil, err
    }

    return readOutputFile(outputPath)
}

func streamOutput(reader io.ReadCloser, logFn func(string)) {
    scanner := bufio.NewScanner(reader)
    for scanner.Scan() {
        logFn(scanner.Text())
    }
}
```

### 5.2 Scanner Configuration

**Semgrep:**
```bash
semgrep scan --config auto --json --output result.json <target>
```

**Gitleaks:**
```bash
gitleaks dir <path> --ignore-gitleaks-allow --exit-code 0 \
    --report-format json --report-path result.json
```

**Trivy:**
```bash
# SBOM generation
trivy repo --format cyclonedx --output sbom.json <path>

# Vulnerability scan
trivy repo --scanners vuln --ignore-unfixed \
    --format json --output vuln.json <path>
```

---

## 6. Finding Transformation

### 6.1 Unified Finding Format (CTIS Schema v1.0)

```go
type Finding struct {
    // Identity
    ID          string    // Unique ID
    Fingerprint string    // For deduplication
    RuleID      string    // Scanner rule ID

    // Classification
    Type        FindingType  // vulnerability, secret, misconfiguration, web3
    Severity    Severity     // critical, high, medium, low, info
    Confidence  int          // 0-100

    // Description
    Title       string
    Description string
    Category    string

    // Location
    Location    *FindingLocation

    // Metadata (enhanced)
    Vulnerability *VulnerabilityDetails  // CVE, CWE, CVSS, PURL, EPSS
    Secret        *SecretDetails         // Secret type, service, scopes
    DataFlow      *DataFlow              // Taint tracking (source → sink)
    Web3          *Web3VulnerabilityDetails  // Smart contract vulnerabilities

    // Status & Suppression (new)
    Status      FindingStatus  // open, resolved, false_positive, accepted_risk
    Suppression *Suppression   // Suppression details

    // Git metadata (new)
    Author      string        // Git author who introduced
    AuthorEmail string        // Author email
    CommitDate  *time.Time    // When introduced

    // Remediation
    Remediation *Remediation
    References  []string
}
```

**CTIS Schema Enhancements (v1.0):**
- **DataFlow**: Full taint tracking support (source → intermediates → sink)
- **LogicalLocation**: Function/class/method context
- **Suppression**: Finding suppression tracking
- **FindingStatus**: Workflow state management
- **Enhanced VulnerabilityDetails**: PURL, EPSS percentile, dependency path
- **Enhanced SecretDetails**: Scopes, expiration, rotation due dates

### 6.2 Fingerprint Generation

```go
// For SAST findings (file:rule:line → hash)
func GenerateSastFingerprint(file, ruleID string, startLine int) string {
    raw := fmt.Sprintf("%s:%s:%d", file, ruleID, startLine)
    return sha256Hash(raw)
}

// For Secret findings (includes secret hash for uniqueness)
func GenerateSecretFingerprint(file, ruleID string, startLine int, secretValue string) string {
    secretHash := sha256Hash(secretValue)[:8]  // First 8 chars of secret hash
    raw := fmt.Sprintf("%s:%s:%d:%s", file, ruleID, startLine, secretHash)
    return sha256Hash(raw)
}

// For SCA findings (package:version:vuln)
func GenerateScaFingerprint(pkgName, pkgVersion, vulnID string) string {
    raw := fmt.Sprintf("%s:%s:%s", pkgName, pkgVersion, vulnID)
    return sha256Hash(raw)
}
```

**Best Practice**: Gitleaks provides its own fingerprint which already includes commit + file + rule + line + secret_hash. Use native fingerprint when available, fall back to our own when not.

### 6.2.1 Best Fingerprint Format Recommendation

| Finding Type | Fingerprint Format | Components | Why |
|-------------|-------------------|------------|-----|
| **SAST** | `sha256(file:ruleID:startLine)` | Location-based | Same rule at same location = same issue |
| **Secret** | `sha256(file:ruleID:startLine:secretHash[:8])` | Location + secret hash | Different secrets at same location = different issues |
| **SCA** | `sha256(pkgName:pkgVersion:vulnID)` | Package + vulnerability | Same vuln in same version = same issue |
| **IaC** | `sha256(file:ruleID:resourceName)` | Location + resource | Same misconfiguration on same resource = same issue |
| **Web3** | `sha256(contract:function:vulnClass:line)` | Contract context | Same vuln in same contract function = same issue |

**Key Principles:**
1. **Stability**: Fingerprint should not change unless the finding is fundamentally different
2. **Uniqueness**: Different findings must have different fingerprints
3. **Consistency**: Same finding across scans should have the same fingerprint
4. **Format**: Always use hash (sha256) to ensure fixed length (64 chars max for DB)

**Secret Fingerprint Deep Dive:**
```go
// Why include secret hash?
// Scenario: Same file, same rule, same line, but TWO DIFFERENT secrets
// Example: .env file with API_KEY on line 5, changed from "abc123" to "xyz789"
// Without secret hash: Same fingerprint → old finding marked as "still present"
// With secret hash: Different fingerprint → old finding "resolved", new finding "open"

func GenerateSecretFingerprint(file, ruleID string, startLine int, secretValue string) string {
    secretHash := sha256Hash(secretValue)[:8]  // First 8 chars is enough for uniqueness
    raw := fmt.Sprintf("%s:%s:%d:%s", file, ruleID, startLine, secretHash)
    return sha256Hash(raw)
}
```

**Native Fingerprint Priority:**
```go
func getFingerprint(finding Finding) string {
    // 1. Use scanner's native fingerprint if available and valid
    if finding.NativeFingerprint != "" && len(finding.NativeFingerprint) <= 64 {
        return finding.NativeFingerprint
    }

    // 2. Hash long fingerprints to fit DB constraint
    if finding.NativeFingerprint != "" {
        return sha256Hash(finding.NativeFingerprint)
    }

    // 3. Generate our own based on finding type
    return generateFingerprint(finding)
}
```

### 6.3 Severity Mapping

```go
// Semgrep
"ERROR"   → SeverityHigh
"WARNING" → SeverityMedium
"INFO"    → SeverityInfo

// Trivy
"CRITICAL" → SeverityCritical
"HIGH"     → SeverityHigh
"MEDIUM"   → SeverityMedium
"LOW"      → SeverityLow

// Gitleaks
All secrets → SeverityHigh  // Default high severity

// CVSS-based (preferred)
score >= 9.0 → SeverityCritical
score >= 7.0 → SeverityHigh
score >= 4.0 → SeverityMedium
score >= 0.1 → SeverityLow
score == 0   → SeverityInfo
```

---

## 7. Error Handling

### 7.1 Graceful Degradation

```go
func (analyzer *Analyzer) Run() {
    // Scanner check
    if analyzer.scanner == nil {
        logger.Fatal("no scanner configured")
    }

    // Handler fallback
    if analyzer.handler == nil {
        analyzer.handler = GetHandler()  // Auto-detect
        if analyzer.handler == nil {
            analyzer.handler = NewConsoleHandler()  // Final fallback
        }
    }

    // Source manager fallback
    if analyzer.sourceManager == nil {
        analyzer.sourceManager = gitenv.Detect()
        // nil is OK - runs in local mode
    }

    // Execute with error handling
    result, err := analyzer.scanner.Scan(options)
    if err != nil {
        analyzer.handler.OnError(err)
        logger.Fatal(err.Error())
    }

    // Continue even if push fails
    err = analyzer.handler.HandleFindings(result)
    if err != nil {
        logger.Error("Failed to push findings: " + err.Error())
        // Don't exit - scan completed successfully
    }

    analyzer.handler.OnCompleted()
}
```

### 7.2 Partial Results

```go
// Trivy example: continue with partial results
func (s *DependencyScanner) Scan() (*ScaResult, error) {
    result := &ScaResult{}

    // SBOM scan
    sbom, err := s.ScanSBOM()
    if err != nil {
        logger.Warn("SBOM scan failed: " + err.Error())
        // Continue - SBOM is optional
    } else {
        result.Packages = sbom.Packages
    }

    // Vulnerability scan
    vulns, err := s.ScanVulnerabilities()
    if err != nil {
        logger.Warn("Vulnerability scan failed: " + err.Error())
        // Continue - return partial results
    } else {
        result.Vulnerabilities = vulns
    }

    return result, nil  // Return what we have
}
```

---

## 8. Logging Best Practices

### 8.1 Structured Logging

```go
// Color-coded severity
logger.Info("Scan started")     // Blue
logger.Warn("No MR detected")   // Yellow
logger.Error("Scan failed")     // Red

// Table output for metadata
tbl := table.NewWriter()
tbl.AppendRow(table.Row{"Provider", gitEnv.Provider()})
tbl.AppendRow(table.Row{"Repository", gitEnv.ProjectName()})
tbl.AppendRow(table.Row{"Branch", gitEnv.CommitBranch()})
tbl.AppendRow(table.Row{"Strategy", scanStrategy.String()})
tbl.Render()
```

### 8.2 Progress Indicators

```go
fmt.Printf("[%s] Scanning %s...\n", scanner.Name(), target)
fmt.Printf("[%s] Completed in %dms\n", scanner.Name(), duration)
fmt.Printf("[%s] Found %d findings\n", scanner.Name(), count)
fmt.Printf("[%s] Pushed: %d created, %d updated\n", scanner.Name(), created, updated)
```

---

## 9. Docker Best Practices

### 9.1 Multi-Stage Build

```dockerfile
# Stage 1: Build
FROM golang:1.23-alpine AS build
ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /go/src/app
COPY . .
RUN go build -o /agent ./cmd/agent

# Stage 2: Runtime with scanner
FROM returntocorp/semgrep  # Or aquasec/trivy, zricethezav/gitleaks
COPY --from=build /agent /agent
ENTRYPOINT []
CMD ["/agent", "run"]
```

### 9.2 Scanner Images

| Scanner | Base Image |
|---------|-----------|
| Semgrep | `returntocorp/semgrep` |
| Trivy | `aquasec/trivy` |
| Gitleaks | `zricethezav/gitleaks` |

---

## 10. Testing Strategy

### 10.1 Test Types

1. **Unit Tests**: Parser, transformer functions
2. **Integration Tests**: Scanner execution
3. **Concurrent Tests**: Parallel scan validation
4. **Mock CI Tests**: Simulated CI environment

### 10.2 Test Environment Setup

```go
func setupTestEnv() {
    os.Setenv("GITLAB_CI", "true")
    os.Setenv("CI_PROJECT_ID", "12345")
    os.Setenv("CI_COMMIT_SHA", "abc123")
    os.Setenv("API_URL", "http://localhost:8080")
    os.Setenv("API_KEY", "test-token")
}
```

### 10.3 Test Data

```
testdata/
├── semgrep/
│   └── sample_output.json
├── trivy/
│   ├── sbom.json
│   └── vulnerabilities.json
├── gitleaks/
│   └── secrets.json
└── sample_project/
    ├── vulnerable_code.py
    ├── package.json
    └── .env.example
```

---

## 11. Configuration

### 11.1 Environment Variables

```bash
# API Configuration
API_URL=https://api.openctem.io
API_KEY=your-api-key
WORKER_ID=worker-123

# Scan Configuration
MAX_CHANGED_FILES=512
PROJECT_PATH=.
SCAN_TIMEOUT=30m

# Scanner-specific
SEMGREP_RULES=auto
TRIVY_SKIP_DB_UPDATE=false
GITLEAKS_CONFIG=.gitleaks.toml

# Output
VERBOSE=true
OUTPUT_FORMAT=json
OUTPUT_FILE=results.json
```

### 11.2 Config File (YAML)

```yaml
agent:
  name: my-agent
  verbose: true
  scan_interval: 1h

openctem:
  base_url: ${API_URL}
  api_key: ${API_KEY}
  worker_id: ${WORKER_ID}

scanners:
  - name: semgrep
    enabled: true
  - name: gitleaks
    enabled: true
  - name: trivy
    enabled: true

targets:
  - .
```

---

## 12. Summary: Key Patterns

| Pattern | Description | Source |
|---------|-------------|--------|
| Plugin Architecture | Scanner as interface | All projects |
| Handler Strategy | Local vs Remote output | code-secure-analyzer |
| Scan Strategy | AllFiles vs ChangedFileOnly | code-secure-analyzer |
| CI Auto-Detection | GitEnv interface | code-secure-analyzer |
| Fingerprint Dedup | Unique finding identity | code-secure-gitleaks |
| Dual-Scan | SBOM + Vulnerabilities | code-secure-trivy |
| Graceful Degradation | Continue on partial failure | All projects |
| Real-time Logging | Goroutine-based streaming | All projects |
| MR/PR Comments | Inline finding comments | code-secure-analyzer |
| CVSS Priority | NVD > GHSA > Others | code-secure-trivy |

---

## Implementation Checklist

### Core Interfaces
- [x] Scanner interfaces (Sast, Sca, Secret)
- [x] GitEnv auto-detection (GitHub, GitLab)
- [x] Scan strategy determination
- [x] Handler lifecycle (OnStart → HandleFindings → OnCompleted)
- [x] Remote handler with API integration
- [x] MR/PR inline comments
- [x] Fingerprint-based deduplication
- [x] Graceful error handling
- [x] Real-time logging

### Scanner Implementations
- [ ] Semgrep scanner (SAST)
- [x] Gitleaks scanner (Secret Detection)
- [ ] Trivy scanner (SCA)
- [ ] Web3 scanners (Slither, Aderyn)

### CTIS Schema (v1.0)
- [x] Finding with DataFlow support
- [x] LogicalLocation for code context
- [x] FindingStatus for workflow
- [x] Suppression tracking
- [x] Enhanced VulnerabilityDetails (PURL, EPSS)
- [x] Enhanced SecretDetails (scopes, rotation)
- [x] Web3 vulnerability details

### Deployment
- [ ] Multi-stage Docker builds
- [ ] CI/CD pipeline templates
- [ ] Comprehensive testing

---

## 13. Gitleaks Scanner Implementation

### 13.1 Scanner Usage

```go
import (
    "github.com/openctemio/sdk-go/sdk/scanners"
    "github.com/openctemio/sdk-go/sdk/scanners/gitleaks"
)

// Quick start - default configuration
scanner := scanners.Gitleaks()

// Custom configuration
scanner := scanners.GitleaksWithConfig(scanners.GitleaksOptions{
    Binary:     "/usr/local/bin/gitleaks",
    ConfigFile: ".gitleaks.toml",
    Timeout:    30 * time.Minute,
    Verbose:    true,
})

// Check if installed
installed, version, _ := scanner.IsInstalled(ctx)

// Run scan
result, err := scanner.Scan(ctx, "/path/to/repo", &core.SecretScanOptions{
    Exclude: []string{"vendor/", "node_modules/"},
    NoGit:   false,
})
```

### 13.2 Parser Usage

```go
import "github.com/openctemio/sdk-go/sdk/scanners/gitleaks"

// Parse gitleaks JSON output to CTIS format
parser := &gitleaks.Parser{}
report, err := parser.Parse(ctx, jsonData, &core.ParseOptions{
    AssetType:  ctis.AssetTypeRepository,
    AssetValue: "github.com/org/repo",
    Branch:     "main",
    CommitSHA:  "abc123",
})
```

### 13.3 Fingerprint Strategy

Gitleaks native fingerprint format: `{commit}:{file}:{rule}:{startLine}:{secretHash}`

Our fallback (when native not available):
```go
fingerprint := GenerateSecretFingerprint(file, ruleID, startLine, secretValue)
// Format: sha256(file:ruleID:startLine:secretHash[:8])
```
