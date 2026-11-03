package core

import (
	"strings"

	"github.com/openctemio/ctis/v2/fingerprint"

	"github.com/openctemio/sdk-go/pkg/shared/severity"
)

// =============================================================================
// Fingerprints (CTIS recipe ctis-fp/2, github.com/openctemio/ctis/v2/fingerprint)
// =============================================================================

// SASTFingerprint is the CTIS recipe v2 fingerprint of a line-based SAST
// finding (fingerprint.V2SAST; endLine 0 when unknown).
func SASTFingerprint(file, ruleID string, startLine, endLine int) string {
	return fingerprint.V2SAST(file, ruleID, startLine, endLine)
}

// SCAFingerprint is the CTIS recipe v2 fingerprint of a dependency
// vulnerability: the versionless package (a purl, or "ecosystem/name") and
// the vulnerability id (fingerprint.V2SCA).
func SCAFingerprint(packageRef, vulnID string) string {
	return fingerprint.V2SCA(packageRef, vulnID)
}

// SecretFingerprint is the CTIS recipe v2 fingerprint of a secret finding:
// its input is HMAC-SHA256(key, secret) (fingerprint.NewSecretDigest), never
// the secret or a masked copy. key is the producer's secret fingerprint key
// (at least fingerprint.MinSecretKeyBytes). Without a valid key, or without
// a secret, it returns "": there is no unsalted path, and the receiver then
// computes its own fingerprint.
func SecretFingerprint(key []byte, file, ruleID, secret string) string {
	d, err := fingerprint.NewSecretDigest(key, []byte(secret))
	if err != nil {
		return ""
	}
	return fingerprint.V2Secret(file, ruleID, d)
}

// =============================================================================
// CVSS Score Handling
// =============================================================================

// CVSSSource represents the source of CVSS data.
type CVSSSource string

const (
	CVSSSourceNVD     CVSSSource = "nvd"     // National Vulnerability Database
	CVSSSourceGHSA    CVSSSource = "ghsa"    // GitHub Security Advisory
	CVSSSourceRedHat  CVSSSource = "redhat"  // Red Hat
	CVSSSourceBitnami CVSSSource = "bitnami" // Bitnami
)

// CVSSData holds CVSS information from various sources.
type CVSSData struct {
	Source CVSSSource `json:"source"`
	Score  float64    `json:"score"`
	Vector string     `json:"vector"`
}

// CVSSPriority defines the priority order for CVSS sources.
// Higher priority sources are preferred.
var CVSSPriority = []CVSSSource{
	CVSSSourceNVD,     // Most authoritative
	CVSSSourceGHSA,    // Well-maintained
	CVSSSourceRedHat,  // Enterprise focused
	CVSSSourceBitnami, // Container focused
}

// SelectBestCVSS selects the best CVSS data from multiple sources.
// Uses priority order: NVD > GHSA > RedHat > Bitnami
func SelectBestCVSS(cvssMap map[CVSSSource]CVSSData) *CVSSData {
	for _, source := range CVSSPriority {
		if data, ok := cvssMap[source]; ok && data.Score > 0 {
			return &data
		}
	}
	return nil
}

// =============================================================================
// Severity Mapping (delegates to shared package)
// =============================================================================

// SeverityFromCVSS converts a CVSS score to severity level.
// Deprecated: Use severity.FromCVSS from pkg/shared/severity instead.
func SeverityFromCVSS(score float64) string {
	return severity.FromCVSS(score).String()
}

// NormalizeSeverity normalizes severity strings from different scanners.
// Deprecated: Use severity.FromString from pkg/shared/severity instead.
func NormalizeSeverity(sev string) string {
	return severity.FromString(sev).String()
}

// =============================================================================
// Package Type Detection
// =============================================================================

// PackageType represents the package ecosystem.
type PackageType string

const (
	PackageTypeMaven    PackageType = "maven"
	PackageTypeNPM      PackageType = "npm"
	PackageTypePyPI     PackageType = "pip"
	PackageTypeGo       PackageType = "gomod"
	PackageTypeCargo    PackageType = "cargo"
	PackageTypeNuGet    PackageType = "nuget"
	PackageTypeGem      PackageType = "gem"
	PackageTypeComposer PackageType = "composer"
)

// DetectPackageType detects the package type from a manifest file.
func DetectPackageType(filename string) PackageType {
	lower := strings.ToLower(filename)
	switch {
	case strings.Contains(lower, "pom.xml") || strings.Contains(lower, ".pom"):
		return PackageTypeMaven
	case strings.Contains(lower, "package.json") || strings.Contains(lower, "package-lock.json") || strings.Contains(lower, "yarn.lock"):
		return PackageTypeNPM
	case strings.Contains(lower, "requirements.txt") || strings.Contains(lower, "setup.py") || strings.Contains(lower, "pipfile") || strings.Contains(lower, "pyproject.toml"):
		return PackageTypePyPI
	case strings.Contains(lower, "go.mod") || strings.Contains(lower, "go.sum"):
		return PackageTypeGo
	case strings.Contains(lower, "cargo.toml") || strings.Contains(lower, "cargo.lock"):
		return PackageTypeCargo
	case strings.Contains(lower, ".csproj") || strings.Contains(lower, "packages.config") || strings.Contains(lower, ".nuspec"):
		return PackageTypeNuGet
	case strings.Contains(lower, "gemfile") || strings.Contains(lower, ".gemspec"):
		return PackageTypeGem
	case strings.Contains(lower, "composer.json") || strings.Contains(lower, "composer.lock"):
		return PackageTypeComposer
	default:
		return ""
	}
}

// =============================================================================
// Masking Utilities
// =============================================================================

// secretMaskMarker stands for the hidden part of a masked secret. Its length
// is fixed, so a masked value does not reveal the secret's length.
const secretMaskMarker = "****"

const (
	// secretMinVisibleLen is the shortest secret (in characters) of which
	// any character is shown. Shorter secrets are masked completely.
	secretMinVisibleLen = 12
	// secretMaxVisibleEnd is the most characters shown at either end.
	secretMaxVisibleEnd = 4
)

// secretVisibleEnds returns how many characters of an n-character secret
// may be shown at its start and at its end: none below
// secretMinVisibleLen characters, otherwise a quarter of the secret in
// total, at most secretMaxVisibleEnd at each end. The start gets the odd
// character: it is usually the token type prefix ("ghp_", "AKIA").
func secretVisibleEnds(n int) (head, tail int) {
	if n < secretMinVisibleLen {
		return 0, 0
	}
	show := n / 4
	if show > 2*secretMaxVisibleEnd {
		show = 2 * secretMaxVisibleEnd
	}
	return (show + 1) / 2, show / 2
}

// MaskSecret masks a secret value for display and for use as a fingerprint
// input (CTIS spec 4.8 and 5.2). It never shows more than a quarter of the
// secret, at most 4 characters at either end, and nothing at all of a
// secret shorter than 12 characters:
//
//	MaskSecret("not-a-real-1")                       == "no****1"
//	MaskSecret("short-one")                          == "****"
//	MaskSecret("fake_tok_0123456789abcdefghijklmn") == "fake****klmn"
//
// Characters are counted as runes, so a multi-byte character is never cut.
func MaskSecret(secret string) string {
	r := []rune(secret)
	head, tail := secretVisibleEnds(len(r))
	if head == 0 && tail == 0 {
		return secretMaskMarker
	}
	return string(r[:head]) + secretMaskMarker + string(r[len(r)-tail:])
}

// MaskSecretInText returns text with every occurrence of secret replaced by
// MaskSecret(secret). It is for context strings such as a scanner's matched
// line, which embed the raw secret.
//
// It fails safe: when secret is empty or does not occur in text (the scanner
// trimmed or re-encoded it), the whole text is replaced by the mask marker,
// because no part of the text can be shown to be free of the secret.
func MaskSecretInText(text, secret string) string {
	if text == "" {
		return ""
	}
	if secret == "" || !strings.Contains(text, secret) {
		return secretMaskMarker
	}
	return strings.ReplaceAll(text, secret, MaskSecret(secret))
}

// MaskAPIKey masks an API key for logs. It shows as many characters as
// MaskSecret does: none below 12 characters, at most a quarter in total.
func MaskAPIKey(key string) string {
	r := []rune(key)
	head, tail := secretVisibleEnds(len(r))
	if head == 0 && tail == 0 {
		return "****"
	}
	return string(r[:head]) + "..." + string(r[len(r)-tail:])
}
