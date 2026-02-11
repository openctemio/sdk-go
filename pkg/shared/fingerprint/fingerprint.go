// Package fingerprint provides unified fingerprint generation algorithms
// for deduplication of security findings across SDK and Backend.
//
// IMPORTANT: This package is shared between sdk and api.
// Any changes to fingerprint algorithms must be backward compatible
// or coordinated across both projects.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Type represents the type of finding for fingerprint generation.
type Type string

const (
	// TypeSAST is for Static Application Security Testing findings (code vulnerabilities).
	TypeSAST Type = "sast"

	// TypeSCA is for Software Composition Analysis findings (dependency vulnerabilities).
	TypeSCA Type = "sca"

	// TypeSecret is for secret/credential detection findings.
	TypeSecret Type = "secret"

	// TypeMisconfiguration is for infrastructure/configuration findings.
	TypeMisconfiguration Type = "misconfig"

	// TypeDAST is for Dynamic Application Security Testing findings (Nuclei, ZAP).
	TypeDAST Type = "dast"

	// TypeContainer is for container image vulnerability findings (Trivy image).
	TypeContainer Type = "container"

	// TypeWeb3 is for smart contract/blockchain findings (Slither).
	TypeWeb3 Type = "web3"

	// TypeGeneric is for findings that don't fit other categories.
	TypeGeneric Type = "generic"
)

// Input contains the data needed to generate a fingerprint.
// Not all fields are required - only the relevant ones for the finding type.
type Input struct {
	// Type of finding (sast, sca, secret, misconfig, generic)
	Type Type

	// Common fields
	RuleID   string // Rule/check identifier
	FilePath string // File path where finding was detected
	Message  string // Finding message/description

	// Location fields (for SAST, Secret)
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	// SCA-specific fields
	PackageName     string // Package/dependency name
	PackageVersion  string // Package version
	VulnerabilityID string // CVE ID or other vuln identifier

	// Secret-specific fields
	SecretValue string // The actual secret (will be hashed)

	// Misconfiguration-specific fields
	ResourceType string // e.g., "aws_s3_bucket", "dockerfile"
	ResourceName string // Resource identifier

	// DAST-specific fields (for Nuclei, ZAP)
	TargetHost string // Target hostname (e.g., "example.com")
	TargetPath string // URL path (e.g., "/api/users")
	Parameter  string // Affected parameter name (e.g., "id")

	// Container-specific fields (for Trivy image)
	ImageTarget string // Image name or digest (e.g., "nginx:latest", "sha256:abc...")

	// Web3-specific fields (for Slither)
	ContractAddress   string // Contract address (e.g., "0x...")
	ChainID           int    // Blockchain chain ID (e.g., 1 for Ethereum mainnet)
	SWCID             string // SWC registry ID (e.g., "SWC-101")
	FunctionSignature string // Function signature (e.g., "transfer(address,uint256)")
}

// Generate creates a fingerprint for the given input.
// The fingerprint is a SHA256 hash (64 hex characters) that uniquely
// identifies a finding based on its type and relevant attributes.
//
// The algorithm varies by finding type to ensure optimal deduplication:
//   - SAST: file + rule + location (same vulnerability in same place)
//   - SCA: package + version + vuln ID (same vuln in same dependency)
//   - Secret: file + rule + location + secret hash (same secret in same place)
//   - Misconfig: resource + rule (same misconfiguration on same resource)
//   - Generic: rule + file + location + message (fallback)
func Generate(input Input) string {
	var data string

	switch input.Type {
	case TypeSAST:
		// SAST: Deduplicate by file location and rule
		// Same vulnerability in the same file/line should be the same finding
		data = fmt.Sprintf("sast:%s:%s:%d:%d",
			normalize(input.FilePath),
			normalize(input.RuleID),
			input.StartLine,
			input.EndLine,
		)

	case TypeSCA:
		// SCA: Deduplicate by package and vulnerability
		// Same CVE in the same package version is the same finding
		data = fmt.Sprintf("sca:%s:%s:%s",
			normalize(input.PackageName),
			normalize(input.PackageVersion),
			normalize(input.VulnerabilityID),
		)

	case TypeSecret:
		// Secret: Include secret hash to distinguish different secrets at same location
		// This handles cases where multiple secrets exist on the same line
		secretHash := ""
		if input.SecretValue != "" {
			secretHash = Hash(input.SecretValue)[:16] // First 16 chars
		}
		data = fmt.Sprintf("secret:%s:%s:%d:%s",
			normalize(input.FilePath),
			normalize(input.RuleID),
			input.StartLine,
			secretHash,
		)

	case TypeMisconfiguration:
		// Misconfig: Deduplicate by resource and rule
		data = fmt.Sprintf("misconfig:%s:%s:%s:%s",
			normalize(input.ResourceType),
			normalize(input.ResourceName),
			normalize(input.RuleID),
			normalize(input.FilePath),
		)

	case TypeDAST:
		// DAST: Deduplicate by template, host, path, and parameter
		// This handles dynamic findings from Nuclei, ZAP, etc.
		// Parameter name (not value) is used to avoid ?id=1 vs ?id=2 mismatches
		data = fmt.Sprintf("dast:%s:%s:%s:%s",
			normalize(input.RuleID), // Template ID
			normalizeHost(input.TargetHost),
			normalizePath(input.TargetPath),
			normalize(input.Parameter),
		)

	case TypeContainer:
		// Container: Deduplicate by image target, package, and vulnerability
		// Similar to SCA but includes image target for multi-image scenarios
		data = fmt.Sprintf("container:%s:%s:%s:%s",
			normalize(input.ImageTarget),
			normalize(input.PackageName),
			normalize(input.PackageVersion),
			normalize(input.VulnerabilityID),
		)

	case TypeWeb3:
		// Web3: Deduplicate by contract, chain, SWC ID, and function
		// Handles smart contract findings from Slither, Mythril, etc.
		data = fmt.Sprintf("web3:%s:%d:%s:%s",
			normalizeAddress(input.ContractAddress),
			input.ChainID,
			normalize(input.SWCID),
			normalize(input.FunctionSignature),
		)

	default:
		// Generic: Use all available location data
		data = fmt.Sprintf("generic:%s:%s:%d:%d:%s",
			normalize(input.RuleID),
			normalize(input.FilePath),
			input.StartLine,
			input.EndLine,
			normalize(input.Message),
		)
	}

	return Hash(data)
}

// GenerateSAST creates a fingerprint for SAST/code vulnerability findings.
// This is a convenience function for the common SAST case.
func GenerateSAST(filePath, ruleID string, startLine, endLine int) string {
	return Generate(Input{
		Type:      TypeSAST,
		FilePath:  filePath,
		RuleID:    ruleID,
		StartLine: startLine,
		EndLine:   endLine,
	})
}

// GenerateSCA creates a fingerprint for SCA/dependency vulnerability findings.
// This is a convenience function for the common SCA case.
func GenerateSCA(packageName, packageVersion, vulnID string) string {
	return Generate(Input{
		Type:            TypeSCA,
		PackageName:     packageName,
		PackageVersion:  packageVersion,
		VulnerabilityID: vulnID,
	})
}

// GenerateSecret creates a fingerprint for secret detection findings.
// This is a convenience function for the common secret case.
func GenerateSecret(filePath, ruleID string, startLine int, secretValue string) string {
	return Generate(Input{
		Type:        TypeSecret,
		FilePath:    filePath,
		RuleID:      ruleID,
		StartLine:   startLine,
		SecretValue: secretValue,
	})
}

// GenerateMisconfiguration creates a fingerprint for misconfiguration findings.
func GenerateMisconfiguration(resourceType, resourceName, ruleID, filePath string) string {
	return Generate(Input{
		Type:         TypeMisconfiguration,
		ResourceType: resourceType,
		ResourceName: resourceName,
		RuleID:       ruleID,
		FilePath:     filePath,
	})
}

// GenerateGeneric creates a fingerprint for generic findings.
// Use this when the finding type doesn't fit other categories.
func GenerateGeneric(ruleID, filePath string, startLine, endLine int, message string) string {
	return Generate(Input{
		Type:      TypeGeneric,
		RuleID:    ruleID,
		FilePath:  filePath,
		StartLine: startLine,
		EndLine:   endLine,
		Message:   message,
	})
}

// GenerateDAST creates a fingerprint for DAST findings (Nuclei, ZAP, etc.).
// templateID is the scanner rule/template ID.
// targetHost is the hostname being scanned.
// targetPath is the URL path where the finding was detected.
// parameter is the affected parameter name (not value).
func GenerateDAST(templateID, targetHost, targetPath, parameter string) string {
	return Generate(Input{
		Type:       TypeDAST,
		RuleID:     templateID,
		TargetHost: targetHost,
		TargetPath: targetPath,
		Parameter:  parameter,
	})
}

// GenerateContainer creates a fingerprint for container image vulnerability findings.
// imageTarget is the image name or digest (e.g., "nginx:latest").
// packageName is the vulnerable package name.
// packageVersion is the installed package version.
// vulnID is the CVE or other vulnerability identifier.
func GenerateContainer(imageTarget, packageName, packageVersion, vulnID string) string {
	return Generate(Input{
		Type:            TypeContainer,
		ImageTarget:     imageTarget,
		PackageName:     packageName,
		PackageVersion:  packageVersion,
		VulnerabilityID: vulnID,
	})
}

// GenerateWeb3 creates a fingerprint for smart contract findings (Slither, Mythril, etc.).
// contractAddress is the contract address (e.g., "0x...").
// chainID is the blockchain chain ID (e.g., 1 for Ethereum mainnet).
// swcID is the SWC registry ID (e.g., "SWC-101").
// functionSignature is the affected function (e.g., "transfer(address,uint256)").
func GenerateWeb3(contractAddress string, chainID int, swcID, functionSignature string) string {
	return Generate(Input{
		Type:              TypeWeb3,
		ContractAddress:   contractAddress,
		ChainID:           chainID,
		SWCID:             swcID,
		FunctionSignature: functionSignature,
	})
}

// Hash computes SHA256 hash of the input string.
// Returns 64 hex characters.
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// normalize cleans up a string for consistent fingerprinting.
// - Trims whitespace
// - Converts to lowercase for case-insensitive matching
// - Normalizes path separators
func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	// Normalize Windows paths to Unix style
	s = strings.ReplaceAll(s, "\\", "/")
	return s
}

// normalizeHost cleans up a hostname for DAST fingerprinting.
// - Removes protocol prefix (http://, https://)
// - Removes port if it's default (80, 443)
// - Converts to lowercase
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.ToLower(host)

	// Remove protocol prefix
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")

	// Remove trailing slash
	host = strings.TrimSuffix(host, "/")

	// Remove default ports
	host = strings.TrimSuffix(host, ":443")
	host = strings.TrimSuffix(host, ":80")

	return host
}

// normalizePath cleans up a URL path for DAST fingerprinting.
// - Removes query string (we use parameter name separately)
// - Removes fragment
// - Normalizes leading/trailing slashes
func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ToLower(path)

	// Remove query string
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Remove fragment
	if idx := strings.Index(path, "#"); idx != -1 {
		path = path[:idx]
	}

	// Ensure leading slash
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Remove trailing slash (except for root)
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}

	return path
}

// normalizeAddress cleans up a blockchain address for Web3 fingerprinting.
// - Converts to lowercase (addresses are case-insensitive in most chains)
// - Ensures 0x prefix for Ethereum-style addresses
func normalizeAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.ToLower(addr)

	// Ensure 0x prefix for Ethereum-style addresses
	if len(addr) == 40 && !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}

	return addr
}

// DetectType attempts to detect the finding type from available data.
// This is useful when the type is not explicitly provided.
func DetectType(input Input) Type {
	// Web3: Has contract address or SWC ID
	if input.ContractAddress != "" || input.SWCID != "" {
		return TypeWeb3
	}

	// Container: Has image target with package info
	if input.ImageTarget != "" && input.PackageName != "" {
		return TypeContainer
	}

	// DAST: Has target host
	if input.TargetHost != "" {
		return TypeDAST
	}

	// SCA: Has package and vulnerability info (but no image target)
	if input.PackageName != "" && input.VulnerabilityID != "" {
		return TypeSCA
	}

	// Secret: Has secret value
	if input.SecretValue != "" {
		return TypeSecret
	}

	// Misconfig: Has resource info
	if input.ResourceType != "" || input.ResourceName != "" {
		return TypeMisconfiguration
	}

	// SAST: Has file location with rule
	if input.FilePath != "" && input.RuleID != "" && input.StartLine > 0 {
		return TypeSAST
	}

	return TypeGeneric
}

// GenerateAuto automatically detects the type and generates a fingerprint.
// Use this when you're not sure which specific generator to use.
func GenerateAuto(input Input) string {
	if input.Type == "" {
		input.Type = DetectType(input)
	}
	return Generate(input)
}
