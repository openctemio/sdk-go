package ctis

import (
	"slices"
	"time"
)

// Report is the root CTIS document containing assets and findings.
type Report struct {
	// Schema version (required)
	Version string `json:"version"`

	// Schema URL for validation (optional)
	Schema string `json:"$schema,omitempty"`

	// Report metadata
	Metadata ReportMetadata `json:"metadata"`

	// Tool information (for collector/scanner reports)
	Tool *Tool `json:"tool,omitempty"`

	// Assets discovered/collected
	Assets []Asset `json:"assets,omitempty"`

	// Findings discovered
	Findings []Finding `json:"findings,omitempty"`

	// Dependencies (SBOM)
	Dependencies []Dependency `json:"dependencies,omitempty"`

	// Custom properties
	Properties Properties `json:"properties,omitempty"`
}

// ReportMetadata contains metadata about the report.
type ReportMetadata struct {
	// Unique identifier for this report/scan (recommended)
	ID string `json:"id,omitempty"`

	// Timestamp when the report was generated (required)
	Timestamp time.Time `json:"timestamp"`

	// Duration of the scan/collection in milliseconds (optional)
	DurationMs int `json:"duration_ms,omitempty"`

	// Source type: scanner, collector, integration, manual
	SourceType string `json:"source_type,omitempty"`

	// External reference (job ID, scan ID)
	SourceRef string `json:"source_ref,omitempty"`

	// Coverage type: full, incremental, partial
	// - full: Complete scan of entire scope (enables auto-resolve)
	// - incremental: Diff scan of changed files only (no auto-resolve)
	// - partial: Partial scan of specific directories (no auto-resolve)
	CoverageType string `json:"coverage_type,omitempty"`

	// Branch information for git-based scans
	// Used for branch-aware finding lifecycle management
	Branch *BranchInfo `json:"branch,omitempty"`

	// Target scope of the scan/collection
	Scope *Scope `json:"scope,omitempty"`

	// Custom properties
	Properties Properties `json:"properties,omitempty"`
}

// BranchInfo contains git branch context for CI/CD scans.
// Used for branch-aware finding lifecycle management (auto-resolve, expiry).
type BranchInfo struct {
	// Branch name (e.g., "main", "feature/xyz", "refs/heads/main")
	Name string `json:"name"`

	// Whether this is the default branch (main/master)
	// Auto-resolve only applies to default branch scans
	IsDefaultBranch bool `json:"is_default_branch"`

	// Commit SHA being scanned
	CommitSHA string `json:"commit_sha,omitempty"`

	// Base branch for PR/MR scans (e.g., "main" when scanning a PR targeting main)
	BaseBranch string `json:"base_branch,omitempty"`

	// PR/MR number if this is a pull request scan
	PullRequestNumber int `json:"pull_request_number,omitempty"`

	// PR/MR URL if this is a pull request scan
	PullRequestURL string `json:"pull_request_url,omitempty"`

	// Repository URL for context
	RepositoryURL string `json:"repository_url,omitempty"`
}

// Scope defines the target scope of the scan/collection.
type Scope struct {
	// Scope name or identifier
	Name string `json:"name,omitempty"`

	// Scope type: domain, network, repository, cloud_account
	Type string `json:"type,omitempty"`

	// Included targets
	Includes []string `json:"includes,omitempty"`

	// Excluded targets
	Excludes []string `json:"excludes,omitempty"`
}

// Tool describes the tool that generated this report.
type Tool struct {
	// Tool name (required)
	Name string `json:"name"`

	// Tool version (recommended)
	Version string `json:"version,omitempty"`

	// Tool vendor/organization
	Vendor string `json:"vendor,omitempty"`

	// Tool information URL
	InfoURL string `json:"info_url,omitempty"`

	// Tool capabilities
	Capabilities []string `json:"capabilities,omitempty"`

	// Custom properties
	Properties Properties `json:"properties,omitempty"`
}

// =============================================================================
// Asset Types
// =============================================================================

// Asset represents a discovered asset.
type Asset struct {
	// Unique identifier for this asset within the report
	ID string `json:"id,omitempty"`

	// Asset type (required): domain, ip_address, repository, certificate, etc.
	Type AssetType `json:"type"`

	// Primary value of the asset (required)
	// For domain: "example.com"
	// For ip_address: "192.168.1.1"
	// For repository: "github.com/org/repo"
	Value string `json:"value"`

	// Human-readable name
	Name string `json:"name,omitempty"`

	// Description
	Description string `json:"description,omitempty"`

	// Tags for categorization
	Tags []string `json:"tags,omitempty"`

	// Asset criticality: critical, high, medium, low, info
	Criticality Criticality `json:"criticality,omitempty"`

	// Confidence score 0-100 (how confident the source is about this asset)
	Confidence int `json:"confidence,omitempty"`

	// When this asset was discovered
	DiscoveredAt *time.Time `json:"discovered_at,omitempty"`

	// Asset-specific technical details
	Technical *AssetTechnical `json:"technical,omitempty"`

	// Related assets (by ID within this report)
	RelatedAssets []string `json:"related_assets,omitempty"`

	// CTEM: Compliance context for the asset
	Compliance *AssetCompliance `json:"compliance,omitempty"`

	// CTEM: Services running on this asset
	Services []ServiceInfo `json:"services,omitempty"`

	// CTEM: Is the asset directly accessible from the internet
	IsInternetAccessible bool `json:"is_internet_accessible,omitempty"`

	// Custom properties
	Properties Properties `json:"properties,omitempty"`
}

// AssetCompliance contains CTEM compliance context for an asset.
type AssetCompliance struct {
	// Compliance frameworks this asset is in scope for: PCI-DSS, HIPAA, SOC2, GDPR, ISO27001
	Frameworks []string `json:"frameworks,omitempty"`

	// Data classification level: public, internal, confidential, restricted, secret
	DataClassification string `json:"data_classification,omitempty"`

	// Asset contains Personally Identifiable Information
	PIIExposed bool `json:"pii_exposed,omitempty"`

	// Asset contains Protected Health Information
	PHIExposed bool `json:"phi_exposed,omitempty"`

	// Regulatory owner email/username
	RegulatoryOwner string `json:"regulatory_owner,omitempty"`
}

// ServiceInfo represents a network service discovered on an asset.
type ServiceInfo struct {
	// Port number
	Port int `json:"port"`

	// Transport protocol: tcp, udp
	Protocol string `json:"protocol,omitempty"`

	// Service type: http, https, ssh, ftp, mysql, postgresql, etc.
	ServiceType string `json:"service_type,omitempty"`

	// Product name: Apache, nginx, OpenSSH, etc.
	Product string `json:"product,omitempty"`

	// Product version
	Version string `json:"version,omitempty"`

	// Service banner
	Banner string `json:"banner,omitempty"`

	// Common Platform Enumeration identifier
	CPE string `json:"cpe,omitempty"`

	// Is this service publicly accessible from the internet
	IsPublic bool `json:"is_public,omitempty"`

	// TLS enabled
	TLSEnabled bool `json:"tls_enabled,omitempty"`

	// TLS version: TLS 1.2, TLS 1.3
	TLSVersion string `json:"tls_version,omitempty"`

	// Service state: active, inactive, filtered
	State string `json:"state,omitempty"`
}

// AssetTechnical contains type-specific technical details.
type AssetTechnical struct {
	// For domain assets
	Domain *DomainTechnical `json:"domain,omitempty"`

	// For IP address assets
	IPAddress *IPAddressTechnical `json:"ip_address,omitempty"`

	// For repository assets
	Repository *RepositoryTechnical `json:"repository,omitempty"`

	// For certificate assets
	Certificate *CertificateTechnical `json:"certificate,omitempty"`

	// For cloud assets
	Cloud *CloudTechnical `json:"cloud,omitempty"`

	// For service assets
	Service *ServiceTechnical `json:"service,omitempty"`

	// For Web3 assets (smart contracts, wallets, tokens, etc.)
	Web3 *Web3Technical `json:"web3,omitempty"`
}

// DomainTechnical contains domain-specific technical details.
type DomainTechnical struct {
	// Registrar information
	Registrar string `json:"registrar,omitempty"`

	// Registration date
	RegisteredAt *time.Time `json:"registered_at,omitempty"`

	// Expiration date
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Nameservers
	Nameservers []string `json:"nameservers,omitempty"`

	// DNS records
	DNSRecords []DNSRecord `json:"dns_records,omitempty"`

	// WHOIS data
	WHOIS map[string]string `json:"whois,omitempty"`
}

// DNSRecord represents a DNS record.
type DNSRecord struct {
	Type  string `json:"type"`  // A, AAAA, CNAME, MX, TXT, etc.
	Name  string `json:"name"`  // Record name
	Value string `json:"value"` // Record value
	TTL   int    `json:"ttl,omitempty"`
}

// IPAddressTechnical contains IP address-specific technical details.
type IPAddressTechnical struct {
	// IP version: 4 or 6
	Version int `json:"version,omitempty"`

	// Hostname (if resolved)
	Hostname string `json:"hostname,omitempty"`

	// ASN information
	ASN int `json:"asn,omitempty"`

	// ASN organization
	ASNOrg string `json:"asn_org,omitempty"`

	// Country code
	Country string `json:"country,omitempty"`

	// City
	City string `json:"city,omitempty"`

	// Open ports
	Ports []PortInfo `json:"ports,omitempty"`

	// Geolocation
	Geolocation *Geolocation `json:"geolocation,omitempty"`
}

// PortInfo contains information about an open port.
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // tcp, udp
	State    string `json:"state,omitempty"`    // open, filtered, closed
	Service  string `json:"service,omitempty"`  // http, ssh, etc.
	Banner   string `json:"banner,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Geolocation contains geographic coordinates.
type Geolocation struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  float64 `json:"accuracy,omitempty"` // in meters
}

// RepositoryTechnical contains repository-specific technical details.
type RepositoryTechnical struct {
	// SCM platform: github, gitlab, bitbucket
	Platform string `json:"platform,omitempty"`

	// Organization/owner
	Owner string `json:"owner,omitempty"`

	// Repository name
	Name string `json:"name,omitempty"`

	// Default branch
	DefaultBranch string `json:"default_branch,omitempty"`

	// Repository visibility: public, private, internal
	Visibility string `json:"visibility,omitempty"`

	// Repository URL
	URL string `json:"url,omitempty"`

	// Clone URL
	CloneURL string `json:"clone_url,omitempty"`

	// Language breakdown
	Languages map[string]int `json:"languages,omitempty"`

	// Stars count
	Stars int `json:"stars,omitempty"`

	// Forks count
	Forks int `json:"forks,omitempty"`

	// Last commit SHA
	LastCommitSHA string `json:"last_commit_sha,omitempty"`

	// Last commit date
	LastCommitAt *time.Time `json:"last_commit_at,omitempty"`
}

// CertificateTechnical contains certificate-specific technical details.
type CertificateTechnical struct {
	// Serial number
	SerialNumber string `json:"serial_number,omitempty"`

	// Subject common name
	SubjectCN string `json:"subject_cn,omitempty"`

	// Subject alternative names
	SANs []string `json:"sans,omitempty"`

	// Issuer common name
	IssuerCN string `json:"issuer_cn,omitempty"`

	// Issuer organization
	IssuerOrg string `json:"issuer_org,omitempty"`

	// Valid from
	NotBefore *time.Time `json:"not_before,omitempty"`

	// Valid until
	NotAfter *time.Time `json:"not_after,omitempty"`

	// Signature algorithm
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`

	// Key algorithm
	KeyAlgorithm string `json:"key_algorithm,omitempty"`

	// Key size in bits
	KeySize int `json:"key_size,omitempty"`

	// SHA-256 fingerprint
	Fingerprint string `json:"fingerprint,omitempty"`

	// Is self-signed
	SelfSigned bool `json:"self_signed,omitempty"`

	// Is expired
	Expired bool `json:"expired,omitempty"`

	// Is wildcard
	Wildcard bool `json:"wildcard,omitempty"`
}

// CloudTechnical contains cloud resource-specific technical details.
type CloudTechnical struct {
	// Cloud provider: aws, gcp, azure
	Provider string `json:"provider,omitempty"`

	// Account/project ID
	AccountID string `json:"account_id,omitempty"`

	// Region
	Region string `json:"region,omitempty"`

	// Availability zone
	Zone string `json:"zone,omitempty"`

	// Resource type: ec2, s3, rds, etc.
	ResourceType string `json:"resource_type,omitempty"`

	// Resource ID
	ResourceID string `json:"resource_id,omitempty"`

	// Resource ARN (AWS)
	ARN string `json:"arn,omitempty"`

	// Resource tags
	Tags map[string]string `json:"tags,omitempty"`
}

// ServiceTechnical contains service-specific technical details.
type ServiceTechnical struct {
	// Service name
	Name string `json:"name,omitempty"`

	// Service version
	Version string `json:"version,omitempty"`

	// Port
	Port int `json:"port,omitempty"`

	// Protocol (application-layer): http, https, ssh, smtp, ftp, dns, ldap, smb, rdp, mysql, postgresql, mongodb, redis, etc.
	Protocol string `json:"protocol,omitempty"`

	// Transport: tcp, udp
	Transport string `json:"transport,omitempty"`

	// SSL/TLS enabled
	TLS bool `json:"tls,omitempty"`

	// TLS version: tls1.0, tls1.1, tls1.2, tls1.3
	TLSVersion string `json:"tls_version,omitempty"`

	// TLS certificate info (for services with TLS)
	TLSCertSubject string `json:"tls_cert_subject,omitempty"`
	TLSCertIssuer  string `json:"tls_cert_issuer,omitempty"`
	TLSCertExpiry  string `json:"tls_cert_expiry,omitempty"`

	// Banner/fingerprint
	Banner string `json:"banner,omitempty"`

	// Product name (e.g., "OpenSSH", "nginx", "Apache", "Postfix")
	Product string `json:"product,omitempty"`

	// CPE (Common Platform Enumeration) identifier
	CPE string `json:"cpe,omitempty"`

	// Extra info
	ExtraInfo string `json:"extra_info,omitempty"`

	// Service state: open, filtered, closed
	State string `json:"state,omitempty"`

	// Authentication required
	AuthRequired bool `json:"auth_required,omitempty"`

	// Authentication methods supported (e.g., ["password", "publickey"] for SSH)
	AuthMethods []string `json:"auth_methods,omitempty"`

	// Default credentials detected
	DefaultCredentials bool `json:"default_credentials,omitempty"`

	// Anonymous access allowed (for FTP, SMB, etc.)
	AnonymousAccess bool `json:"anonymous_access,omitempty"`

	// Response time in milliseconds
	ResponseTimeMs int `json:"response_time_ms,omitempty"`

	// Last seen timestamp
	LastSeen string `json:"last_seen,omitempty"`

	// Service-specific details (protocol-dependent)
	// For HTTP: methods, headers, etc.
	// For SMTP: EHLO response, supported extensions
	// For SSH: supported algorithms, host keys
	Details map[string]any `json:"details,omitempty"`
}

// =============================================================================
// Web3 Technical Details
// =============================================================================

// Web3Technical contains Web3-specific technical details for smart contracts,
// wallets, tokens, and other blockchain assets.
type Web3Technical struct {
	// Blockchain network: ethereum, polygon, bsc, arbitrum, optimism, avalanche, solana, etc.
	Chain string `json:"chain,omitempty"`

	// Chain ID (EVM chains): 1 (mainnet), 137 (polygon), 56 (bsc), etc.
	ChainID int64 `json:"chain_id,omitempty"`

	// Network type: mainnet, testnet, devnet
	NetworkType string `json:"network_type,omitempty"`

	// Contract/wallet address
	Address string `json:"address,omitempty"`

	// For smart contracts
	Contract *SmartContractDetails `json:"contract,omitempty"`

	// For wallets
	Wallet *WalletDetails `json:"wallet,omitempty"`

	// For tokens (ERC-20, ERC-721, etc.)
	Token *TokenDetails `json:"token,omitempty"`

	// For DeFi protocols
	DeFi *DeFiDetails `json:"defi,omitempty"`

	// For NFT collections
	NFT *NFTCollectionDetails `json:"nft,omitempty"`
}

// SmartContractDetails contains smart contract-specific details.
type SmartContractDetails struct {
	// Contract name
	Name string `json:"name,omitempty"`

	// Contract address
	Address string `json:"address,omitempty"`

	// Deployer address
	DeployerAddress string `json:"deployer_address,omitempty"`

	// Deployment transaction hash
	DeploymentTxHash string `json:"deployment_tx_hash,omitempty"`

	// Deployment block number
	DeploymentBlock int64 `json:"deployment_block,omitempty"`

	// Deployment timestamp
	DeployedAt *time.Time `json:"deployed_at,omitempty"`

	// Is verified on explorer (etherscan, etc.)
	Verified bool `json:"verified,omitempty"`

	// Compiler version
	CompilerVersion string `json:"compiler_version,omitempty"`

	// EVM version
	EVMVersion string `json:"evm_version,omitempty"`

	// Optimization enabled
	OptimizationEnabled bool `json:"optimization_enabled,omitempty"`

	// Optimization runs
	OptimizationRuns int `json:"optimization_runs,omitempty"`

	// Contract type: erc20, erc721, erc1155, proxy, multisig, defi, custom
	ContractType string `json:"contract_type,omitempty"`

	// Is proxy contract
	IsProxy bool `json:"is_proxy,omitempty"`

	// Implementation address (for proxy contracts)
	ImplementationAddress string `json:"implementation_address,omitempty"`

	// Proxy type: transparent, uups, beacon, diamond
	ProxyType string `json:"proxy_type,omitempty"`

	// Is upgradeable
	IsUpgradeable bool `json:"is_upgradeable,omitempty"`

	// Owner/admin address
	OwnerAddress string `json:"owner_address,omitempty"`

	// Has renounced ownership
	OwnershipRenounced bool `json:"ownership_renounced,omitempty"`

	// Source code URL (GitHub, etc.)
	SourceCodeURL string `json:"source_code_url,omitempty"`

	// ABI (JSON string or base64 encoded)
	ABI string `json:"abi,omitempty"`

	// Bytecode hash (keccak256)
	BytecodeHash string `json:"bytecode_hash,omitempty"`

	// Source code hash
	SourceCodeHash string `json:"source_code_hash,omitempty"`

	// License type: MIT, GPL, UNLICENSED, etc.
	License string `json:"license,omitempty"`

	// External libraries used
	Libraries []ContractLibrary `json:"libraries,omitempty"`

	// Implemented interfaces: ERC20, ERC721, etc.
	Interfaces []string `json:"interfaces,omitempty"`

	// Contract balance (in wei)
	Balance string `json:"balance,omitempty"`

	// Total transactions
	TxCount int64 `json:"tx_count,omitempty"`
}

// ContractLibrary represents an external library linked to a contract.
type ContractLibrary struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// WalletDetails contains wallet-specific details.
type WalletDetails struct {
	// Wallet type: eoa, multisig, smart_wallet, mpc
	WalletType string `json:"wallet_type,omitempty"`

	// For multisig: required signatures
	RequiredSignatures int `json:"required_signatures,omitempty"`

	// For multisig: total owners
	TotalOwners int `json:"total_owners,omitempty"`

	// Owner addresses (for multisig)
	Owners []string `json:"owners,omitempty"`

	// Wallet provider: metamask, ledger, safe, argent, etc.
	Provider string `json:"provider,omitempty"`

	// Balance (native token, in wei)
	Balance string `json:"balance,omitempty"`

	// Token balances
	TokenBalances []TokenBalance `json:"token_balances,omitempty"`

	// NFT count
	NFTCount int `json:"nft_count,omitempty"`

	// First transaction timestamp
	FirstTxAt *time.Time `json:"first_tx_at,omitempty"`

	// Last transaction timestamp
	LastTxAt *time.Time `json:"last_tx_at,omitempty"`

	// Total transactions
	TxCount int64 `json:"tx_count,omitempty"`

	// ENS name (if applicable)
	ENSName string `json:"ens_name,omitempty"`

	// Labels (exchange, whale, hacker, etc.)
	Labels []string `json:"labels,omitempty"`
}

// TokenBalance represents a token balance for a wallet.
type TokenBalance struct {
	// Token contract address
	ContractAddress string `json:"contract_address"`

	// Token symbol
	Symbol string `json:"symbol,omitempty"`

	// Token name
	Name string `json:"name,omitempty"`

	// Token decimals
	Decimals int `json:"decimals,omitempty"`

	// Balance (raw value)
	Balance string `json:"balance"`

	// Balance formatted (human readable)
	BalanceFormatted string `json:"balance_formatted,omitempty"`

	// USD value
	USDValue float64 `json:"usd_value,omitempty"`
}

// TokenDetails contains token-specific details (ERC-20, etc.).
type TokenDetails struct {
	// Token standard: erc20, erc721, erc1155, bep20, spl
	Standard string `json:"standard,omitempty"`

	// Token symbol
	Symbol string `json:"symbol,omitempty"`

	// Token name
	Name string `json:"name,omitempty"`

	// Token decimals
	Decimals int `json:"decimals,omitempty"`

	// Total supply (raw value)
	TotalSupply string `json:"total_supply,omitempty"`

	// Max supply (if applicable)
	MaxSupply string `json:"max_supply,omitempty"`

	// Is mintable
	Mintable bool `json:"mintable,omitempty"`

	// Is burnable
	Burnable bool `json:"burnable,omitempty"`

	// Is pausable
	Pausable bool `json:"pausable,omitempty"`

	// Has blacklist/whitelist
	HasBlacklist bool `json:"has_blacklist,omitempty"`

	// Has transfer fee/tax
	HasTransferFee bool `json:"has_transfer_fee,omitempty"`

	// Transfer fee percentage
	TransferFeePercent float64 `json:"transfer_fee_percent,omitempty"`

	// Holder count
	HolderCount int64 `json:"holder_count,omitempty"`

	// Market cap USD
	MarketCapUSD float64 `json:"market_cap_usd,omitempty"`

	// Price USD
	PriceUSD float64 `json:"price_usd,omitempty"`

	// Liquidity USD
	LiquidityUSD float64 `json:"liquidity_usd,omitempty"`

	// Trading pairs
	TradingPairs []TradingPair `json:"trading_pairs,omitempty"`

	// Is honeypot
	IsHoneypot bool `json:"is_honeypot,omitempty"`

	// Honeypot reason
	HoneypotReason string `json:"honeypot_reason,omitempty"`
}

// TradingPair represents a trading pair for a token.
type TradingPair struct {
	// DEX name: uniswap, sushiswap, pancakeswap, etc.
	DEX string `json:"dex"`

	// Pair address
	PairAddress string `json:"pair_address"`

	// Quote token symbol (WETH, USDT, etc.)
	QuoteToken string `json:"quote_token"`

	// Liquidity USD
	LiquidityUSD float64 `json:"liquidity_usd,omitempty"`
}

// DeFiDetails contains DeFi protocol-specific details.
type DeFiDetails struct {
	// Protocol name: uniswap, aave, compound, etc.
	ProtocolName string `json:"protocol_name,omitempty"`

	// Protocol type: dex, lending, yield, bridge, derivatives, etc.
	ProtocolType string `json:"protocol_type,omitempty"`

	// Protocol version
	Version string `json:"version,omitempty"`

	// Total Value Locked (TVL) in USD
	TVLUSD float64 `json:"tvl_usd,omitempty"`

	// Supported chains
	SupportedChains []string `json:"supported_chains,omitempty"`

	// Core contracts
	CoreContracts []CoreContract `json:"core_contracts,omitempty"`

	// Governance token address
	GovernanceToken string `json:"governance_token,omitempty"`

	// Is audited
	Audited bool `json:"audited,omitempty"`

	// Audit reports
	AuditReports []AuditReport `json:"audit_reports,omitempty"`

	// Has bug bounty
	HasBugBounty bool `json:"has_bug_bounty,omitempty"`

	// Bug bounty platform: immunefi, hackerone, etc.
	BugBountyPlatform string `json:"bug_bounty_platform,omitempty"`

	// Max bug bounty payout
	MaxBountyUSD float64 `json:"max_bounty_usd,omitempty"`

	// Timelock duration (for governance)
	TimelockDuration int `json:"timelock_duration,omitempty"`

	// Is paused
	Paused bool `json:"paused,omitempty"`
}

// CoreContract represents a core contract of a DeFi protocol.
type CoreContract struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Role    string `json:"role,omitempty"` // router, factory, vault, etc.
}

// AuditReport represents a security audit report.
type AuditReport struct {
	Auditor       string     `json:"auditor"`
	ReportURL     string     `json:"report_url,omitempty"`
	Date          *time.Time `json:"date,omitempty"`
	Scope         string     `json:"scope,omitempty"`
	CriticalCount int        `json:"critical_count,omitempty"`
	HighCount     int        `json:"high_count,omitempty"`
	MediumCount   int        `json:"medium_count,omitempty"`
	LowCount      int        `json:"low_count,omitempty"`
}

// NFTCollectionDetails contains NFT collection-specific details.
type NFTCollectionDetails struct {
	// Collection name
	Name string `json:"name,omitempty"`

	// Collection symbol
	Symbol string `json:"symbol,omitempty"`

	// Token standard: erc721, erc1155
	Standard string `json:"standard,omitempty"`

	// Total supply
	TotalSupply int64 `json:"total_supply,omitempty"`

	// Max supply
	MaxSupply int64 `json:"max_supply,omitempty"`

	// Unique holders
	HolderCount int64 `json:"holder_count,omitempty"`

	// Floor price (in native token)
	FloorPrice string `json:"floor_price,omitempty"`

	// Floor price USD
	FloorPriceUSD float64 `json:"floor_price_usd,omitempty"`

	// Total volume (in native token)
	TotalVolume string `json:"total_volume,omitempty"`

	// Total volume USD
	TotalVolumeUSD float64 `json:"total_volume_usd,omitempty"`

	// Royalty percentage
	RoyaltyPercent float64 `json:"royalty_percent,omitempty"`

	// Royalty recipient
	RoyaltyRecipient string `json:"royalty_recipient,omitempty"`

	// Marketplace URLs
	Marketplaces []string `json:"marketplaces,omitempty"`

	// Is revealed
	Revealed bool `json:"revealed,omitempty"`

	// Base URI
	BaseURI string `json:"base_uri,omitempty"`

	// Metadata storage: ipfs, arweave, centralized
	MetadataStorage string `json:"metadata_storage,omitempty"`

	// Creator address
	Creator string `json:"creator,omitempty"`
}

// =============================================================================
// Finding Types
// =============================================================================

// Finding represents a security finding.
type Finding struct {
	// Unique identifier for this finding within the report
	ID string `json:"id,omitempty"`

	// Finding type (required): vulnerability, secret, misconfiguration, compliance
	Type FindingType `json:"type"`

	// Short title (required)
	Title string `json:"title"`

	// Detailed description
	Description string `json:"description,omitempty"`

	// Primary message to display (the main human-readable finding message)
	// This is distinct from Title (short) and Description (detailed)
	// If not set, Title will be used as the message
	Message string `json:"message,omitempty"`

	// Severity (required): critical, high, medium, low, info
	Severity Severity `json:"severity"`

	// Confidence score 0-100
	Confidence int `json:"confidence,omitempty"`

	// Impact level: critical, high, medium, low (for risk assessment)
	Impact string `json:"impact,omitempty"`

	// Likelihood level: high, medium, low (for risk assessment)
	Likelihood string `json:"likelihood,omitempty"`

	// Finding category/class
	Category string `json:"category,omitempty"`

	// Vulnerability class(es): SQL Injection, XSS, Command Injection, etc.
	VulnerabilityClass []string `json:"vulnerability_class,omitempty"`

	// Subcategory: audit, vuln, secure default, etc.
	Subcategory []string `json:"subcategory,omitempty"`

	// Rule/check ID that detected this finding
	RuleID string `json:"rule_id,omitempty"`

	// Rule name
	RuleName string `json:"rule_name,omitempty"`

	// Reference to asset ID within this report
	AssetRef string `json:"asset_ref,omitempty"`

	// Direct asset value (if not using AssetRef)
	AssetValue string `json:"asset_value,omitempty"`

	// Asset type (if using AssetValue)
	AssetType AssetType `json:"asset_type,omitempty"`

	// Location information (for code-based findings)
	Location *FindingLocation `json:"location,omitempty"`

	// Vulnerability-specific details
	Vulnerability *VulnerabilityDetails `json:"vulnerability,omitempty"`

	// Secret-specific details
	Secret *SecretDetails `json:"secret,omitempty"`

	// Misconfiguration-specific details
	Misconfiguration *MisconfigurationDetails `json:"misconfiguration,omitempty"`

	// Compliance-specific details
	Compliance *ComplianceDetails `json:"compliance,omitempty"`

	// Web3-specific details (smart contract vulnerabilities)
	Web3 *Web3VulnerabilityDetails `json:"web3,omitempty"`

	// Remediation guidance
	Remediation *Remediation `json:"remediation,omitempty"`

	// References (URLs)
	References []string `json:"references,omitempty"`

	// Tags
	Tags []string `json:"tags,omitempty"`

	// Fingerprint for deduplication
	Fingerprint string `json:"fingerprint,omitempty"`

	// Partial fingerprints - contributing identity components (SARIF partialFingerprints)
	PartialFingerprints map[string]string `json:"partial_fingerprints,omitempty"`

	// Correlation ID - groups logically identical results across runs (SARIF correlationGuid)
	CorrelationID string `json:"correlation_id,omitempty"`

	// Baseline state - status relative to previous scan (SARIF baselineState)
	// Values: new, unchanged, updated, absent
	BaselineState string `json:"baseline_state,omitempty"`

	// Kind - evaluation state of the finding (SARIF kind)
	// Values: not_applicable, pass, fail, review, open, informational
	Kind string `json:"kind,omitempty"`

	// Rank - priority/importance score 0-100 (SARIF rank)
	Rank float64 `json:"rank,omitempty"`

	// Occurrence count - number of times this result was observed (SARIF occurrenceCount)
	OccurrenceCount int `json:"occurrence_count,omitempty"`

	// Related locations - additional locations related to this finding (SARIF relatedLocations)
	RelatedLocations []*FindingLocation `json:"related_locations,omitempty"`

	// Stacks - call stacks relevant to the finding (SARIF stacks)
	Stacks []*StackTrace `json:"stacks,omitempty"`

	// Attachments - relevant artifacts or evidence (SARIF attachments)
	Attachments []*Attachment `json:"attachments,omitempty"`

	// Work item URIs - URIs of associated issues/tickets (SARIF workItemUris)
	WorkItemURIs []string `json:"work_item_uris,omitempty"`

	// Hosted viewer URI - URI to view in hosted viewer (SARIF hostedViewerUri)
	HostedViewerURI string `json:"hosted_viewer_uri,omitempty"`

	// First seen timestamp
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`

	// Last seen timestamp
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`

	// Finding status: open, resolved, false_positive, accepted_risk, in_progress
	Status FindingStatus `json:"status,omitempty"`

	// Data flow trace for taint analysis (source -> intermediate -> sink)
	DataFlow *DataFlow `json:"data_flow,omitempty"`

	// Git author who introduced the finding
	Author string `json:"author,omitempty"`

	// Author email
	AuthorEmail string `json:"author_email,omitempty"`

	// Commit date when the finding was introduced
	CommitDate *time.Time `json:"commit_date,omitempty"`

	// Suppression information (if finding is suppressed)
	Suppression *Suppression `json:"suppression,omitempty"`

	// CTEM: Exposure information
	Exposure *FindingExposure `json:"exposure,omitempty"`

	// CTEM: Remediation context
	RemediationContext *RemediationContext `json:"remediation_context,omitempty"`

	// CTEM: Business impact assessment
	BusinessImpact *BusinessImpact `json:"business_impact,omitempty"`

	// Custom properties
	Properties Properties `json:"properties,omitempty"`
}

// FindingExposure contains CTEM exposure information for a finding.
type FindingExposure struct {
	// Exposure vector: network, local, physical, adjacent_net
	Vector string `json:"vector,omitempty"`

	// Is the finding reachable from the network
	IsNetworkAccessible bool `json:"is_network_accessible,omitempty"`

	// Is the finding directly reachable from the internet
	IsInternetAccessible bool `json:"is_internet_accessible,omitempty"`

	// Prerequisites for exploitation: auth_required, mfa_required, local_access, etc.
	AttackPrerequisites string `json:"attack_prerequisites,omitempty"`
}

// RemediationContext contains CTEM remediation context for a finding.
type RemediationContext struct {
	// Remediation type: patch, upgrade, workaround, config_change, mitigate, accept_risk
	Type string `json:"type,omitempty"`

	// Estimated time to fix in minutes
	EstimatedMinutes int `json:"estimated_minutes,omitempty"`

	// Fix complexity: simple, moderate, complex
	Complexity string `json:"complexity,omitempty"`

	// Is a remedy (patch/fix) available
	RemedyAvailable bool `json:"remedy_available,omitempty"`
}

// BusinessImpact contains CTEM business impact assessment for a finding.
type BusinessImpact struct {
	// Data exposure risk: none, low, medium, high, critical
	DataExposureRisk string `json:"data_exposure_risk,omitempty"`

	// Has potential reputational impact
	ReputationalImpact bool `json:"reputational_impact,omitempty"`

	// Compliance frameworks impacted: PCI-DSS, HIPAA, SOC2, GDPR, ISO27001
	ComplianceImpact []string `json:"compliance_impact,omitempty"`
}

// FindingStatus represents the status of a finding.
type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusResolved      FindingStatus = "resolved"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusAcceptedRisk  FindingStatus = "accepted_risk"
	FindingStatusInProgress    FindingStatus = "in_progress"
)

// DataFlow represents taint analysis data flow trace.
// This structure captures the complete path from source to sink,
// including all intermediate steps and transformations.
type DataFlow struct {
	// Taint source locations (where untrusted data enters)
	Sources []DataFlowLocation `json:"sources,omitempty"`

	// Intermediate variable locations (propagation path)
	Intermediates []DataFlowLocation `json:"intermediates,omitempty"`

	// Taint sink location (where data reaches dangerous function)
	Sinks []DataFlowLocation `json:"sinks,omitempty"`

	// Sanitizers applied (functions that clean/escape data)
	Sanitizers []DataFlowLocation `json:"sanitizers,omitempty"`

	// Whether the data is still tainted at the sink
	// (false if properly sanitized before reaching sink)
	Tainted bool `json:"tainted"`

	// Type of taint: user_input, file_read, env_var, network, database
	TaintType string `json:"taint_type,omitempty"`

	// Vulnerability type this flow leads to: sqli, xss, ssrf, command_injection, etc.
	VulnerabilityType string `json:"vulnerability_type,omitempty"`

	// Flow confidence score (0-100)
	Confidence int `json:"confidence,omitempty"`

	// Is interprocedural (crosses function boundaries)
	Interprocedural bool `json:"interprocedural,omitempty"`

	// Is cross-file (data flows across multiple files)
	CrossFile bool `json:"cross_file,omitempty"`

	// Call graph path (function names in order)
	CallPath []string `json:"call_path,omitempty"`

	// Summary of the flow for human readability
	Summary string `json:"summary,omitempty"`
}

// DataFlowLocation represents a location in a data flow trace.
type DataFlowLocation struct {
	// File path
	Path string `json:"path,omitempty"`

	// Line number (1-indexed)
	Line int `json:"line,omitempty"`

	// End line (for multi-line spans)
	EndLine int `json:"end_line,omitempty"`

	// Column number (1-indexed)
	Column int `json:"column,omitempty"`

	// End column
	EndColumn int `json:"end_column,omitempty"`

	// Code content at this location
	Content string `json:"content,omitempty"`

	// Variable or expression name
	Label string `json:"label,omitempty"`

	// Step index in the flow (for ordering, 0-indexed)
	Index int `json:"index,omitempty"`

	// Location type: source, sink, propagator, sanitizer, transform
	Type DataFlowLocationType `json:"type,omitempty"`

	// Function/method name containing this location
	Function string `json:"function,omitempty"`

	// Class/struct name (if applicable)
	Class string `json:"class,omitempty"`

	// Module/namespace
	Module string `json:"module,omitempty"`

	// The operation performed: assignment, call, return, parameter, concat, etc.
	Operation string `json:"operation,omitempty"`

	// For function calls: the function being called
	CalledFunction string `json:"called_function,omitempty"`

	// For parameters: the parameter index (0-indexed)
	ParameterIndex int `json:"parameter_index,omitempty"`

	// Taint state at this location: tainted, sanitized, unknown
	TaintState string `json:"taint_state,omitempty"`

	// Transformation applied: encode, decode, escape, hash, encrypt, etc.
	Transformation string `json:"transformation,omitempty"`

	// Notes for human understanding
	Notes string `json:"notes,omitempty"`
}

// DataFlowLocationType represents the type of a location in dataflow.
type DataFlowLocationType string

const (
	// DataFlowLocationSource is where untrusted data enters the system
	DataFlowLocationSource DataFlowLocationType = "source"

	// DataFlowLocationSink is where data reaches a dangerous function
	DataFlowLocationSink DataFlowLocationType = "sink"

	// DataFlowLocationPropagator is where data is passed/assigned
	DataFlowLocationPropagator DataFlowLocationType = "propagator"

	// DataFlowLocationSanitizer is where data is cleaned/escaped
	DataFlowLocationSanitizer DataFlowLocationType = "sanitizer"

	// DataFlowLocationTransform is where data is transformed (not sanitized)
	DataFlowLocationTransform DataFlowLocationType = "transform"
)

// StackTrace represents a call stack trace (SARIF stack).
type StackTrace struct {
	// Stack description/message
	Message string `json:"message,omitempty"`

	// Stack frames from innermost to outermost
	Frames []*StackFrame `json:"frames,omitempty"`
}

// StackFrame represents a single frame in a call stack.
type StackFrame struct {
	// Location of this frame
	Location *FindingLocation `json:"location,omitempty"`

	// Module/library name
	Module string `json:"module,omitempty"`

	// Thread ID
	ThreadID int `json:"thread_id,omitempty"`

	// Function parameters
	Parameters []string `json:"parameters,omitempty"`
}

// Attachment represents an artifact or evidence attachment (SARIF attachment).
type Attachment struct {
	// Description of the attachment
	Description string `json:"description,omitempty"`

	// Artifact location
	ArtifactLocation *ArtifactLocation `json:"artifact_location,omitempty"`

	// Relevant regions within the artifact
	Regions []*FindingLocation `json:"regions,omitempty"`
}

// ArtifactLocation represents the location of an artifact.
type ArtifactLocation struct {
	// URI of the artifact
	URI string `json:"uri,omitempty"`

	// Base URI ID for resolution
	URIBaseID string `json:"uri_base_id,omitempty"`

	// Index within the artifacts array
	Index int `json:"index,omitempty"`
}

// Suppression contains information about finding suppression.
type Suppression struct {
	// Suppression kind: in_source, external
	Kind string `json:"kind,omitempty"`

	// Suppression status: accepted, under_review, rejected
	Status string `json:"status,omitempty"`

	// Justification for suppression
	Justification string `json:"justification,omitempty"`

	// Who suppressed the finding
	SuppressedBy string `json:"suppressed_by,omitempty"`

	// When the finding was suppressed
	SuppressedAt *time.Time `json:"suppressed_at,omitempty"`
}

// FindingLocation contains location information for code-based findings.
type FindingLocation struct {
	// File path
	Path string `json:"path,omitempty"`

	// Start line number (1-indexed)
	StartLine int `json:"start_line,omitempty"`

	// End line number
	EndLine int `json:"end_line,omitempty"`

	// Start column
	StartColumn int `json:"start_column,omitempty"`

	// End column
	EndColumn int `json:"end_column,omitempty"`

	// Code snippet
	Snippet string `json:"snippet,omitempty"`

	// Branch name (for repository findings)
	Branch string `json:"branch,omitempty"`

	// Commit SHA
	CommitSHA string `json:"commit_sha,omitempty"`

	// Logical location (function, class, method name)
	LogicalLocation *LogicalLocation `json:"logical_location,omitempty"`

	// Context region (surrounding code for better understanding)
	ContextSnippet string `json:"context_snippet,omitempty"`

	// Context start line (for context_snippet)
	ContextStartLine int `json:"context_start_line,omitempty"`
}

// LogicalLocation represents a logical code location (function, class, method).
type LogicalLocation struct {
	// Fully qualified name (e.g., "pkg.MyClass.myMethod")
	FullyQualifiedName string `json:"fully_qualified_name,omitempty"`

	// Function/method name
	Name string `json:"name,omitempty"`

	// Kind: function, method, class, module, namespace
	Kind string `json:"kind,omitempty"`

	// Parent logical location index (for nested locations)
	ParentIndex int `json:"parent_index,omitempty"`
}

// VulnerabilityDetails contains vulnerability-specific details.
type VulnerabilityDetails struct {
	// CVE ID
	CVEID string `json:"cve_id,omitempty"`

	// CWE IDs (can have multiple)
	CWEIDs []string `json:"cwe_ids,omitempty"`

	// CWE ID (single, for backward compatibility)
	CWEID string `json:"cwe_id,omitempty"`

	// OWASP IDs (e.g., "A01:2021", "A03:2021")
	OWASPIDs []string `json:"owasp_ids,omitempty"`

	// ASVS (Application Security Verification Standard) compliance info
	ASVS *ASVSInfo `json:"asvs,omitempty"`

	// CVSS version (2.0, 3.0, 3.1, 4.0)
	CVSSVersion string `json:"cvss_version,omitempty"`

	// CVSS score
	CVSSScore float64 `json:"cvss_score,omitempty"`

	// CVSS vector
	CVSSVector string `json:"cvss_vector,omitempty"`

	// CVSS data source: nvd, ghsa, redhat, bitnami
	CVSSSource string `json:"cvss_source,omitempty"`

	// Affected package
	Package string `json:"package,omitempty"`

	// Package URL (PURL spec) e.g., pkg:npm/lodash@4.17.20
	PURL string `json:"purl,omitempty"`

	// Affected version
	AffectedVersion string `json:"affected_version,omitempty"`

	// Affected version range (semver format)
	AffectedVersionRange string `json:"affected_version_range,omitempty"`

	// Fixed version
	FixedVersion string `json:"fixed_version,omitempty"`

	// All available fixed versions
	FixedVersions []string `json:"fixed_versions,omitempty"`

	// Ecosystem: npm, pip, maven, cargo, go, nuget, etc.
	Ecosystem string `json:"ecosystem,omitempty"`

	// Vulnerability published date
	PublishedAt *time.Time `json:"published_at,omitempty"`

	// Last modified date
	ModifiedAt *time.Time `json:"modified_at,omitempty"`

	// Exploit available
	ExploitAvailable bool `json:"exploit_available,omitempty"`

	// Exploit maturity: none, poc, functional, weaponized
	ExploitMaturity string `json:"exploit_maturity,omitempty"`

	// In CISA KEV (Known Exploited Vulnerabilities)
	InCISAKEV bool `json:"in_cisa_kev,omitempty"`

	// EPSS score (Exploit Prediction Scoring System)
	EPSSScore float64 `json:"epss_score,omitempty"`

	// EPSS percentile
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`

	// Affected CPE
	CPE string `json:"cpe,omitempty"`

	// Advisory URLs
	Advisories []string `json:"advisories,omitempty"`

	// Is direct dependency (vs transitive)
	IsDirect bool `json:"is_direct,omitempty"`

	// Dependency path for transitive vulnerabilities
	DependencyPath []string `json:"dependency_path,omitempty"`

	// Data source information (vulnerability database)
	DataSource *VulnDataSource `json:"data_source,omitempty"`

	// Severity source (who assigned the severity: nvd, ghsa, redhat, etc.)
	SeveritySource string `json:"severity_source,omitempty"`

	// Vendor-specific severity mapping (vendor -> severity level 1-5)
	VendorSeverity map[string]int `json:"vendor_severity,omitempty"`

	// Container layer information (for image scans)
	Layer *ContainerLayer `json:"layer,omitempty"`

	// Aqua Vulnerability Database ID (e.g., AVD-AWS-0001)
	AVDID string `json:"avd_id,omitempty"`

	// Vulnerability status: affected, fixed, under_investigation, will_not_fix
	VulnStatus string `json:"vuln_status,omitempty"`
}

// VulnDataSource contains information about the vulnerability data source.
type VulnDataSource struct {
	// Data source ID (e.g., "nvd", "ghsa", "osv")
	ID string `json:"id,omitempty"`

	// Data source name
	Name string `json:"name,omitempty"`

	// Data source URL
	URL string `json:"url,omitempty"`
}

// ASVSInfo contains OWASP ASVS (Application Security Verification Standard) compliance info.
// ASVS provides a basis for testing application security controls.
type ASVSInfo struct {
	// ASVS section (e.g., "V2: Authentication")
	Section string `json:"section,omitempty"`

	// Control ID (e.g., "2.1.1")
	ControlID string `json:"control_id,omitempty"`

	// Control URL (link to ASVS documentation)
	ControlURL string `json:"control_url,omitempty"`

	// ASVS level (1, 2, or 3)
	Level int `json:"level,omitempty"`
}

// ContainerLayer contains information about the container layer where a vulnerability was found.
type ContainerLayer struct {
	// Layer digest (e.g., "sha256:abc123...")
	Digest string `json:"digest,omitempty"`

	// Layer diff ID
	DiffID string `json:"diff_id,omitempty"`
}

// SecretDetails contains secret-specific details.
type SecretDetails struct {
	// Secret type: api_key, password, token, certificate, private_key, etc.
	SecretType string `json:"secret_type,omitempty"`

	// Service associated with the secret: aws, github, stripe, gcp, azure, etc.
	Service string `json:"service,omitempty"`

	// Masked value (first and last few chars)
	MaskedValue string `json:"masked_value,omitempty"`

	// Length of the secret
	Length int `json:"length,omitempty"`

	// Entropy score
	Entropy float64 `json:"entropy,omitempty"`

	// Is valid (if verification was performed)
	Valid *bool `json:"valid,omitempty"`

	// Verification timestamp
	VerifiedAt *time.Time `json:"verified_at,omitempty"`

	// Is revoked
	Revoked bool `json:"revoked,omitempty"`

	// When the secret was revoked
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// Secret scope/permissions (e.g., "read:org", "repo", "admin")
	Scopes []string `json:"scopes,omitempty"`

	// Expiration date (if known)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Secret age (how long since creation, if known)
	AgeInDays int `json:"age_in_days,omitempty"`

	// Rotation recommended by date
	RotationDueAt *time.Time `json:"rotation_due_at,omitempty"`

	// Is the secret in git history only (not in current HEAD)
	InHistoryOnly bool `json:"in_history_only,omitempty"`

	// Commit count where this secret appears
	CommitCount int `json:"commit_count,omitempty"`
}

// MisconfigurationDetails contains misconfiguration-specific details.
type MisconfigurationDetails struct {
	// Policy/check ID
	PolicyID string `json:"policy_id,omitempty"`

	// Policy name
	PolicyName string `json:"policy_name,omitempty"`

	// Aqua Vulnerability Database ID (e.g., AVD-AWS-0001)
	AVDID string `json:"avd_id,omitempty"`

	// Resource type
	ResourceType string `json:"resource_type,omitempty"`

	// Resource name
	ResourceName string `json:"resource_name,omitempty"`

	// Cloud provider (e.g., AWS, GCP, Azure)
	Provider string `json:"provider,omitempty"`

	// Service (e.g., S3, EC2, IAM)
	Service string `json:"service,omitempty"`

	// Namespace (e.g., builtin.aws.s3)
	Namespace string `json:"namespace,omitempty"`

	// Rego query path
	Query string `json:"query,omitempty"`

	// Expected value
	Expected string `json:"expected,omitempty"`

	// Actual value
	Actual string `json:"actual,omitempty"`

	// Cause description
	Cause string `json:"cause,omitempty"`
}

// ComplianceDetails contains compliance-specific details.
type ComplianceDetails struct {
	// Framework: pci-dss, hipaa, soc2, cis, etc.
	Framework string `json:"framework,omitempty"`

	// Framework version
	FrameworkVersion string `json:"framework_version,omitempty"`

	// Control ID
	ControlID string `json:"control_id,omitempty"`

	// Control name
	ControlName string `json:"control_name,omitempty"`

	// Control description
	ControlDescription string `json:"control_description,omitempty"`

	// Result: pass, fail, manual, not_applicable
	Result string `json:"result,omitempty"`
}

// =============================================================================
// Web3 Vulnerability Details
// =============================================================================

// Web3VulnerabilityDetails contains Web3/smart contract vulnerability-specific details.
type Web3VulnerabilityDetails struct {
	// Vulnerability class/category (SWC ID or custom)
	// Common: reentrancy, overflow, access_control, front_running, etc.
	VulnerabilityClass string `json:"vulnerability_class,omitempty"`

	// SWC Registry ID (e.g., SWC-107 for reentrancy)
	SWCID string `json:"swc_id,omitempty"`

	// Contract address affected
	ContractAddress string `json:"contract_address,omitempty"`

	// Chain ID
	ChainID int64 `json:"chain_id,omitempty"`

	// Chain name
	Chain string `json:"chain,omitempty"`

	// Affected function signature
	FunctionSignature string `json:"function_signature,omitempty"`

	// Affected function selector (4 bytes)
	FunctionSelector string `json:"function_selector,omitempty"`

	// Vulnerable code pattern
	VulnerablePattern string `json:"vulnerable_pattern,omitempty"`

	// Bytecode offset (if found in bytecode analysis)
	BytecodeOffset int `json:"bytecode_offset,omitempty"`

	// Is exploitable on mainnet
	ExploitableOnMainnet bool `json:"exploitable_on_mainnet,omitempty"`

	// Estimated impact in USD (if quantifiable)
	EstimatedImpactUSD float64 `json:"estimated_impact_usd,omitempty"`

	// Affected assets value in USD
	AffectedValueUSD float64 `json:"affected_value_usd,omitempty"`

	// Attack vector description
	AttackVector string `json:"attack_vector,omitempty"`

	// Proof of concept (if available)
	POC *Web3POC `json:"poc,omitempty"`

	// Related transaction hashes (if exploit occurred)
	RelatedTxHashes []string `json:"related_tx_hashes,omitempty"`

	// Attacker addresses (if known)
	AttackerAddresses []string `json:"attacker_addresses,omitempty"`

	// Tool that found this: slither, mythril, securify, manticore, etc.
	DetectionTool string `json:"detection_tool,omitempty"`

	// Detection confidence: high, medium, low
	DetectionConfidence string `json:"detection_confidence,omitempty"`

	// Is false positive
	IsFalsePositive bool `json:"is_false_positive,omitempty"`

	// Gas optimization issues (for gas-related findings)
	GasIssue *GasIssue `json:"gas_issue,omitempty"`

	// Access control details
	AccessControl *AccessControlIssue `json:"access_control,omitempty"`

	// Reentrancy details
	Reentrancy *ReentrancyIssue `json:"reentrancy,omitempty"`

	// Oracle manipulation details
	OracleManipulation *OracleManipulationIssue `json:"oracle_manipulation,omitempty"`

	// Flash loan attack details
	FlashLoan *FlashLoanIssue `json:"flash_loan,omitempty"`
}

// Web3POC contains proof of concept details for Web3 vulnerabilities.
type Web3POC struct {
	// POC type: transaction, script, foundry_test, hardhat_test
	Type string `json:"type,omitempty"`

	// POC code or script
	Code string `json:"code,omitempty"`

	// POC transaction data
	TxData string `json:"tx_data,omitempty"`

	// Expected outcome
	ExpectedOutcome string `json:"expected_outcome,omitempty"`

	// Tested on: mainnet_fork, testnet, local
	TestedOn string `json:"tested_on,omitempty"`

	// Fork block number (for mainnet fork tests)
	ForkBlockNumber int64 `json:"fork_block_number,omitempty"`
}

// GasIssue contains details about gas optimization issues.
type GasIssue struct {
	// Current gas cost
	CurrentGas int64 `json:"current_gas,omitempty"`

	// Optimized gas cost
	OptimizedGas int64 `json:"optimized_gas,omitempty"`

	// Gas savings percentage
	SavingsPercent float64 `json:"savings_percent,omitempty"`

	// Optimization suggestion
	Suggestion string `json:"suggestion,omitempty"`
}

// AccessControlIssue contains details about access control vulnerabilities.
type AccessControlIssue struct {
	// Missing modifier
	MissingModifier string `json:"missing_modifier,omitempty"`

	// Unprotected function
	UnprotectedFunction string `json:"unprotected_function,omitempty"`

	// Can be called by
	CallableBy string `json:"callable_by,omitempty"` // anyone, owner_only, etc.

	// Privilege escalation path
	EscalationPath string `json:"escalation_path,omitempty"`

	// Missing role check
	MissingRoleCheck string `json:"missing_role_check,omitempty"`
}

// ReentrancyIssue contains details about reentrancy vulnerabilities.
type ReentrancyIssue struct {
	// Reentrancy type: cross_function, cross_contract, read_only
	Type string `json:"type,omitempty"`

	// Vulnerable external call
	ExternalCall string `json:"external_call,omitempty"`

	// State variable modified after call
	StateModifiedAfterCall string `json:"state_modified_after_call,omitempty"`

	// Entry point function
	EntryPoint string `json:"entry_point,omitempty"`

	// Callback function
	Callback string `json:"callback,omitempty"`

	// Max reentrancy depth possible
	MaxDepth int `json:"max_depth,omitempty"`
}

// OracleManipulationIssue contains details about oracle manipulation vulnerabilities.
type OracleManipulationIssue struct {
	// Oracle type: chainlink, uniswap_twap, custom
	OracleType string `json:"oracle_type,omitempty"`

	// Oracle address
	OracleAddress string `json:"oracle_address,omitempty"`

	// Manipulation method: flash_loan, sandwich, time_manipulation
	ManipulationMethod string `json:"manipulation_method,omitempty"`

	// Price impact possible
	PriceImpactPercent float64 `json:"price_impact_percent,omitempty"`

	// Missing checks
	MissingChecks []string `json:"missing_checks,omitempty"`
}

// FlashLoanIssue contains details about flash loan attack vulnerabilities.
type FlashLoanIssue struct {
	// Flash loan provider: aave, dydx, uniswap, balancer
	Provider string `json:"provider,omitempty"`

	// Attack type: price_manipulation, governance_attack, collateral_theft
	AttackType string `json:"attack_type,omitempty"`

	// Required capital for attack
	RequiredCapitalUSD float64 `json:"required_capital_usd,omitempty"`

	// Potential profit
	PotentialProfitUSD float64 `json:"potential_profit_usd,omitempty"`

	// Attack steps
	AttackSteps []string `json:"attack_steps,omitempty"`
}

// Web3VulnerabilityClass represents common Web3 vulnerability classes.
type Web3VulnerabilityClass string

const (
	// SWC-100 series - Basic
	Web3VulnReentrancy          Web3VulnerabilityClass = "reentrancy"           // SWC-107
	Web3VulnIntegerOverflow     Web3VulnerabilityClass = "integer_overflow"     // SWC-101
	Web3VulnIntegerUnderflow    Web3VulnerabilityClass = "integer_underflow"    // SWC-101
	Web3VulnAccessControl       Web3VulnerabilityClass = "access_control"       // SWC-105
	Web3VulnUncheckedCall       Web3VulnerabilityClass = "unchecked_call"       // SWC-104
	Web3VulnDelegateCall        Web3VulnerabilityClass = "delegate_call"        // SWC-112
	Web3VulnSelfDestruct        Web3VulnerabilityClass = "self_destruct"        // SWC-106
	Web3VulnTxOrigin            Web3VulnerabilityClass = "tx_origin"            // SWC-115
	Web3VulnTimestampDependence Web3VulnerabilityClass = "timestamp_dependence" // SWC-116
	Web3VulnBlockHashDependence Web3VulnerabilityClass = "blockhash_dependence" // SWC-120

	// DeFi-specific
	Web3VulnFlashLoan          Web3VulnerabilityClass = "flash_loan_attack"
	Web3VulnOracleManipulation Web3VulnerabilityClass = "oracle_manipulation"
	Web3VulnFrontRunning       Web3VulnerabilityClass = "front_running"
	Web3VulnSandwichAttack     Web3VulnerabilityClass = "sandwich_attack"
	Web3VulnSlippage           Web3VulnerabilityClass = "slippage_attack"
	Web3VulnPriceManipulation  Web3VulnerabilityClass = "price_manipulation"
	Web3VulnGovernanceAttack   Web3VulnerabilityClass = "governance_attack"
	Web3VulnLiquidityDrain     Web3VulnerabilityClass = "liquidity_drain"
	Web3VulnMEV                Web3VulnerabilityClass = "mev_vulnerability"

	// Token-specific
	Web3VulnHoneypot          Web3VulnerabilityClass = "honeypot"
	Web3VulnHiddenMint        Web3VulnerabilityClass = "hidden_mint"
	Web3VulnHiddenFee         Web3VulnerabilityClass = "hidden_fee"
	Web3VulnBlacklistAbuse    Web3VulnerabilityClass = "blacklist_abuse"
	Web3VulnRenounceOwnership Web3VulnerabilityClass = "fake_renounce"

	// Proxy & Upgrade
	Web3VulnStorageCollision   Web3VulnerabilityClass = "storage_collision"
	Web3VulnUninitializedProxy Web3VulnerabilityClass = "uninitialized_proxy"
	Web3VulnUpgradeVuln        Web3VulnerabilityClass = "upgrade_vulnerability"

	// Cryptographic
	Web3VulnWeakRandomness        Web3VulnerabilityClass = "weak_randomness" // SWC-120
	Web3VulnSignatureMalleability Web3VulnerabilityClass = "signature_malleability"
	Web3VulnReplayAttack          Web3VulnerabilityClass = "replay_attack"

	// Gas & DoS
	Web3VulnDosGasLimit      Web3VulnerabilityClass = "dos_gas_limit"
	Web3VulnUnboundedLoop    Web3VulnerabilityClass = "unbounded_loop"
	Web3VulnDosBlockStuffing Web3VulnerabilityClass = "dos_block_stuffing"

	// Logic
	Web3VulnBusinessLogic      Web3VulnerabilityClass = "business_logic"
	Web3VulnInvariantViolation Web3VulnerabilityClass = "invariant_violation"
)

// AllWeb3VulnerabilityClasses returns all Web3 vulnerability classes.
func AllWeb3VulnerabilityClasses() []Web3VulnerabilityClass {
	return []Web3VulnerabilityClass{
		Web3VulnReentrancy,
		Web3VulnIntegerOverflow,
		Web3VulnIntegerUnderflow,
		Web3VulnAccessControl,
		Web3VulnUncheckedCall,
		Web3VulnDelegateCall,
		Web3VulnSelfDestruct,
		Web3VulnTxOrigin,
		Web3VulnTimestampDependence,
		Web3VulnBlockHashDependence,
		Web3VulnFlashLoan,
		Web3VulnOracleManipulation,
		Web3VulnFrontRunning,
		Web3VulnSandwichAttack,
		Web3VulnSlippage,
		Web3VulnPriceManipulation,
		Web3VulnGovernanceAttack,
		Web3VulnLiquidityDrain,
		Web3VulnMEV,
		Web3VulnHoneypot,
		Web3VulnHiddenMint,
		Web3VulnHiddenFee,
		Web3VulnBlacklistAbuse,
		Web3VulnRenounceOwnership,
		Web3VulnStorageCollision,
		Web3VulnUninitializedProxy,
		Web3VulnUpgradeVuln,
		Web3VulnWeakRandomness,
		Web3VulnSignatureMalleability,
		Web3VulnReplayAttack,
		Web3VulnDosGasLimit,
		Web3VulnUnboundedLoop,
		Web3VulnDosBlockStuffing,
		Web3VulnBusinessLogic,
		Web3VulnInvariantViolation,
	}
}

// Remediation provides remediation guidance for a finding.
type Remediation struct {
	// Short recommendation
	Recommendation string `json:"recommendation,omitempty"`

	// Detailed fix steps
	Steps []string `json:"steps,omitempty"`

	// Effort estimate: trivial, low, medium, high
	Effort string `json:"effort,omitempty"`

	// Fix available
	FixAvailable bool `json:"fix_available,omitempty"`

	// Auto-fixable
	AutoFixable bool `json:"auto_fixable,omitempty"`

	// Suggested fix code - the actual code to replace the vulnerable code
	// For SAST tools like Semgrep that provide auto-fix suggestions
	FixCode string `json:"fix_code,omitempty"`

	// Regex-based fix pattern (for tools that provide regex replacements)
	FixRegex *FixRegex `json:"fix_regex,omitempty"`

	// Reference URLs
	References []string `json:"references,omitempty"`
}

// FixRegex contains regex-based auto-fix information.
// Used by tools like Semgrep that can provide regex replacement patterns.
type FixRegex struct {
	// Regular expression pattern to match
	Regex string `json:"regex,omitempty"`

	// Replacement string (may contain capture group references like $1, $2)
	Replacement string `json:"replacement,omitempty"`

	// Number of replacements to make (0 = all)
	Count int `json:"count,omitempty"`
}

// =============================================================================
// Enums and Value Objects
// =============================================================================

// AssetType represents the type of an asset.
type AssetType string

const (
	// ==========================================================================
	// Discovery / External Attack Surface
	// ==========================================================================
	AssetTypeDomain      AssetType = "domain"
	AssetTypeSubdomain   AssetType = "subdomain"
	AssetTypeIPAddress   AssetType = "ip_address"
	AssetTypeCertificate AssetType = "certificate"

	// ==========================================================================
	// Applications
	// ==========================================================================
	AssetTypeWebsite        AssetType = "website"         // Public-facing website
	AssetTypeWebApplication AssetType = "web_application" // Web application (SaaS, internal apps)
	AssetTypeAPI            AssetType = "api"             // API endpoint (REST, GraphQL, gRPC)
	AssetTypeMobileApp      AssetType = "mobile_app"      // Mobile application (iOS, Android)
	AssetTypeService        AssetType = "service"         // Network service (SSH, SMTP, FTP, DNS, etc.)

	// ==========================================================================
	// Code / Repository
	// ==========================================================================
	AssetTypeRepository AssetType = "repository"

	// ==========================================================================
	// Cloud
	// ==========================================================================
	AssetTypeCloudAccount      AssetType = "cloud_account"      // AWS Account, GCP Project, Azure Subscription
	AssetTypeCompute           AssetType = "compute"            // EC2, GCE, Azure VM
	AssetTypeStorage           AssetType = "storage"            // S3, GCS, Azure Blob
	AssetTypeDatabase          AssetType = "database"           // RDS, Cloud SQL, Cosmos DB
	AssetTypeServerless        AssetType = "serverless"         // Lambda, Cloud Functions, Azure Functions
	AssetTypeContainerRegistry AssetType = "container_registry" // ECR, GCR, ACR

	// ==========================================================================
	// Infrastructure
	// ==========================================================================
	AssetTypeHost                AssetType = "host"                 // Physical or virtual host
	AssetTypeServer              AssetType = "server"               // Server machine
	AssetTypeContainer           AssetType = "container"            // Docker container
	AssetTypeKubernetes          AssetType = "kubernetes"           // Kubernetes cluster (generic)
	AssetTypeKubernetesCluster   AssetType = "kubernetes_cluster"   // Kubernetes cluster
	AssetTypeKubernetesNamespace AssetType = "kubernetes_namespace" // Kubernetes namespace

	// ==========================================================================
	// Network
	// ==========================================================================
	AssetTypeNetwork      AssetType = "network"       // Network segment
	AssetTypeVPC          AssetType = "vpc"           // Virtual Private Cloud
	AssetTypeSubnet       AssetType = "subnet"        // Network subnet
	AssetTypeLoadBalancer AssetType = "load_balancer" // Load balancer (ALB, NLB, etc.)
	AssetTypeFirewall     AssetType = "firewall"      // Firewall / Security Group

	// ==========================================================================
	// Identity / IAM
	// ==========================================================================
	AssetTypeIAMUser        AssetType = "iam_user"        // IAM user
	AssetTypeIAMRole        AssetType = "iam_role"        // IAM role
	AssetTypeServiceAccount AssetType = "service_account" // Service account

	// ==========================================================================
	// Recon-discovered Asset Types
	// ==========================================================================
	AssetTypeHTTPService   AssetType = "http_service"   // HTTP/HTTPS services from HTTPX
	AssetTypeOpenPort      AssetType = "open_port"      // Individual open ports from Naabu
	AssetTypeDiscoveredURL AssetType = "discovered_url" // URLs/endpoints from Katana

	// ==========================================================================
	// Web3 Asset Types
	// ==========================================================================
	AssetTypeSmartContract AssetType = "smart_contract"
	AssetTypeWallet        AssetType = "wallet"
	AssetTypeNFTCollection AssetType = "nft_collection"
	AssetTypeDeFiProtocol  AssetType = "defi_protocol"
	AssetTypeToken         AssetType = "token"
	AssetTypeBlockchain    AssetType = "blockchain"

	// ==========================================================================
	// Unclassified Assets
	// ==========================================================================
	AssetTypeUnclassified AssetType = "unclassified" // Assets that have not been classified yet
)

// AllAssetTypes returns all valid asset types.
func AllAssetTypes() []AssetType {
	return []AssetType{
		// Discovery / External Attack Surface
		AssetTypeDomain,
		AssetTypeSubdomain,
		AssetTypeIPAddress,
		AssetTypeCertificate,
		// Applications
		AssetTypeWebsite,
		AssetTypeWebApplication,
		AssetTypeAPI,
		AssetTypeMobileApp,
		AssetTypeService,
		// Code / Repository
		AssetTypeRepository,
		// Cloud
		AssetTypeCloudAccount,
		AssetTypeCompute,
		AssetTypeStorage,
		AssetTypeDatabase,
		AssetTypeServerless,
		AssetTypeContainerRegistry,
		// Infrastructure
		AssetTypeHost,
		AssetTypeServer,
		AssetTypeContainer,
		AssetTypeKubernetes,
		AssetTypeKubernetesCluster,
		AssetTypeKubernetesNamespace,
		// Network
		AssetTypeNetwork,
		AssetTypeVPC,
		AssetTypeSubnet,
		AssetTypeLoadBalancer,
		AssetTypeFirewall,
		// Identity / IAM
		AssetTypeIAMUser,
		AssetTypeIAMRole,
		AssetTypeServiceAccount,
		// Recon-discovered
		AssetTypeHTTPService,
		AssetTypeOpenPort,
		AssetTypeDiscoveredURL,
		// Web3
		AssetTypeSmartContract,
		AssetTypeWallet,
		AssetTypeNFTCollection,
		AssetTypeDeFiProtocol,
		AssetTypeToken,
		AssetTypeBlockchain,
		// Unclassified
		AssetTypeUnclassified,
	}
}

// IsValid checks if the asset type is valid.
func (t AssetType) IsValid() bool {
	return slices.Contains(AllAssetTypes(), t)
}

// String returns the string representation.
func (t AssetType) String() string {
	return string(t)
}

// FindingType represents the type of a finding.
type FindingType string

const (
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeSecret           FindingType = "secret"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeCompliance       FindingType = "compliance"
	FindingTypeWeb3             FindingType = "web3" // Smart contract vulnerabilities
)

// AllFindingTypes returns all valid finding types.
func AllFindingTypes() []FindingType {
	return []FindingType{
		FindingTypeVulnerability,
		FindingTypeSecret,
		FindingTypeMisconfiguration,
		FindingTypeCompliance,
		FindingTypeWeb3,
	}
}

// IsValid checks if the finding type is valid.
func (t FindingType) IsValid() bool {
	return slices.Contains(AllFindingTypes(), t)
}

// String returns the string representation.
func (t FindingType) String() string {
	return string(t)
}

// Severity represents the severity level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AllSeverities returns all valid severities.
func AllSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}

// IsValid checks if the severity is valid.
func (s Severity) IsValid() bool {
	return slices.Contains(AllSeverities(), s)
}

// String returns the string representation.
func (s Severity) String() string {
	return string(s)
}

// Score returns a numeric score for the severity (0-10).
func (s Severity) Score() float64 {
	switch s {
	case SeverityCritical:
		return 10.0
	case SeverityHigh:
		return 7.5
	case SeverityMedium:
		return 5.0
	case SeverityLow:
		return 2.5
	case SeverityInfo:
		return 0.0
	default:
		return 5.0
	}
}

// Criticality represents asset criticality level.
type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
	CriticalityInfo     Criticality = "info"
)

// AllCriticalities returns all valid criticalities.
func AllCriticalities() []Criticality {
	return []Criticality{
		CriticalityCritical,
		CriticalityHigh,
		CriticalityMedium,
		CriticalityLow,
		CriticalityInfo,
	}
}

// IsValid checks if the criticality is valid.
func (c Criticality) IsValid() bool {
	// Empty is also valid (defaults to medium)
	if c == "" {
		return true
	}
	return slices.Contains(AllCriticalities(), c)
}

// String returns the string representation.
func (c Criticality) String() string {
	return string(c)
}

// Properties is a property bag for custom properties.
type Properties map[string]any

// =============================================================================
// Factory Functions
// =============================================================================

// NewReport creates a new empty CTIS report.
func NewReport() *Report {
	return &Report{
		Version: "1.0",
		Metadata: ReportMetadata{
			Timestamp:  time.Now(),
			SourceType: "scanner",
		},
		Assets:   make([]Asset, 0),
		Findings: make([]Finding, 0),
	}
}

// =============================================================================
// DataFlow Helper Functions
// =============================================================================

// NewDataFlow creates a new DataFlow with the given source and sink.
func NewDataFlow(source, sink DataFlowLocation) *DataFlow {
	source.Type = DataFlowLocationSource
	source.Index = 0
	sink.Type = DataFlowLocationSink
	sink.Index = 1

	return &DataFlow{
		Sources: []DataFlowLocation{source},
		Sinks:   []DataFlowLocation{sink},
		Tainted: true,
	}
}

// AddIntermediate adds an intermediate step to the dataflow path.
func (df *DataFlow) AddIntermediate(loc DataFlowLocation) {
	loc.Type = DataFlowLocationPropagator
	loc.Index = len(df.Sources) + len(df.Intermediates)
	df.Intermediates = append(df.Intermediates, loc)

	// Update sink indices
	for i := range df.Sinks {
		df.Sinks[i].Index = loc.Index + 1 + i
	}

	// Check if flow crosses files
	if len(df.Intermediates) > 0 && len(df.Sources) > 0 {
		if loc.Path != df.Sources[0].Path {
			df.CrossFile = true
		}
	}
}

// AddSanitizer adds a sanitizer location that cleans the tainted data.
func (df *DataFlow) AddSanitizer(loc DataFlowLocation) {
	loc.Type = DataFlowLocationSanitizer
	loc.TaintState = "sanitized"
	df.Sanitizers = append(df.Sanitizers, loc)
}

// MarkAsSanitized marks the dataflow as no longer tainted.
func (df *DataFlow) MarkAsSanitized() {
	df.Tainted = false
}

// GetFullPath returns all locations in order from source to sink.
func (df *DataFlow) GetFullPath() []DataFlowLocation {
	path := make([]DataFlowLocation, 0, len(df.Sources)+len(df.Intermediates)+len(df.Sinks))
	path = append(path, df.Sources...)
	path = append(path, df.Intermediates...)
	path = append(path, df.Sinks...)
	return path
}

// GetPathLength returns the number of steps in the dataflow.
func (df *DataFlow) GetPathLength() int {
	return len(df.Sources) + len(df.Intermediates) + len(df.Sinks)
}

// IsCrossFunction checks if the dataflow crosses function boundaries.
func (df *DataFlow) IsCrossFunction() bool {
	if df.Interprocedural {
		return true
	}

	functions := make(map[string]bool)
	for _, loc := range df.GetFullPath() {
		if loc.Function != "" {
			functions[loc.Function] = true
		}
	}
	return len(functions) > 1
}

// BuildSummary generates a human-readable summary of the dataflow.
func (df *DataFlow) BuildSummary() string {
	if len(df.Sources) == 0 || len(df.Sinks) == 0 {
		return ""
	}

	source := df.Sources[0]
	sink := df.Sinks[len(df.Sinks)-1]

	summary := ""
	if source.Label != "" {
		summary = source.Label
	} else {
		summary = "tainted data"
	}

	if df.TaintType != "" {
		summary += " (" + df.TaintType + ")"
	}

	summary += " flows from "
	if source.Path != "" {
		summary += source.Path
		if source.Line > 0 {
			summary += ":" + itoa(source.Line)
		}
	}

	if len(df.Intermediates) > 0 {
		summary += " through " + itoa(len(df.Intermediates)) + " step(s)"
	}

	summary += " to "
	switch {
	case sink.CalledFunction != "":
		summary += sink.CalledFunction + "()"
	case sink.Label != "":
		summary += sink.Label
	default:
		summary += "sink"
	}

	if sink.Path != "" && sink.Path != source.Path {
		summary += " in " + sink.Path
		if sink.Line > 0 {
			summary += ":" + itoa(sink.Line)
		}
	} else if sink.Line > 0 {
		summary += " at line " + itoa(sink.Line)
	}

	if !df.Tainted {
		summary += " (sanitized)"
	}

	df.Summary = summary
	return summary
}

// itoa converts int to string without importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	if i < 0 {
		return "-" + itoa(-i)
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}

// NewDataFlowLocation creates a new DataFlowLocation.
func NewDataFlowLocation(path string, line, column int, content string) DataFlowLocation {
	return DataFlowLocation{
		Path:    path,
		Line:    line,
		Column:  column,
		Content: content,
	}
}

// WithLabel sets the label for the location.
func (loc DataFlowLocation) WithLabel(label string) DataFlowLocation {
	loc.Label = label
	return loc
}

// WithFunction sets the function context for the location.
func (loc DataFlowLocation) WithFunction(fn string) DataFlowLocation {
	loc.Function = fn
	return loc
}

// WithOperation sets the operation type for the location.
func (loc DataFlowLocation) WithOperation(op string) DataFlowLocation {
	loc.Operation = op
	return loc
}

// AsSource marks this location as a taint source.
func (loc DataFlowLocation) AsSource() DataFlowLocation {
	loc.Type = DataFlowLocationSource
	loc.TaintState = "tainted"
	return loc
}

// AsSink marks this location as a taint sink.
func (loc DataFlowLocation) AsSink() DataFlowLocation {
	loc.Type = DataFlowLocationSink
	return loc
}

// AsSanitizer marks this location as a sanitizer.
func (loc DataFlowLocation) AsSanitizer() DataFlowLocation {
	loc.Type = DataFlowLocationSanitizer
	loc.TaintState = "sanitized"
	return loc
}
