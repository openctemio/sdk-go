package ctis

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ReconConverterOptions configures the conversion from ReconResult to CTIS Report.
type ReconConverterOptions struct {
	// Source tracking
	DiscoverySource string // "agent", "integration", "manual"
	DiscoveryTool   string // Scanner name

	// Default values
	DefaultCriticality Criticality
	DefaultConfidence  int // 0-100

	// Asset grouping
	GroupByDomain bool // Group subdomains under root domain asset
	GroupByIP     bool // Group ports under IP asset

	// Filtering
	MinConfidence int // Minimum confidence to include
}

// DefaultReconConverterOptions returns sensible default options.
func DefaultReconConverterOptions() *ReconConverterOptions {
	return &ReconConverterOptions{
		DiscoverySource:    "agent",
		DefaultCriticality: CriticalityMedium,
		DefaultConfidence:  80,
		GroupByDomain:      true,
		GroupByIP:          true,
		MinConfidence:      0,
	}
}

// ReconToCTISInput holds the data from a reconnaissance scan result.
// This is a simplified version of core.ReconResult to avoid import cycles.
type ReconToCTISInput struct {
	// Scanner info
	ScannerName    string
	ScannerVersion string
	ReconType      string // subdomain, dns, port, http_probe, url_crawl

	// Target
	Target string

	// Timing
	StartedAt  int64
	FinishedAt int64
	DurationMs int64

	// Results
	Subdomains   []SubdomainInput
	DNSRecords   []DNSRecordInput
	OpenPorts    []OpenPortInput
	LiveHosts    []LiveHostInput
	URLs         []DiscoveredURLInput
	Technologies []TechnologyInput
}

// SubdomainInput represents a discovered subdomain.
type SubdomainInput struct {
	Host   string
	Domain string
	Source string
	IPs    []string
}

// DNSRecordInput represents a DNS record.
type DNSRecordInput struct {
	Host       string
	RecordType string
	Values     []string
	TTL        int
	Resolver   string
	StatusCode string
}

// OpenPortInput represents an open port.
type OpenPortInput struct {
	Host     string
	IP       string
	Port     int
	Protocol string
	Service  string
	Version  string
	Banner   string
}

// LiveHostInput represents an HTTP/HTTPS live host.
type LiveHostInput struct {
	URL           string
	Host          string
	IP            string
	Port          int
	Scheme        string
	StatusCode    int
	ContentLength int64
	Title         string
	WebServer     string
	ContentType   string
	Technologies  []string
	CDN           string
	TLSVersion    string
	Redirect      string
	ResponseTime  int64
}

// DiscoveredURLInput represents a discovered URL/endpoint.
type DiscoveredURLInput struct {
	URL        string
	Method     string
	Source     string
	StatusCode int
	Depth      int
	Parent     string
	Type       string
	Extension  string
}

// TechnologyInput represents a detected technology.
type TechnologyInput struct {
	Name       string
	Version    string
	Categories []string
	Confidence int
	Website    string
}

// ConvertReconToCTIS converts reconnaissance results to a CTIS Report.
func ConvertReconToCTIS(input *ReconToCTISInput, opts *ReconConverterOptions) (*Report, error) {
	if opts == nil {
		opts = DefaultReconConverterOptions()
	}

	now := time.Now()
	report := &Report{
		Version: "1.0",
		Schema:  "https://openctem.io/schemas/ctis/1.0",
		Metadata: ReportMetadata{
			ID:         fmt.Sprintf("recon-%s-%d", input.ScannerName, now.UnixNano()),
			Timestamp:  now,
			DurationMs: int(input.DurationMs),
			SourceType: "scanner",
			SourceRef:  input.Target,
			Scope: &Scope{
				Name: input.Target,
				Type: getTargetScopeType(input.ReconType),
			},
		},
		Tool: &Tool{
			Name:         input.ScannerName,
			Version:      input.ScannerVersion,
			Vendor:       "projectdiscovery",
			Capabilities: []string{input.ReconType},
		},
		Assets:     make([]Asset, 0),
		Findings:   make([]Finding, 0),
		Properties: make(Properties),
	}

	// Set discovery tool
	if opts.DiscoveryTool == "" {
		opts.DiscoveryTool = input.ScannerName
	}

	// Convert based on recon type
	switch input.ReconType {
	case "subdomain":
		convertSubdomains(report, input.Subdomains, opts)
	case "dns":
		convertDNSRecords(report, input.DNSRecords, opts)
	case "port":
		convertOpenPorts(report, input.OpenPorts, opts)
	case "http_probe":
		convertLiveHosts(report, input.LiveHosts, opts)
	case "url_crawl":
		convertDiscoveredURLs(report, input.URLs, opts)
	default:
		// Try to convert all available data
		if len(input.Subdomains) > 0 {
			convertSubdomains(report, input.Subdomains, opts)
		}
		if len(input.DNSRecords) > 0 {
			convertDNSRecords(report, input.DNSRecords, opts)
		}
		if len(input.OpenPorts) > 0 {
			convertOpenPorts(report, input.OpenPorts, opts)
		}
		if len(input.LiveHosts) > 0 {
			convertLiveHosts(report, input.LiveHosts, opts)
		}
		if len(input.URLs) > 0 {
			convertDiscoveredURLs(report, input.URLs, opts)
		}
	}

	// Add technologies if present
	if len(input.Technologies) > 0 {
		report.Properties["technologies"] = input.Technologies
	}

	return report, nil
}

func getTargetScopeType(reconType string) string {
	switch reconType {
	case "subdomain", "dns":
		return "domain"
	case "port":
		return "network"
	case "http_probe", "url_crawl":
		return "web"
	default:
		return "domain"
	}
}

func convertSubdomains(report *Report, subdomains []SubdomainInput, opts *ReconConverterOptions) {
	now := time.Now()
	seen := make(map[string]bool)

	for _, sub := range subdomains {
		if sub.Host == "" || seen[sub.Host] {
			continue
		}
		seen[sub.Host] = true

		assetType := AssetTypeDomain
		if sub.Domain != "" && sub.Host != sub.Domain {
			assetType = AssetTypeSubdomain
		}

		asset := Asset{
			ID:           fmt.Sprintf("subdomain-%s", normalizeAssetID(sub.Host)),
			Type:         assetType,
			Value:        sub.Host,
			Name:         sub.Host,
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Properties: Properties{
				"discovery_source": opts.DiscoverySource,
				"discovery_tool":   opts.DiscoveryTool,
			},
		}

		// Add technical details
		technical := &AssetTechnical{
			Domain: &DomainTechnical{},
		}

		if sub.Domain != "" {
			asset.Properties["root_domain"] = sub.Domain
		}

		if sub.Source != "" {
			asset.Properties["discovery_method"] = sub.Source
		}

		// Add resolved IPs as DNS records
		if len(sub.IPs) > 0 {
			asset.Properties["resolved_ips"] = sub.IPs
			for _, ip := range sub.IPs {
				technical.Domain.DNSRecords = append(technical.Domain.DNSRecords, DNSRecord{
					Type:  "A",
					Name:  sub.Host,
					Value: ip,
				})
			}
		}

		asset.Technical = technical
		report.Assets = append(report.Assets, asset)
	}
}

func convertDNSRecords(report *Report, records []DNSRecordInput, opts *ReconConverterOptions) {
	now := time.Now()

	// Group records by host
	hostRecords := make(map[string][]DNSRecord)
	hostInfo := make(map[string]*DNSRecordInput)

	for _, rec := range records {
		if rec.Host == "" {
			continue
		}

		dnsRec := DNSRecord{
			Type:  rec.RecordType,
			Name:  rec.Host,
			Value: strings.Join(rec.Values, ", "),
			TTL:   rec.TTL,
		}

		hostRecords[rec.Host] = append(hostRecords[rec.Host], dnsRec)
		if _, exists := hostInfo[rec.Host]; !exists {
			hostInfo[rec.Host] = &rec
		}
	}

	// Create asset for each host
	for host, dnsRecords := range hostRecords {
		asset := Asset{
			ID:           fmt.Sprintf("dns-%s", normalizeAssetID(host)),
			Type:         AssetTypeDomain,
			Value:        host,
			Name:         host,
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Technical: &AssetTechnical{
				Domain: &DomainTechnical{
					DNSRecords: dnsRecords,
				},
			},
			Properties: Properties{
				"discovery_source": opts.DiscoverySource,
				"discovery_tool":   opts.DiscoveryTool,
				"dns_record_count": len(dnsRecords),
			},
		}

		// Extract nameservers from NS records
		for _, rec := range dnsRecords {
			if rec.Type == "NS" {
				asset.Technical.Domain.Nameservers = append(
					asset.Technical.Domain.Nameservers,
					rec.Value,
				)
			}
		}

		report.Assets = append(report.Assets, asset)
	}
}

func convertOpenPorts(report *Report, ports []OpenPortInput, opts *ReconConverterOptions) {
	now := time.Now()

	if opts.GroupByIP {
		// Group ports by IP/Host
		hostPorts := make(map[string][]PortInfo)
		hostInfo := make(map[string]*OpenPortInput)

		for _, p := range ports {
			key := p.IP
			if key == "" {
				key = p.Host
			}
			if key == "" {
				continue
			}

			portInfo := PortInfo{
				Port:     p.Port,
				Protocol: p.Protocol,
				State:    "open",
				Service:  p.Service,
				Version:  p.Version,
				Banner:   p.Banner,
			}

			hostPorts[key] = append(hostPorts[key], portInfo)
			if _, exists := hostInfo[key]; !exists {
				hostInfo[key] = &p
			}
		}

		// Create asset for each IP/host
		for key, portList := range hostPorts {
			info := hostInfo[key]

			asset := Asset{
				ID:           fmt.Sprintf("ip-%s", normalizeAssetID(key)),
				Type:         AssetTypeIPAddress,
				Value:        key,
				Name:         key,
				Criticality:  opts.DefaultCriticality,
				Confidence:   opts.DefaultConfidence,
				DiscoveredAt: &now,
				Technical: &AssetTechnical{
					IPAddress: &IPAddressTechnical{
						Ports: portList,
					},
				},
				Properties: Properties{
					"discovery_source": opts.DiscoverySource,
					"discovery_tool":   opts.DiscoveryTool,
					"open_port_count":  len(portList),
				},
			}

			// Set hostname if available
			if info.Host != "" && info.Host != key {
				asset.Technical.IPAddress.Hostname = info.Host
			}

			// Detect IP version
			if strings.Contains(key, ":") {
				asset.Technical.IPAddress.Version = 6
			} else {
				asset.Technical.IPAddress.Version = 4
			}

			report.Assets = append(report.Assets, asset)
		}
	} else {
		// Create individual asset for each port
		for _, p := range ports {
			key := p.IP
			if key == "" {
				key = p.Host
			}
			if key == "" {
				continue
			}

			asset := Asset{
				ID:           fmt.Sprintf("port-%s-%d", normalizeAssetID(key), p.Port),
				Type:         AssetTypeOpenPort,
				Value:        fmt.Sprintf("%s:%d", key, p.Port),
				Name:         fmt.Sprintf("%s:%d/%s", key, p.Port, p.Protocol),
				Criticality:  opts.DefaultCriticality,
				Confidence:   opts.DefaultConfidence,
				DiscoveredAt: &now,
				Properties: Properties{
					"discovery_source": opts.DiscoverySource,
					"discovery_tool":   opts.DiscoveryTool,
					"host":             key,
					"port":             p.Port,
					"protocol":         p.Protocol,
					"service":          p.Service,
					"version":          p.Version,
					"banner":           p.Banner,
				},
			}

			report.Assets = append(report.Assets, asset)
		}
	}
}

func convertLiveHosts(report *Report, hosts []LiveHostInput, opts *ReconConverterOptions) {
	now := time.Now()
	seen := make(map[string]bool)

	for _, h := range hosts {
		if h.URL == "" || seen[h.URL] {
			continue
		}
		seen[h.URL] = true

		// Determine asset type based on scheme and content
		assetType := AssetTypeHTTPService
		if h.StatusCode >= 200 && h.StatusCode < 400 {
			assetType = AssetTypeService
		}

		asset := Asset{
			ID:           fmt.Sprintf("http-%s", normalizeAssetID(h.URL)),
			Type:         assetType,
			Value:        h.URL,
			Name:         h.Host,
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Technical: &AssetTechnical{
				Service: &ServiceTechnical{
					Name:     h.WebServer,
					Port:     h.Port,
					Protocol: h.Scheme,
					TLS:      h.Scheme == "https",
				},
			},
			Properties: Properties{
				"discovery_source": opts.DiscoverySource,
				"discovery_tool":   opts.DiscoveryTool,
				"status_code":      h.StatusCode,
				"content_length":   h.ContentLength,
				"title":            h.Title,
				"web_server":       h.WebServer,
				"content_type":     h.ContentType,
				"response_time_ms": h.ResponseTime,
			},
		}

		// Add technologies
		if len(h.Technologies) > 0 {
			asset.Properties["technologies"] = h.Technologies
			asset.Tags = append(asset.Tags, h.Technologies...)
		}

		// Add CDN info
		if h.CDN != "" {
			asset.Properties["cdn"] = h.CDN
		}

		// Add TLS info
		if h.TLSVersion != "" {
			asset.Properties["tls_version"] = h.TLSVersion
		}

		// Add IP info
		if h.IP != "" {
			asset.Properties["ip"] = h.IP
		}

		// Add redirect info
		if h.Redirect != "" && h.Redirect != h.URL {
			asset.Properties["redirect_url"] = h.Redirect
		}

		report.Assets = append(report.Assets, asset)
	}
}

func convertDiscoveredURLs(report *Report, urls []DiscoveredURLInput, opts *ReconConverterOptions) {
	now := time.Now()
	seen := make(map[string]bool)

	for _, u := range urls {
		if u.URL == "" || seen[u.URL] {
			continue
		}
		seen[u.URL] = true

		// Parse URL to extract host
		parsedURL, err := url.Parse(u.URL)
		host := u.URL
		if err == nil && parsedURL.Host != "" {
			host = parsedURL.Host
		}

		asset := Asset{
			ID:           fmt.Sprintf("url-%s", normalizeAssetID(u.URL)),
			Type:         AssetTypeDiscoveredURL,
			Value:        u.URL,
			Name:         truncateString(u.URL, 255),
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Properties: Properties{
				"discovery_source": opts.DiscoverySource,
				"discovery_tool":   opts.DiscoveryTool,
				"host":             host,
				"method":           u.Method,
				"source":           u.Source,
				"depth":            u.Depth,
				"type":             u.Type,
				"extension":        u.Extension,
			},
		}

		// Add parent URL if present
		if u.Parent != "" {
			asset.Properties["parent_url"] = u.Parent
		}

		// Add status code if present
		if u.StatusCode > 0 {
			asset.Properties["status_code"] = u.StatusCode
		}

		// Tag by type
		if u.Type != "" {
			asset.Tags = append(asset.Tags, u.Type)
		}

		report.Assets = append(report.Assets, asset)
	}
}

// normalizeAssetID creates a safe ID from a string value.
func normalizeAssetID(value string) string {
	// Replace special characters with dashes
	result := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '-' || r == '_' {
			return r
		}
		return '-'
	}, value)

	// Remove consecutive dashes
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}

	// Trim dashes from ends
	result = strings.Trim(result, "-")

	// Truncate if too long
	if len(result) > 100 {
		result = result[:100]
	}

	return strings.ToLower(result)
}

// truncateString truncates a string to maxLen characters.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// MergeReconReports merges multiple CTIS reports from different recon scanners.
// This is useful when running a recon pipeline (subfinder -> dnsx -> naabu -> httpx).
func MergeReconReports(reports []*Report) *Report {
	if len(reports) == 0 {
		return nil
	}
	if len(reports) == 1 {
		return reports[0]
	}

	merged := &Report{
		Version: "1.0",
		Schema:  "https://openctem.io/schemas/ctis/1.0",
		Metadata: ReportMetadata{
			ID:         fmt.Sprintf("merged-recon-%d", time.Now().UnixNano()),
			Timestamp:  time.Now(),
			SourceType: "scanner",
		},
		Assets:     make([]Asset, 0),
		Findings:   make([]Finding, 0),
		Properties: make(Properties),
	}

	// Track tools used
	tools := make([]string, 0)
	totalDuration := 0

	// Merge assets, deduplicating by ID
	assetMap := make(map[string]*Asset)

	for _, report := range reports {
		if report == nil {
			continue
		}

		// Collect tool info
		if report.Tool != nil {
			tools = append(tools, report.Tool.Name)
		}
		totalDuration += report.Metadata.DurationMs

		// Merge assets
		for i := range report.Assets {
			asset := &report.Assets[i]
			if existing, ok := assetMap[asset.Value]; ok {
				// Merge properties
				mergeAssetProperties(existing, asset)
			} else {
				// Add new asset
				assetCopy := *asset
				assetMap[asset.Value] = &assetCopy
			}
		}

		// Merge findings
		merged.Findings = append(merged.Findings, report.Findings...)
	}

	// Convert map back to slice
	for _, asset := range assetMap {
		merged.Assets = append(merged.Assets, *asset)
	}

	// Set merged metadata
	merged.Metadata.DurationMs = totalDuration
	merged.Properties["tools_used"] = tools
	merged.Tool = &Tool{
		Name:         "recon-pipeline",
		Capabilities: tools,
	}

	return merged
}

// mergeAssetProperties merges properties from src into dst.
func mergeAssetProperties(dst, src *Asset) {
	// Merge tags
	tagSet := make(map[string]bool)
	for _, t := range dst.Tags {
		tagSet[t] = true
	}
	for _, t := range src.Tags {
		if !tagSet[t] {
			dst.Tags = append(dst.Tags, t)
			tagSet[t] = true
		}
	}

	// Merge properties
	if dst.Properties == nil {
		dst.Properties = make(Properties)
	}
	for k, v := range src.Properties {
		if _, exists := dst.Properties[k]; !exists {
			dst.Properties[k] = v
		}
	}

	// Merge technical details (domain)
	if src.Technical != nil && src.Technical.Domain != nil {
		if dst.Technical == nil {
			dst.Technical = &AssetTechnical{}
		}
		if dst.Technical.Domain == nil {
			dst.Technical.Domain = &DomainTechnical{}
		}

		// Merge DNS records
		existingRecords := make(map[string]bool)
		for _, rec := range dst.Technical.Domain.DNSRecords {
			key := rec.Type + ":" + rec.Name + ":" + rec.Value
			existingRecords[key] = true
		}
		for _, rec := range src.Technical.Domain.DNSRecords {
			key := rec.Type + ":" + rec.Name + ":" + rec.Value
			if !existingRecords[key] {
				dst.Technical.Domain.DNSRecords = append(dst.Technical.Domain.DNSRecords, rec)
			}
		}

		// Merge nameservers
		nsSet := make(map[string]bool)
		for _, ns := range dst.Technical.Domain.Nameservers {
			nsSet[ns] = true
		}
		for _, ns := range src.Technical.Domain.Nameservers {
			if !nsSet[ns] {
				dst.Technical.Domain.Nameservers = append(dst.Technical.Domain.Nameservers, ns)
			}
		}
	}

	// Merge technical details (IP)
	if src.Technical != nil && src.Technical.IPAddress != nil {
		if dst.Technical == nil {
			dst.Technical = &AssetTechnical{}
		}
		if dst.Technical.IPAddress == nil {
			dst.Technical.IPAddress = &IPAddressTechnical{}
		}

		// Merge ports
		existingPorts := make(map[string]bool)
		for _, p := range dst.Technical.IPAddress.Ports {
			key := strconv.Itoa(p.Port) + ":" + p.Protocol
			existingPorts[key] = true
		}
		for _, p := range src.Technical.IPAddress.Ports {
			key := strconv.Itoa(p.Port) + ":" + p.Protocol
			if !existingPorts[key] {
				dst.Technical.IPAddress.Ports = append(dst.Technical.IPAddress.Ports, p)
			}
		}
	}

	// Update confidence (take higher)
	if src.Confidence > dst.Confidence {
		dst.Confidence = src.Confidence
	}
}
